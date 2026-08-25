from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable

import peg_schema
import program_model as pm
import pu_index
import pu_ownership
from ownership_contract import ownership_scope_accepts

MAX_PROVIDER_SCAN_METHODS = 200_000
MAX_PROVIDER_SCAN_EDGES = 20_000
MAX_PROVIDER_QUERY_SECONDS = 5


def _normalize_private_method_id(value: str) -> tuple[str, str, str] | None:
    parts = str(value or "").strip().split(" ", 2)
    if len(parts) != 3:
        return None
    class_name = pu_index.normalize_class_descriptor(parts[0])
    name = parts[1].strip()
    descriptor = parts[2].strip()
    return (class_name, name, descriptor) if class_name and name and descriptor else None


class DexProgramProvider:
    def __init__(self, job: Path, workspace: Path, caps: dict[str, Any]) -> None:
        self.job = Path(job)
        self.workspace = Path(workspace)
        self.caps = caps
        pu_index.ensure_index(self.job, self.workspace, caps)
        with pu_index.connect(self.job) as conn:
            sha = str(pu_index.meta_get(conn, "artifact_sha256") or "")
            self.analysis_kind = str(pu_index.meta_get(conn, "analysis_kind") or "unknown")
            analyzer = pu_index.meta_get(conn, "analyzer", {}) or {}
            self.analyzer_name = str(analyzer.get("name") or "static-core")
            self.analyzer_version = str(analyzer.get("version") or "unknown")
        artifact = pu_index.artifact(self.job, self.workspace)
        self._snapshot = pm.ProgramSnapshot(sha, artifact.suffix.lstrip(".") or "artifact")
        self.classifier = pu_ownership.CodeOwnershipClassifier.for_job(self.job)
        self._evidence: dict[str, dict[str, Any]] = {}
        self._boundary_entities: dict[str, pm.ProgramEntity] = {}

    @property
    def snapshot(self) -> pm.ProgramSnapshot:
        return self._snapshot

    @property
    def application_key(self) -> str:
        return "application:v1"

    def _application(self) -> pm.ProgramEntity:
        context = self.classifier.context
        props: dict[str, Any] = {"artifact_kind": self.snapshot.artifact_kind}
        if context.application_package:
            props["application_id"] = context.application_package
        ref = self._evidence_ref({"kind": "artifact", "artifact_sha256": self.snapshot.artifact_sha256}, state="observed")
        return pm.ProgramEntity(
            self.snapshot.snapshot_id,
            pm.entity_id(self.snapshot, "APPLICATION", self.application_key),
            self.application_key,
            "APPLICATION",
            context.application_package or "application",
            "artifact",
            "FIRST_PARTY",
            props,
            (ref,),
        )

    @staticmethod
    def class_key(class_name: str) -> str:
        return f"class:v1:dex:{class_name}"

    @classmethod
    def function_key(cls, class_name: str, name: str, descriptor: str) -> str:
        return f"function:v1:dex:{cls.class_key(class_name)}:{name}{descriptor}"

    def _evidence_ref(self, location: dict[str, Any], *, state: str = "derived") -> str:
        ref = pm.evidence_id(self.snapshot, self.analyzer_name, location)
        if ref not in self._evidence:
            self._evidence[ref] = peg_schema.evidence(
                analysis_id=f"static-core:{self.snapshot.artifact_sha256}",
                artifact_sha256=self.snapshot.artifact_sha256,
                analyzer_name=self.analyzer_name,
                analyzer_version=self.analyzer_version,
                state=state,
                location=location,
            )
        return ref

    def _class_entity(self, class_name: str, *, external: bool = False, evidence_ref: str | None = None) -> pm.ProgramEntity:
        decision = self.classifier.classify(class_name, external=external)
        key = self.class_key(class_name)
        return pm.ProgramEntity(
            self.snapshot.snapshot_id,
            pm.entity_id(self.snapshot, "CLASS", key),
            key,
            "CLASS",
            class_name,
            "dex",
            decision["scope"],
            {"qualified_name": class_name},
            (evidence_ref,) if evidence_ref else (),
        )

    def _function_entity(self, row: sqlite3.Row | dict[str, Any]) -> pm.ProgramEntity:
        class_name = str(row["class"])
        name = str(row["name"])
        descriptor = str(row["descriptor"])
        external = bool(row["external"])
        location: dict[str, Any] = {
            "kind": "dex-method" if self.analysis_kind == "dex-xref" else "source-declaration",
            "class": class_name,
            "name": name,
            "descriptor": descriptor,
        }
        try:
            source = json.loads(row["source_json"]) if isinstance(row, sqlite3.Row) else row.get("source", {})
        except (TypeError, json.JSONDecodeError):
            source = {}
        if isinstance(source, dict):
            if isinstance(source.get("apk_member"), str):
                location["artifact_member"] = source["apk_member"][:1024]
            if isinstance(source.get("file"), str):
                location["source_file"] = source["file"][:2048]
            if isinstance(source.get("line"), int):
                location["line"] = source["line"]
        ref = self._evidence_ref(location)
        decision = self.classifier.classify(class_name, external=external)
        key = self.function_key(class_name, name, descriptor)
        props: dict[str, Any] = {"signature": descriptor, "implementation": "external" if external else "present"}
        parameter_count = row["parameter_count"] if "parameter_count" in row.keys() else None
        if parameter_count is not None:
            props["parameter_count"] = int(parameter_count)
        return pm.ProgramEntity(
            self.snapshot.snapshot_id,
            pm.entity_id(self.snapshot, "FUNCTION", key),
            key,
            "FUNCTION",
            f"{class_name}.{name}",
            "dex",
            decision["scope"],
            props,
            (ref,),
        )

    def _synthetic_function(self, private_id: str) -> pm.ProgramEntity | None:
        parsed = _normalize_private_method_id(private_id)
        if parsed is None:
            return None
        class_name, name, descriptor = parsed
        return self._function_entity({
            "class": class_name,
            "name": name,
            "descriptor": descriptor,
            "parameter_count": pu_index.dex_parameter_count(descriptor),
            "external": True,
            "source": {},
        })

    @staticmethod
    def _private_method(conn: sqlite3.Connection, private_id: str) -> sqlite3.Row | None:
        return conn.execute("SELECT * FROM methods WHERE id=?", (private_id,)).fetchone()

    def _find_private_by_entity_id(self, conn: sqlite3.Connection, identifier: str) -> sqlite3.Row | None:
        start = time.monotonic()
        for row in conn.execute("SELECT * FROM methods ORDER BY class,name,descriptor,id LIMIT ?", (MAX_PROVIDER_SCAN_METHODS,)):
            if time.monotonic() - start > MAX_PROVIDER_QUERY_SECONDS:
                break
            if self._function_entity(row).entity_id == identifier:
                return row
        return None

    def _find_class_name_by_entity_id(self, conn: sqlite3.Connection, identifier: str) -> str | None:
        start = time.monotonic()
        seen: set[str] = set()
        for row in conn.execute("SELECT class,external FROM methods ORDER BY class LIMIT ?", (MAX_PROVIDER_SCAN_METHODS,)):
            if time.monotonic() - start > MAX_PROVIDER_QUERY_SECONDS:
                break
            class_name = str(row["class"])
            if class_name in seen:
                continue
            seen.add(class_name)
            if self._class_entity(class_name, external=bool(row["external"])).entity_id == identifier:
                return class_name
        return None

    def _boundary(self, target: pm.ProgramEntity, decision: dict[str, Any]) -> pm.ProgramEntity:
        scope = target.ownership
        owner = decision.get("owner")
        sdk = decision.get("sdk")
        boundary_kind = {"THIRD_PARTY": "third-party-sdk", "PLATFORM": "platform", "GENERATED": "generated"}.get(scope, "external-unresolved")
        key = f"boundary:v1:{boundary_kind}:{target.semantic_key}"
        props: dict[str, Any] = {"boundary_kind": boundary_kind, "target": target.display_name or target.semantic_key}
        if owner:
            props["owner"] = str(owner)
        if sdk:
            props["sdk"] = str(sdk)
        item = pm.ProgramEntity(
            self.snapshot.snapshot_id,
            pm.entity_id(self.snapshot, "EXTERNAL_BOUNDARY", key),
            key,
            "EXTERNAL_BOUNDARY",
            str(sdk or owner or target.display_name or "external boundary"),
            "dex",
            scope,
            props,
            target.evidence_refs,
        )
        self._boundary_entities[item.entity_id] = item
        return item

    def get_entity(self, entity_id: str) -> pm.ProgramEntity | None:
        app = self._application()
        if app.entity_id == entity_id:
            return app
        if entity_id in self._boundary_entities:
            return self._boundary_entities[entity_id]
        with pu_index.connect(self.job) as conn:
            row = self._find_private_by_entity_id(conn, entity_id)
            if row is not None:
                return self._function_entity(row)
            class_name = self._find_class_name_by_entity_id(conn, entity_id)
            if class_name:
                first = conn.execute("SELECT external FROM methods WHERE class=? ORDER BY id LIMIT 1", (class_name,)).fetchone()
                return self._class_entity(class_name, external=bool(first["external"]) if first else False)
        return None

    def iter_entities(self, *, kind: str | None = None, text: str | None = None, ownership_scope: str = "application", representation: str | None = None, limit: int = pm.MAX_PROVIDER_PAGE_SIZE) -> Iterable[pm.ProgramEntity]:
        limit = max(1, min(int(limit), pm.MAX_PROVIDER_PAGE_SIZE))
        if representation and representation not in {"dex", "artifact"}:
            return
        needle = str(text or "").lower()
        count = 0
        if kind in {None, "APPLICATION"}:
            app = self._application()
            if ownership_scope_accepts(app.ownership, ownership_scope) and (not needle or needle in (app.display_name + " " + app.semantic_key).lower()):
                yield app
                count += 1
                if count >= limit:
                    return
        if kind not in {None, "CLASS", "FUNCTION"}:
            return
        with pu_index.connect(self.job) as conn:
            seen_classes: set[str] = set()
            start = time.monotonic()
            for row in conn.execute("SELECT * FROM methods ORDER BY external,class,name,descriptor,id LIMIT ?", (MAX_PROVIDER_SCAN_METHODS,)):
                if time.monotonic() - start > MAX_PROVIDER_QUERY_SECONDS:
                    break
                if kind in {None, "CLASS"} and str(row["class"]) not in seen_classes:
                    seen_classes.add(str(row["class"]))
                    item = self._class_entity(str(row["class"]), external=bool(row["external"]))
                    if ownership_scope_accepts(item.ownership, ownership_scope) and (not needle or needle in (item.display_name + " " + item.semantic_key).lower()):
                        yield item
                        count += 1
                        if count >= limit:
                            return
                if kind in {None, "FUNCTION"}:
                    item = self._function_entity(row)
                    if ownership_scope_accepts(item.ownership, ownership_scope) and (not needle or needle in (item.display_name + " " + item.semantic_key).lower()):
                        yield item
                        count += 1
                        if count >= limit:
                            return

    def _declares(self, source: pm.ProgramEntity, target: pm.ProgramEntity) -> pm.ProgramRelationship:
        refs = tuple(sorted(set(source.evidence_refs) | set(target.evidence_refs)))
        return pm.ProgramRelationship(
            self.snapshot.snapshot_id,
            pm.relationship_id(self.snapshot, "DECLARES", source.entity_id, target.entity_id),
            "DECLARES", source.entity_id, target.entity_id, "dex", {}, refs,
        )

    def _call_relationship(self, caller: pm.ProgramEntity, callee: pm.ProgramEntity, *, offset: int, edge_kind: str) -> pm.ProgramRelationship:
        is_call = self.analysis_kind == "dex-xref" and edge_kind == "dex-xref"
        caller_class = caller.display_name.rsplit(".", 1)[0]
        callee_class = callee.display_name.rsplit(".", 1)[0]
        caller_decision = self.classifier.classify(caller_class, external=caller.properties.get("implementation") == "external")
        callee_decision = self.classifier.classify(callee_class, external=callee.properties.get("implementation") == "external")
        crossing = caller.ownership in {"FIRST_PARTY", "UNKNOWN"} and callee.ownership in {"THIRD_PARTY", "PLATFORM", "GENERATED"}
        reverse_crossing = callee.ownership in {"FIRST_PARTY", "UNKNOWN"} and caller.ownership in {"THIRD_PARTY", "PLATFORM", "GENERATED"}
        ref = self._evidence_ref({"kind": "dex-callsite" if is_call else "dex-xref", "caller": caller.semantic_key, "target": callee.semantic_key, "offset": int(offset)})
        if crossing or reverse_crossing:
            external = callee if crossing else caller
            decision = callee_decision if crossing else caller_decision
            boundary = self._boundary(external, decision)
            kind = "CALLS_EXTERNAL" if is_call else "XREF"
            source = caller if crossing else boundary
            target = boundary if crossing else callee
            props = {"callsite_offset": int(offset), "boundary_kind": boundary.properties["boundary_kind"]} if is_call else {"reference_offset": int(offset), "reference_kind": edge_kind}
        else:
            kind = "CALLS" if is_call else "XREF"
            source, target = caller, callee
            props = {"callsite_offset": int(offset)} if is_call else {"reference_offset": int(offset), "reference_kind": edge_kind}
        return pm.ProgramRelationship(
            self.snapshot.snapshot_id,
            pm.relationship_id(self.snapshot, kind, source.entity_id, target.entity_id, str(offset)),
            kind, source.entity_id, target.entity_id, "dex", props, (ref,),
        )

    def iter_relationships(self, *, entity_id: str, kinds: frozenset[str] | None = None, direction: str = "both", ownership_scope: str = "application", limit: int = pm.MAX_PROVIDER_PAGE_SIZE) -> Iterable[pm.ProgramRelationship]:
        limit = max(1, min(int(limit), pm.MAX_PROVIDER_PAGE_SIZE))
        count = 0
        app = self._application()
        with pu_index.connect(self.job) as conn:
            class_name = self._find_class_name_by_entity_id(conn, entity_id)
            function_row = self._find_private_by_entity_id(conn, entity_id)

            if entity_id == app.entity_id and direction in {"outgoing", "both"} and (not kinds or "DECLARES" in kinds):
                seen: set[str] = set()
                for row in conn.execute("SELECT class,external FROM methods ORDER BY class LIMIT ?", (MAX_PROVIDER_SCAN_METHODS,)):
                    name = str(row["class"])
                    if name in seen:
                        continue
                    seen.add(name)
                    target = self._class_entity(name, external=bool(row["external"]))
                    if not ownership_scope_accepts(target.ownership, ownership_scope):
                        continue
                    yield self._declares(app, target)
                    count += 1
                    if count >= limit:
                        return

            if class_name:
                class_entity = self._class_entity(class_name)
                if direction in {"incoming", "both"} and (not kinds or "DECLARES" in kinds):
                    yield self._declares(app, class_entity)
                    count += 1
                    if count >= limit:
                        return
                if direction in {"outgoing", "both"} and (not kinds or "DECLARES" in kinds):
                    for row in conn.execute("SELECT * FROM methods WHERE class=? ORDER BY name,descriptor,id LIMIT ?", (class_name, MAX_PROVIDER_SCAN_METHODS)):
                        target = self._function_entity(row)
                        if not ownership_scope_accepts(target.ownership, ownership_scope):
                            continue
                        yield self._declares(class_entity, target)
                        count += 1
                        if count >= limit:
                            return

            if function_row is not None:
                function_entity = self._function_entity(function_row)
                if direction in {"incoming", "both"} and (not kinds or "DECLARES" in kinds):
                    class_entity = self._class_entity(str(function_row["class"]), external=bool(function_row["external"]))
                    yield self._declares(class_entity, function_entity)
                    count += 1
                    if count >= limit:
                        return

                private_id = str(function_row["id"])
                edge_rows: list[sqlite3.Row] = []
                if direction in {"outgoing", "both"}:
                    edge_rows.extend(conn.execute("SELECT * FROM call_edges WHERE caller=? ORDER BY offset,callee LIMIT ?", (private_id, MAX_PROVIDER_SCAN_EDGES)).fetchall())
                if direction in {"incoming", "both"}:
                    edge_rows.extend(conn.execute("SELECT * FROM call_edges WHERE callee=? ORDER BY offset,caller LIMIT ?", (private_id, MAX_PROVIDER_SCAN_EDGES)).fetchall())
                for edge in edge_rows[:MAX_PROVIDER_SCAN_EDGES]:
                    caller_row = self._private_method(conn, str(edge["caller"]))
                    callee_row = self._private_method(conn, str(edge["callee"]))
                    caller = self._function_entity(caller_row) if caller_row is not None else self._synthetic_function(str(edge["caller"]))
                    callee = self._function_entity(callee_row) if callee_row is not None else self._synthetic_function(str(edge["callee"]))
                    if caller is None or callee is None:
                        continue
                    relation = self._call_relationship(caller, callee, offset=int(edge["offset"]), edge_kind=str(edge["kind"]))
                    if kinds and relation.kind not in kinds:
                        continue
                    yield relation
                    count += 1
                    if count >= limit:
                        return

    def get_evidence(self, evidence_ref: str) -> dict[str, Any] | None:
        return self._evidence.get(evidence_ref)


def repository(job: Path, workspace: Path, caps: dict[str, Any]) -> pm.ProgramRepository:
    return pm.ProgramRepository((DexProgramProvider(job, workspace, caps),))
