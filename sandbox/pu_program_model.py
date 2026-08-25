from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

import peg_schema
import program_model as pm
import pu_index
import pu_ownership
from ownership_contract import ownership_scope_accepts, validate_ownership_scope

MAX_PROVIDER_SCAN_METHODS = 200_000
MAX_PROVIDER_SCAN_EDGES = 20_000
MAX_PROVIDER_QUERY_SECONDS = 5
REPRESENTATION = "dex"
EXTERNAL_SCOPES = frozenset({"THIRD_PARTY", "PLATFORM", "GENERATED"})
_BOUNDARY_ID_PREFIX = f"pm:v{pm.PROGRAM_MODEL_VERSION}:external_boundary:"


def _normalize_private_method_id(value: str) -> tuple[str, str, str] | None:
    parts = str(value or "").strip().split(" ", 2)
    if len(parts) != 3:
        return None
    class_name = pu_index.normalize_class_descriptor(parts[0])
    name = parts[1].strip()
    descriptor = parts[2].strip()
    if not class_name or not name or not descriptor:
        return None
    return class_name, name, descriptor


class DexProgramProvider:
    def __init__(self, job: Path, workspace: Path, caps: dict[str, Any]) -> None:
        self.job = Path(job)
        self.workspace = Path(workspace)
        self.caps = caps
        pu_index.ensure_index(self.job, self.workspace, caps)
        with pu_index.connect(self.job) as conn:
            sha = str(pu_index.meta_get(conn, "artifact_sha256") or "")
            self.analysis_kind = str(
                pu_index.meta_get(conn, "analysis_kind") or "unknown"
            )
            analyzer = pu_index.meta_get(conn, "analyzer", {}) or {}
            self.analyzer_name = str(analyzer.get("name") or "static-core")
            self.analyzer_version = str(analyzer.get("version") or "unknown")
        artifact = pu_index.artifact(self.job, self.workspace)
        self._snapshot = pm.ProgramSnapshot(
            sha,
            artifact.suffix.lstrip(".") or "artifact",
        )
        self.classifier = pu_ownership.CodeOwnershipClassifier.for_job(self.job)
        self._evidence: dict[str, dict[str, Any]] = {}
        self._boundary_entities: dict[str, pm.ProgramEntity] = {}

    @property
    def snapshot(self) -> pm.ProgramSnapshot:
        return self._snapshot

    @property
    def application_key(self) -> str:
        return "application:v1"

    def _evidence_ref(
        self,
        location: dict[str, Any],
        *,
        state: str = "derived",
    ) -> str:
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

    def _application(self) -> pm.ProgramEntity:
        context = self.classifier.context
        props: dict[str, Any] = {"artifact_kind": self.snapshot.artifact_kind}
        if context.application_package:
            props["application_id"] = context.application_package
        evidence_ref = self._evidence_ref(
            {
                "kind": "artifact",
                "artifact_sha256": self.snapshot.artifact_sha256,
            },
            state="observed",
        )
        return pm.ProgramEntity(
            self.snapshot.snapshot_id,
            pm.entity_id(self.snapshot, "APPLICATION", self.application_key),
            self.application_key,
            "APPLICATION",
            context.application_package or "application",
            "artifact",
            "FIRST_PARTY",
            props,
            (evidence_ref,),
        )

    @staticmethod
    def class_key(class_name: str) -> str:
        return f"class:v1:dex:{class_name}"

    @classmethod
    def function_key(cls, class_name: str, name: str, descriptor: str) -> str:
        return (
            f"function:v1:dex:{cls.class_key(class_name)}:"
            f"{name}{descriptor}"
        )

    def _class_entity(
        self,
        class_name: str,
        *,
        external: bool = False,
        evidence_ref: str | None = None,
    ) -> pm.ProgramEntity:
        decision = self.classifier.classify(class_name, external=external)
        key = self.class_key(class_name)
        return pm.ProgramEntity(
            self.snapshot.snapshot_id,
            pm.entity_id(self.snapshot, "CLASS", key),
            key,
            "CLASS",
            class_name,
            REPRESENTATION,
            decision["scope"],
            {"qualified_name": class_name},
            (evidence_ref,) if evidence_ref else (),
        )

    def _function_entity(
        self,
        row: sqlite3.Row | dict[str, Any],
    ) -> pm.ProgramEntity:
        class_name = str(row["class"])
        name = str(row["name"])
        descriptor = str(row["descriptor"])
        external = bool(row["external"])
        location: dict[str, Any] = {
            "kind": (
                "dex-method"
                if self.analysis_kind == "dex-xref"
                else "source-declaration"
            ),
            "class": class_name,
            "name": name,
            "descriptor": descriptor,
        }
        try:
            if isinstance(row, sqlite3.Row):
                source = json.loads(row["source_json"])
            else:
                source = row.get("source", {})
        except (TypeError, json.JSONDecodeError):
            source = {}
        if isinstance(source, dict):
            if isinstance(source.get("apk_member"), str):
                location["artifact_member"] = source["apk_member"][:1024]
            if isinstance(source.get("file"), str):
                location["source_file"] = source["file"][:2048]
            if isinstance(source.get("line"), int):
                location["line"] = source["line"]
        evidence_ref = self._evidence_ref(location)
        decision = self.classifier.classify(class_name, external=external)
        key = self.function_key(class_name, name, descriptor)
        props: dict[str, Any] = {
            "signature": descriptor,
            "implementation": "external" if external else "present",
        }
        parameter_count = row["parameter_count"] if "parameter_count" in row.keys() else None
        if parameter_count is not None:
            props["parameter_count"] = int(parameter_count)
        return pm.ProgramEntity(
            self.snapshot.snapshot_id,
            pm.entity_id(self.snapshot, "FUNCTION", key),
            key,
            "FUNCTION",
            f"{class_name}.{name}",
            REPRESENTATION,
            decision["scope"],
            props,
            (evidence_ref,),
        )

    def _synthetic_function(self, private_id: str) -> pm.ProgramEntity | None:
        parsed = _normalize_private_method_id(private_id)
        if parsed is None:
            return None
        class_name, name, descriptor = parsed
        return self._function_entity(
            {
                "class": class_name,
                "name": name,
                "descriptor": descriptor,
                "parameter_count": pu_index.dex_parameter_count(descriptor),
                "external": True,
                "source": {},
            }
        )

    def _boundary(
        self,
        target: pm.ProgramEntity,
        decision: dict[str, Any],
    ) -> pm.ProgramEntity:
        scope = target.ownership
        owner = decision.get("owner")
        sdk = decision.get("sdk")
        boundary_kind = {
            "THIRD_PARTY": "third-party-sdk",
            "PLATFORM": "platform",
            "GENERATED": "generated",
        }.get(scope, "external-unresolved")
        key = f"boundary:v1:{boundary_kind}:{target.semantic_key}"
        props: dict[str, Any] = {
            "boundary_kind": boundary_kind,
            "target": target.display_name or target.semantic_key,
        }
        if owner:
            props["owner"] = str(owner)
        if sdk:
            props["sdk"] = str(sdk)
        evidence_ref = self._evidence_ref(
            {
                "kind": "external-boundary",
                "target": target.semantic_key,
                "scope": scope,
                "boundary_kind": boundary_kind,
            }
        )
        item = pm.ProgramEntity(
            self.snapshot.snapshot_id,
            pm.entity_id(self.snapshot, "EXTERNAL_BOUNDARY", key),
            key,
            "EXTERNAL_BOUNDARY",
            str(sdk or owner or target.display_name or "external boundary"),
            REPRESENTATION,
            scope,
            props,
            (evidence_ref,),
        )
        self._boundary_entities[item.entity_id] = item
        return item

    def _find_function_row(
        self,
        conn: sqlite3.Connection,
        identifier: str,
    ) -> tuple[sqlite3.Row | None, bool]:
        started = time.monotonic()
        rows = conn.execute(
            "SELECT * FROM methods ORDER BY class,name,descriptor,id LIMIT ?",
            (MAX_PROVIDER_SCAN_METHODS + 1,),
        )
        scanned = 0
        for row in rows:
            scanned += 1
            if scanned > MAX_PROVIDER_SCAN_METHODS:
                return None, True
            if time.monotonic() - started > MAX_PROVIDER_QUERY_SECONDS:
                return None, True
            if self._function_entity(row).entity_id == identifier:
                return row, False
        return None, False

    def _find_class_name(
        self,
        conn: sqlite3.Connection,
        identifier: str,
    ) -> tuple[str | None, bool]:
        started = time.monotonic()
        rows = conn.execute(
            "SELECT class,MAX(external) external FROM methods "
            "GROUP BY class ORDER BY class LIMIT ?",
            (MAX_PROVIDER_SCAN_METHODS + 1,),
        )
        scanned = 0
        for row in rows:
            scanned += 1
            if scanned > MAX_PROVIDER_SCAN_METHODS:
                return None, True
            if time.monotonic() - started > MAX_PROVIDER_QUERY_SECONDS:
                return None, True
            item = self._class_entity(
                str(row["class"]),
                external=bool(row["external"]),
            )
            if item.entity_id == identifier:
                return str(row["class"]), False
        return None, False

    def _edge_entities(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        cache: dict[str, pm.ProgramEntity | None],
    ) -> tuple[pm.ProgramEntity | None, pm.ProgramEntity | None]:
        def resolve(private_id: str) -> pm.ProgramEntity | None:
            if private_id in cache:
                return cache[private_id]
            method_row = conn.execute(
                "SELECT * FROM methods WHERE id=?",
                (private_id,),
            ).fetchone()
            item = (
                self._function_entity(method_row)
                if method_row is not None
                else self._synthetic_function(private_id)
            )
            cache[private_id] = item
            return item

        return resolve(str(row["caller"])), resolve(str(row["callee"]))

    def _scan_call_relationships(
        self,
        conn: sqlite3.Connection,
        *,
        started: float,
        private_id: str | None = None,
    ) -> tuple[list[pm.ProgramRelationship], bool]:
        if private_id is None:
            rows = conn.execute(
                "SELECT * FROM call_edges "
                "ORDER BY kind,caller,callee,offset LIMIT ?",
                (MAX_PROVIDER_SCAN_EDGES + 1,),
            )
        else:
            rows = conn.execute(
                "SELECT * FROM call_edges WHERE caller=? OR callee=? "
                "ORDER BY kind,caller,callee,offset LIMIT ?",
                (private_id, private_id, MAX_PROVIDER_SCAN_EDGES + 1),
            )
        cache: dict[str, pm.ProgramEntity | None] = {}
        result: list[pm.ProgramRelationship] = []
        scanned = 0
        truncated = False
        for row in rows:
            scanned += 1
            if scanned > MAX_PROVIDER_SCAN_EDGES:
                truncated = True
                break
            if time.monotonic() - started > MAX_PROVIDER_QUERY_SECONDS:
                truncated = True
                break
            caller, callee = self._edge_entities(conn, row, cache)
            if caller is None or callee is None:
                continue
            result.append(
                self._call_relationship(
                    caller,
                    callee,
                    offset=int(row["offset"]),
                    edge_kind=str(row["kind"]),
                )
            )
        return result, truncated

    def _find_boundary(
        self,
        conn: sqlite3.Connection,
        identifier: str,
    ) -> tuple[pm.ProgramEntity | None, bool]:
        if identifier in self._boundary_entities:
            return self._boundary_entities[identifier], False
        _, truncated = self._scan_call_relationships(
            conn,
            started=time.monotonic(),
        )
        return self._boundary_entities.get(identifier), truncated

    def get_entity(self, entity_id: str) -> pm.ProgramEntity | None:
        app = self._application()
        if app.entity_id == entity_id:
            return app
        if entity_id in self._boundary_entities:
            return self._boundary_entities[entity_id]
        with pu_index.connect(self.job) as conn:
            if str(entity_id).startswith(_BOUNDARY_ID_PREFIX):
                boundary, _ = self._find_boundary(conn, entity_id)
                return boundary
            row, _ = self._find_function_row(conn, entity_id)
            if row is not None:
                return self._function_entity(row)
            class_name, _ = self._find_class_name(conn, entity_id)
            if class_name:
                first = conn.execute(
                    "SELECT external FROM methods WHERE class=? ORDER BY id LIMIT 1",
                    (class_name,),
                ).fetchone()
                return self._class_entity(
                    class_name,
                    external=bool(first["external"]) if first else False,
                )
        return None

    @staticmethod
    def _finish_page(
        accepted: list[Any],
        *,
        limit: int,
        truncated: bool,
    ) -> pm.ProviderPage:
        has_more = len(accepted) > limit
        return pm.ProviderPage(
            tuple(accepted[:limit]),
            has_more=has_more,
            truncated=truncated,
        )

    @staticmethod
    def _kind_may_follow(
        kind: str,
        after: tuple[str, str, str, str] | None,
    ) -> bool:
        return after is None or kind >= after[0]

    def query_entities(
        self,
        *,
        kind: str | None = None,
        text: str | None = None,
        ownership_scope: str = "application",
        representation: str | None = None,
        after: tuple[str, str, str, str] | None = None,
        limit: int = pm.MAX_PAGE_SIZE,
    ) -> pm.ProviderPage:
        scope = validate_ownership_scope(ownership_scope)
        limit = max(1, min(int(limit), pm.MAX_PROVIDER_PAGE_SIZE))
        if representation and representation not in {REPRESENTATION, "artifact"}:
            return pm.ProviderPage(())
        needle = str(text or "").lower()
        accepted: list[pm.ProgramEntity] = []
        truncated = False
        started = time.monotonic()

        def consider(item: pm.ProgramEntity) -> bool:
            if kind and item.kind != kind:
                return False
            if representation and item.representation != representation:
                return False
            if not ownership_scope_accepts(item.ownership, scope):
                return False
            if needle and needle not in (
                item.display_name + " " + item.semantic_key
            ).lower():
                return False
            key = pm.entity_sort_key(item)
            if after is not None and key <= after:
                return False
            accepted.append(item)
            return len(accepted) > limit

        if kind in {None, "APPLICATION"} and self._kind_may_follow(
            "APPLICATION", after
        ):
            if consider(self._application()):
                return self._finish_page(accepted, limit=limit, truncated=False)

        with pu_index.connect(self.job) as conn:
            if kind in {None, "CLASS"} and self._kind_may_follow("CLASS", after):
                rows = conn.execute(
                    "SELECT class,MAX(external) external FROM methods "
                    "GROUP BY class ORDER BY class LIMIT ?",
                    (MAX_PROVIDER_SCAN_METHODS + 1,),
                )
                scanned = 0
                for row in rows:
                    scanned += 1
                    if scanned > MAX_PROVIDER_SCAN_METHODS:
                        truncated = True
                        break
                    if time.monotonic() - started > MAX_PROVIDER_QUERY_SECONDS:
                        truncated = True
                        break
                    if consider(
                        self._class_entity(
                            str(row["class"]),
                            external=bool(row["external"]),
                        )
                    ):
                        return self._finish_page(
                            accepted,
                            limit=limit,
                            truncated=truncated,
                        )

            if kind in {None, "FUNCTION"} and self._kind_may_follow(
                "FUNCTION", after
            ):
                rows = conn.execute(
                    "SELECT * FROM methods ORDER BY class,name,descriptor,id LIMIT ?",
                    (MAX_PROVIDER_SCAN_METHODS + 1,),
                )
                scanned = 0
                for row in rows:
                    scanned += 1
                    if scanned > MAX_PROVIDER_SCAN_METHODS:
                        truncated = True
                        break
                    if time.monotonic() - started > MAX_PROVIDER_QUERY_SECONDS:
                        truncated = True
                        break
                    if consider(self._function_entity(row)):
                        return self._finish_page(
                            accepted,
                            limit=limit,
                            truncated=truncated,
                        )

        accepted.sort(key=pm.entity_sort_key)
        return self._finish_page(accepted, limit=limit, truncated=truncated)

    def _declares(
        self,
        source: pm.ProgramEntity,
        target: pm.ProgramEntity,
    ) -> pm.ProgramRelationship:
        refs = tuple(sorted(set(source.evidence_refs) | set(target.evidence_refs)))
        return pm.ProgramRelationship(
            self.snapshot.snapshot_id,
            pm.relationship_id(
                self.snapshot,
                "DECLARES",
                source.entity_id,
                target.entity_id,
            ),
            "DECLARES",
            source.entity_id,
            target.entity_id,
            REPRESENTATION,
            {},
            refs,
        )

    def _call_relationship(
        self,
        caller: pm.ProgramEntity,
        callee: pm.ProgramEntity,
        *,
        offset: int,
        edge_kind: str,
    ) -> pm.ProgramRelationship:
        is_call = self.analysis_kind == "dex-xref" and edge_kind == "dex-xref"
        caller_class = caller.display_name.rsplit(".", 1)[0]
        callee_class = callee.display_name.rsplit(".", 1)[0]
        caller_decision = self.classifier.classify(
            caller_class,
            external=caller.properties.get("implementation") == "external",
        )
        callee_decision = self.classifier.classify(
            callee_class,
            external=callee.properties.get("implementation") == "external",
        )
        app_scopes = {"FIRST_PARTY", "UNKNOWN"}
        crossing = caller.ownership in app_scopes and callee.ownership in EXTERNAL_SCOPES
        reverse_crossing = (
            callee.ownership in app_scopes and caller.ownership in EXTERNAL_SCOPES
        )
        evidence_ref = self._evidence_ref(
            {
                "kind": "dex-callsite" if is_call else "dex-xref",
                "caller": caller.semantic_key,
                "target": callee.semantic_key,
                "offset": int(offset),
            }
        )
        if crossing or reverse_crossing:
            external = callee if crossing else caller
            decision = callee_decision if crossing else caller_decision
            boundary = self._boundary(external, decision)
            kind = "CALLS_EXTERNAL" if is_call else "XREF"
            source = caller if crossing else boundary
            target = boundary if crossing else callee
            if is_call:
                props = {
                    "callsite_offset": int(offset),
                    "boundary_kind": boundary.properties["boundary_kind"],
                }
            else:
                props = {
                    "reference_offset": int(offset),
                    "reference_kind": edge_kind,
                }
        else:
            kind = "CALLS" if is_call else "XREF"
            source, target = caller, callee
            if is_call:
                props = {"callsite_offset": int(offset)}
            else:
                props = {
                    "reference_offset": int(offset),
                    "reference_kind": edge_kind,
                }
        return pm.ProgramRelationship(
            self.snapshot.snapshot_id,
            pm.relationship_id(
                self.snapshot,
                kind,
                source.entity_id,
                target.entity_id,
                str(offset),
            ),
            kind,
            source.entity_id,
            target.entity_id,
            REPRESENTATION,
            props,
            (evidence_ref,),
        )

    def query_relationships(
        self,
        *,
        entity_id: str,
        kinds: frozenset[str] | None = None,
        direction: str = "both",
        ownership_scope: str = "application",
        after: tuple[str, str, str, str] | None = None,
        limit: int = pm.MAX_PAGE_SIZE,
    ) -> pm.ProviderPage:
        scope = validate_ownership_scope(ownership_scope)
        limit = max(1, min(int(limit), pm.MAX_PROVIDER_PAGE_SIZE))
        accepted: list[pm.ProgramRelationship] = []
        truncated = False
        started = time.monotonic()
        app = self._application()

        def consider(item: pm.ProgramRelationship) -> bool:
            if kinds and item.kind not in kinds:
                return False
            if direction == "incoming" and item.target_entity_id != entity_id:
                return False
            if direction == "outgoing" and item.source_entity_id != entity_id:
                return False
            if direction == "both" and entity_id not in {
                item.source_entity_id,
                item.target_entity_id,
            }:
                return False
            key = pm.relationship_sort_key(item)
            if after is not None and key <= after:
                return False
            accepted.append(item)
            return len(accepted) > limit

        with pu_index.connect(self.job) as conn:
            if str(entity_id).startswith(_BOUNDARY_ID_PREFIX):
                relations, edge_truncated = self._scan_call_relationships(
                    conn,
                    started=started,
                )
                truncated = truncated or edge_truncated
                for relation in relations:
                    consider(relation)
                accepted.sort(key=pm.relationship_sort_key)
                return self._finish_page(
                    accepted,
                    limit=limit,
                    truncated=truncated,
                )

            function_row, function_scan_truncated = self._find_function_row(
                conn,
                entity_id,
            )
            class_name, class_scan_truncated = self._find_class_name(
                conn,
                entity_id,
            )
            truncated = function_scan_truncated or class_scan_truncated

            if entity_id == app.entity_id and direction in {"outgoing", "both"}:
                rows = conn.execute(
                    "SELECT class,MAX(external) external FROM methods "
                    "GROUP BY class ORDER BY class LIMIT ?",
                    (MAX_PROVIDER_SCAN_METHODS + 1,),
                )
                scanned = 0
                for row in rows:
                    scanned += 1
                    if scanned > MAX_PROVIDER_SCAN_METHODS:
                        truncated = True
                        break
                    if time.monotonic() - started > MAX_PROVIDER_QUERY_SECONDS:
                        truncated = True
                        break
                    target = self._class_entity(
                        str(row["class"]),
                        external=bool(row["external"]),
                    )
                    if not ownership_scope_accepts(target.ownership, scope):
                        continue
                    if consider(self._declares(app, target)):
                        break

            if class_name:
                first = conn.execute(
                    "SELECT external FROM methods WHERE class=? ORDER BY id LIMIT 1",
                    (class_name,),
                ).fetchone()
                class_entity = self._class_entity(
                    class_name,
                    external=bool(first["external"]) if first else False,
                )
                if direction in {"incoming", "both"}:
                    consider(self._declares(app, class_entity))
                if direction in {"outgoing", "both"} and len(accepted) <= limit:
                    rows = conn.execute(
                        "SELECT * FROM methods WHERE class=? "
                        "ORDER BY name,descriptor,id LIMIT ?",
                        (class_name, MAX_PROVIDER_SCAN_METHODS + 1),
                    )
                    scanned = 0
                    for row in rows:
                        scanned += 1
                        if scanned > MAX_PROVIDER_SCAN_METHODS:
                            truncated = True
                            break
                        if time.monotonic() - started > MAX_PROVIDER_QUERY_SECONDS:
                            truncated = True
                            break
                        target = self._function_entity(row)
                        if not ownership_scope_accepts(target.ownership, scope):
                            continue
                        if consider(self._declares(class_entity, target)):
                            break

            if function_row is not None and len(accepted) <= limit:
                function = self._function_entity(function_row)
                class_entity = self._class_entity(str(function_row["class"]))
                if direction in {"incoming", "both"}:
                    consider(self._declares(class_entity, function))
                relations, edge_truncated = self._scan_call_relationships(
                    conn,
                    started=started,
                    private_id=str(function_row["id"]),
                )
                truncated = truncated or edge_truncated
                for relation in relations:
                    consider(relation)

        accepted.sort(key=pm.relationship_sort_key)
        return self._finish_page(accepted, limit=limit, truncated=truncated)

    def get_evidence(self, evidence_ref: str) -> dict[str, Any] | None:
        return self._evidence.get(str(evidence_ref))
