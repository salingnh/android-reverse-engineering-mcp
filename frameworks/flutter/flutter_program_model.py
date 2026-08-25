from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable

import flutter_semantic as semantic
import peg_schema
import program_model as pm
from ownership_contract import ownership_scope_accepts

MAX_PROVIDER_SCAN_ROWS = 250_000
MAX_PROVIDER_XREFS = 20_000
MAX_PROVIDER_QUERY_SECONDS = 5
REPRESENTATION = "flutter-dart-aot"


def flutter_ownership(library_url: str) -> dict[str, Any]:
    url = str(library_url or "").strip()
    if url.startswith("dart:"):
        return {"scope": "PLATFORM", "owner": "Dart", "sdk": "Dart SDK"}
    if url.startswith("package:flutter/"):
        return {"scope": "PLATFORM", "owner": "Flutter", "sdk": "Flutter Framework"}
    # package: does not imply third-party: app code and dependencies both use it.
    return {"scope": "UNKNOWN", "owner": None, "sdk": None}


class FlutterProgramProvider:
    def __init__(self, index_path: Path) -> None:
        self.index_path = Path(index_path)
        with semantic._open_db(self.index_path) as conn:
            self.meta = semantic._metadata(conn)
        sha = str(self.meta.get("artifact_sha256") or "")
        self._snapshot = pm.ProgramSnapshot(sha, str(self.meta.get("artifact_kind") or "libapp.so"))
        self.analysis_id = str(self.meta.get("analysis_id") or f"flutter-aot:{sha}")
        self.analyzer_name = str(self.meta.get("analyzer") or "blutter-semantic-index")
        self.analyzer_version = str(self.meta.get("blutter_commit") or "unknown")
        self._evidence: dict[str, dict[str, Any]] = {}
        self._boundaries: dict[str, pm.ProgramEntity] = {}

    @property
    def snapshot(self) -> pm.ProgramSnapshot:
        return self._snapshot

    @property
    def application_key(self) -> str:
        return "application:v1"

    @staticmethod
    def module_key(library_url: str) -> str:
        return f"module:v1:{REPRESENTATION}:{library_url}"

    @classmethod
    def class_key(cls, library_url: str, class_name: str) -> str:
        return f"class:v1:{REPRESENTATION}:{cls.module_key(library_url)}:{class_name}"

    def _function_key(self, conn: sqlite3.Connection, row: sqlite3.Row) -> str:
        base = f"function:v1:{REPRESENTATION}:{self.class_key(str(row['library_url']), str(row['class_name']))}:{str(row['signature'])}"
        count = int(conn.execute(
            "SELECT COUNT(*) FROM functions WHERE library_url=? AND class_name=? AND signature=?",
            (row["library_url"], row["class_name"], row["signature"]),
        ).fetchone()[0])
        if count > 1:
            # Actual artifact address is only a collision disambiguator, never the
            # normal semantic identity and never a private row id.
            return f"{base}@0x{int(row['native_offset']):x}"
        return base

    def _evidence_ref(self, location: dict[str, Any], *, state: str = "derived") -> str:
        ref = pm.evidence_id(self.snapshot, self.analyzer_name, location)
        if ref not in self._evidence:
            self._evidence[ref] = peg_schema.evidence(
                analysis_id=self.analysis_id,
                artifact_sha256=self.snapshot.artifact_sha256,
                analyzer_name=self.analyzer_name,
                analyzer_version=self.analyzer_version,
                state=state,
                location=location,
                image_version=str(self.meta.get("image_version")) if self.meta.get("image_version") else None,
                build_commit=str(self.meta.get("build_commit")) if self.meta.get("build_commit") else None,
            )
        return ref

    def _application(self) -> pm.ProgramEntity:
        ref = self._evidence_ref({"kind": "flutter-artifact", "artifact_sha256": self.snapshot.artifact_sha256}, state="observed")
        return pm.ProgramEntity(
            self.snapshot.snapshot_id,
            pm.entity_id(self.snapshot, "APPLICATION", self.application_key),
            self.application_key,
            "APPLICATION",
            "Flutter application",
            "artifact",
            "FIRST_PARTY",
            {"artifact_kind": self.snapshot.artifact_kind},
            (ref,),
        )

    def _module(self, row: sqlite3.Row) -> pm.ProgramEntity:
        url = str(row["url"])
        decision = flutter_ownership(url)
        ref = self._evidence_ref({"kind": "dart-library", "uri": url, "source_file": str(row["source_file"]), "line": int(row["line"])})
        key = self.module_key(url)
        return pm.ProgramEntity(
            self.snapshot.snapshot_id,
            pm.entity_id(self.snapshot, "MODULE", key),
            key,
            "MODULE",
            str(row["name"] or url),
            REPRESENTATION,
            decision["scope"],
            {"module_kind": "dart-library", "uri": url},
            (ref,),
        )

    def _class(self, row: sqlite3.Row, *, library_url: str | None = None) -> pm.ProgramEntity:
        if library_url is None:
            with semantic._open_db(self.index_path) as conn:
                lib = conn.execute("SELECT url FROM libraries WHERE id=?", (row["library_id"],)).fetchone()
            library_url = str(lib["url"]) if lib else ""
        name = str(row["name"])
        decision = flutter_ownership(library_url)
        ref = self._evidence_ref({"kind": "dart-class", "library": library_url, "class": name, "source_file": str(row["source_file"]), "line": int(row["line"])})
        key = self.class_key(library_url, name)
        return pm.ProgramEntity(
            self.snapshot.snapshot_id,
            pm.entity_id(self.snapshot, "CLASS", key),
            key,
            "CLASS",
            f"{library_url}::{name}",
            REPRESENTATION,
            decision["scope"],
            {"qualified_name": f"{library_url}::{name}"},
            (ref,),
        )

    def _function(self, conn: sqlite3.Connection, row: sqlite3.Row) -> pm.ProgramEntity:
        library_url = str(row["library_url"])
        decision = flutter_ownership(library_url)
        key = self._function_key(conn, row)
        ref = self._evidence_ref({
            "kind": "dart-function", "library": library_url,
            "class": str(row["class_name"]), "name": str(row["name"]),
            "native_offset": int(row["native_offset"]),
            "source_file": str(row["source_file"]), "line": int(row["line"]),
        })
        return pm.ProgramEntity(
            self.snapshot.snapshot_id,
            pm.entity_id(self.snapshot, "FUNCTION", key),
            key,
            "FUNCTION",
            f"{library_url}::{row['class_name']}::{row['name']}",
            REPRESENTATION,
            decision["scope"],
            {"signature": str(row["signature"]), "implementation": "present", "native_offset": int(row["native_offset"]), "size": int(row["size"])},
            (ref,),
        )

    def _boundary(self, *, library_url: str, class_name: str, name: str, target: pm.ProgramEntity | None = None) -> pm.ProgramEntity:
        decision = flutter_ownership(library_url)
        boundary_kind = "platform" if decision["scope"] == "PLATFORM" else "external-unresolved"
        target_key = target.semantic_key if target else f"{library_url}::{class_name}::{name}"
        key = f"boundary:v1:{boundary_kind}:{target_key}"
        props: dict[str, Any] = {"boundary_kind": boundary_kind, "target": f"{library_url}::{class_name}::{name}"}
        if decision.get("owner"):
            props["owner"] = decision["owner"]
        if decision.get("sdk"):
            props["sdk"] = decision["sdk"]
        item = pm.ProgramEntity(
            self.snapshot.snapshot_id,
            pm.entity_id(self.snapshot, "EXTERNAL_BOUNDARY", key),
            key,
            "EXTERNAL_BOUNDARY",
            str(decision.get("sdk") or decision.get("owner") or name or "external boundary"),
            REPRESENTATION,
            decision["scope"],
            props,
            target.evidence_refs if target else (),
        )
        self._boundaries[item.entity_id] = item
        return item

    def _find_function_by_entity_id(self, conn: sqlite3.Connection, identifier: str) -> sqlite3.Row | None:
        start = time.monotonic()
        for row in conn.execute("SELECT * FROM functions ORDER BY library_url,class_name,name,native_offset LIMIT ?", (MAX_PROVIDER_SCAN_ROWS,)):
            if time.monotonic() - start > MAX_PROVIDER_QUERY_SECONDS:
                break
            if self._function(conn, row).entity_id == identifier:
                return row
        return None

    def _find_class_by_entity_id(self, conn: sqlite3.Connection, identifier: str) -> sqlite3.Row | None:
        start = time.monotonic()
        rows = conn.execute("SELECT c.*,l.url AS library_url FROM classes c JOIN libraries l ON l.id=c.library_id ORDER BY l.url,c.name LIMIT ?", (MAX_PROVIDER_SCAN_ROWS,))
        for row in rows:
            if time.monotonic() - start > MAX_PROVIDER_QUERY_SECONDS:
                break
            if self._class(row, library_url=str(row["library_url"])).entity_id == identifier:
                return row
        return None

    def _find_module_by_entity_id(self, conn: sqlite3.Connection, identifier: str) -> sqlite3.Row | None:
        for row in conn.execute("SELECT * FROM libraries ORDER BY url LIMIT ?", (MAX_PROVIDER_SCAN_ROWS,)):
            if self._module(row).entity_id == identifier:
                return row
        return None

    def get_entity(self, entity_id: str) -> pm.ProgramEntity | None:
        app = self._application()
        if entity_id == app.entity_id:
            return app
        if entity_id in self._boundaries:
            return self._boundaries[entity_id]
        with semantic._open_db(self.index_path) as conn:
            row = self._find_function_by_entity_id(conn, entity_id)
            if row is not None:
                return self._function(conn, row)
            row = self._find_class_by_entity_id(conn, entity_id)
            if row is not None:
                return self._class(row, library_url=str(row["library_url"]))
            row = self._find_module_by_entity_id(conn, entity_id)
            if row is not None:
                return self._module(row)
        return None

    def iter_entities(self, *, kind: str | None = None, text: str | None = None, ownership_scope: str = "application", representation: str | None = None, limit: int = pm.MAX_PROVIDER_PAGE_SIZE) -> Iterable[pm.ProgramEntity]:
        limit = max(1, min(int(limit), pm.MAX_PROVIDER_PAGE_SIZE))
        if representation and representation not in {REPRESENTATION, "artifact"}:
            return
        needle = str(text or "").lower()
        count = 0
        if kind in {None, "APPLICATION"}:
            app = self._application()
            if not needle or needle in (app.display_name + " " + app.semantic_key).lower():
                yield app
                count += 1
                if count >= limit:
                    return
        with semantic._open_db(self.index_path) as conn:
            start = time.monotonic()
            if kind in {None, "MODULE"}:
                for row in conn.execute("SELECT * FROM libraries ORDER BY url LIMIT ?", (MAX_PROVIDER_SCAN_ROWS,)):
                    if time.monotonic() - start > MAX_PROVIDER_QUERY_SECONDS:
                        return
                    item = self._module(row)
                    if ownership_scope_accepts(item.ownership, ownership_scope) and (not needle or needle in (item.display_name + " " + item.semantic_key).lower()):
                        yield item
                        count += 1
                        if count >= limit:
                            return
            if kind in {None, "CLASS"}:
                for row in conn.execute("SELECT c.*,l.url AS library_url FROM classes c JOIN libraries l ON l.id=c.library_id ORDER BY l.url,c.name LIMIT ?", (MAX_PROVIDER_SCAN_ROWS,)):
                    if time.monotonic() - start > MAX_PROVIDER_QUERY_SECONDS:
                        return
                    item = self._class(row, library_url=str(row["library_url"]))
                    if ownership_scope_accepts(item.ownership, ownership_scope) and (not needle or needle in (item.display_name + " " + item.semantic_key).lower()):
                        yield item
                        count += 1
                        if count >= limit:
                            return
            if kind in {None, "FUNCTION"}:
                for row in conn.execute("SELECT * FROM functions ORDER BY library_url,class_name,name,native_offset LIMIT ?", (MAX_PROVIDER_SCAN_ROWS,)):
                    if time.monotonic() - start > MAX_PROVIDER_QUERY_SECONDS:
                        return
                    item = self._function(conn, row)
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
            "DECLARES", source.entity_id, target.entity_id, REPRESENΤATION if False else REPRESENTATION, {}, refs,
        )

    def _xref(self, conn: sqlite3.Connection, row: sqlite3.Row) -> pm.ProgramRelationship | None:
        caller_row = conn.execute("SELECT * FROM functions WHERE id=?", (row["caller_id"],)).fetchone()
        if caller_row is None:
            return None
        caller = self._function(conn, caller_row)
        target_row = conn.execute("SELECT * FROM functions WHERE id=?", (row["target_id"],)).fetchone() if row["target_id"] else None
        target = self._function(conn, target_row) if target_row is not None else None
        target_decision = flutter_ownership(str(row["target_library_url"]))
        destination = self._boundary(
            library_url=str(row["target_library_url"]),
            class_name=str(row["target_class_name"]),
            name=str(row["target_name"]),
            target=target,
        ) if target is None or target_decision["scope"] == "PLATFORM" else target
        ref = self._evidence_ref({
            "kind": "dart-xref", "caller": caller.semantic_key,
            "target_library": str(row["target_library_url"]),
            "target_class": str(row["target_class_name"]),
            "target_name": str(row["target_name"]),
            "source_file": str(row["source_file"]), "line": int(row["line"]),
        })
        return pm.ProgramRelationship(
            self.snapshot.snapshot_id,
            pm.relationship_id(self.snapshot, "XREF", caller.entity_id, destination.entity_id, f"{row['source_file']}:{row['line']}"),
            "XREF", caller.entity_id, destination.entity_id, REPRESENTATION,
            {"reference_kind": "blutter-xref"}, (ref,),
        )

    def iter_relationships(self, *, entity_id: str, kinds: frozenset[str] | None = None, direction: str = "both", ownership_scope: str = "application", limit: int = pm.MAX_PROVIDER_PAGE_SIZE) -> Iterable[pm.ProgramRelationship]:
        limit = max(1, min(int(limit), pm.MAX_PROVIDER_PAGE_SIZE))
        count = 0
        app = self._application()
        with semantic._open_db(self.index_path) as conn:
            module_row = self._find_module_by_entity_id(conn, entity_id)
            class_row = self._find_class_by_entity_id(conn, entity_id)
            function_row = self._find_function_by_entity_id(conn, entity_id)

            if entity_id == app.entity_id and direction in {"outgoing", "both"} and (not kinds or "DECLARES" in kinds):
                for row in conn.execute("SELECT * FROM libraries ORDER BY url LIMIT ?", (MAX_PROVIDER_SCAN_ROWS,)):
                    module = self._module(row)
                    if not ownership_scope_accepts(module.ownership, ownership_scope):
                        continue
                    yield self._declares(app, module)
                    count += 1
                    if count >= limit:
                        return

            if module_row is not None:
                module = self._module(module_row)
                if direction in {"incoming", "both"} and (not kinds or "DECLARES" in kinds):
                    yield self._declares(app, module)
                    count += 1
                    if count >= limit:
                        return
                if direction in {"outgoing", "both"} and (not kinds or "DECLARES" in kinds):
                    for row in conn.execute("SELECT c.*,l.url AS library_url FROM classes c JOIN libraries l ON l.id=c.library_id WHERE c.library_id=? ORDER BY c.name LIMIT ?", (module_row["id"], MAX_PROVIDER_SCAN_ROWS)):
                        target = self._class(row, library_url=str(row["library_url"]))
                        if not ownership_scope_accepts(target.ownership, ownership_scope):
                            continue
                        yield self._declares(module, target)
                        count += 1
                        if count >= limit:
                            return

            if class_row is not None:
                class_entity = self._class(class_row, library_url=str(class_row["library_url"]))
                lib = conn.execute("SELECT * FROM libraries WHERE id=?", (class_row["library_id"],)).fetchone()
                if lib is not None and direction in {"incoming", "both"} and (not kinds or "DECLARES" in kinds):
                    yield self._declares(self._module(lib), class_entity)
                    count += 1
                    if count >= limit:
                        return
                if direction in {"outgoing", "both"} and (not kinds or "DECLARES" in kinds):
                    for row in conn.execute("SELECT * FROM functions WHERE class_id_ref=? ORDER BY name,native_offset LIMIT ?", (class_row["id"], MAX_PROVIDER_SCAN_ROWS)):
                        target = self._function(conn, row)
                        if not ownership_scope_accepts(target.ownership, ownership_scope):
                            continue
                        yield self._declares(class_entity, target)
                        count += 1
                        if count >= limit:
                            return

            if function_row is not None:
                function = self._function(conn, function_row)
                if direction in {"incoming", "both"} and (not kinds or "DECLARES" in kinds):
                    class_private = conn.execute("SELECT c.*,l.url AS library_url FROM classes c JOIN libraries l ON l.id=c.library_id WHERE c.id=?", (function_row["class_id_ref"],)).fetchone()
                    if class_private is not None:
                        yield self._declares(self._class(class_private, library_url=str(class_private["library_url"])), function)
                        count += 1
                        if count >= limit:
                            return
                if not kinds or "XREF" in kinds:
                    rows: list[sqlite3.Row] = []
                    if direction in {"outgoing", "both"}:
                        rows.extend(conn.execute("SELECT * FROM xrefs WHERE caller_id=? ORDER BY source_file,line LIMIT ?", (function_row["id"], MAX_PROVIDER_XREFS)).fetchall())
                    if direction in {"incoming", "both"}:
                        rows.extend(conn.execute("SELECT * FROM xrefs WHERE target_id=? ORDER BY source_file,line LIMIT ?", (function_row["id"], MAX_PROVIDER_XREFS)).fetchall())
                    for row in rows[:MAX_PROVIDER_XREFS]:
                        relation = self._xref(conn, row)
                        if relation is None:
                            continue
                        yield relation
                        count += 1
                        if count >= limit:
                            return

    def get_evidence(self, evidence_ref: str) -> dict[str, Any] | None:
        return self._evidence.get(evidence_ref)


def repository(index_path: Path) -> pm.ProgramRepository:
    return pm.ProgramRepository((FlutterProgramProvider(index_path),))
