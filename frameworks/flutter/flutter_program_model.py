from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any

import flutter_semantic as semantic
import peg_schema
import program_model as pm
from ownership_contract import ownership_scope_accepts, validate_ownership_scope

MAX_PROVIDER_SCAN_ROWS = 250_000
MAX_PROVIDER_XREFS = 20_000
MAX_PROVIDER_QUERY_SECONDS = 5
REPRESENTATION = "flutter-dart-aot"
_FUNCTION_SCAN_SQL = """
SELECT f.*,
       COUNT(*) OVER (
         PARTITION BY library_url,class_name,name,signature
       ) AS duplicate_count
FROM functions f
ORDER BY library_url,class_name,name,signature,native_offset
LIMIT ?
"""


def flutter_ownership(library_url: str) -> dict[str, Any]:
    url = str(library_url or "").strip()
    if url.startswith("dart:"):
        return {
            "scope": "PLATFORM",
            "owner": "Dart SDK",
            "sdk": "Dart",
            "reason": "dart_sdk_library",
        }
    if url.startswith("package:flutter/"):
        return {
            "scope": "PLATFORM",
            "owner": "Flutter",
            "sdk": "Flutter",
            "reason": "flutter_framework_library",
        }
    return {
        "scope": "UNKNOWN",
        "owner": None,
        "sdk": None,
        "reason": "insufficient_flutter_ownership_evidence",
    }


class FlutterProgramProvider:
    def __init__(self, index_path: Path) -> None:
        self.index_path = Path(index_path).resolve()
        conn = semantic._open_db(self.index_path)
        try:
            self.meta = semantic._metadata(conn)
        finally:
            conn.close()
        self._snapshot = pm.ProgramSnapshot(
            str(self.meta.get("artifact_sha256") or ""),
            str(self.meta.get("artifact_kind") or "libapp.so"),
        )
        self.analysis_id = str(
            self.meta.get("analysis_id")
            or f"flutter-aot:{self.snapshot.artifact_sha256}"
        )
        self.analyzer_name = str(
            self.meta.get("analyzer") or "blutter-semantic-index"
        )
        self.analyzer_version = str(
            self.meta.get("blutter_commit") or "unknown"
        )
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
            limitations = []
            if location.get("kind") == "flutter-xref":
                limitations.append(
                    "Blutter XREF/call-adjacency evidence is not proof of value flow"
                )
            self._evidence[ref] = peg_schema.evidence(
                analysis_id=self.analysis_id,
                artifact_sha256=self.snapshot.artifact_sha256,
                analyzer_name=self.analyzer_name,
                analyzer_version=self.analyzer_version,
                state=state,
                location=location,
                limitations=limitations,
            )
        return ref

    def _application(self) -> pm.ProgramEntity:
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
            "Flutter application",
            "artifact",
            "UNKNOWN",
            {"artifact_kind": self.snapshot.artifact_kind},
            (evidence_ref,),
        )

    @staticmethod
    def module_key(library_url: str) -> str:
        return f"module:v1:flutter-dart-aot:{library_url}"

    @classmethod
    def class_key(cls, library_url: str, class_name: str) -> str:
        return (
            f"class:v1:flutter-dart-aot:{cls.module_key(library_url)}:"
            f"{class_name}"
        )

    def _function_key(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        duplicate_count: int | None = None,
    ) -> str:
        library_url = str(row["library_url"])
        class_name = str(row["class_name"])
        name = str(row["name"])
        signature = str(row["signature"])
        base = (
            f"function:v1:flutter-dart-aot:"
            f"{self.class_key(library_url, class_name)}:{name}:{signature}"
        )
        if duplicate_count is None:
            duplicate_count = int(
                conn.execute(
                    "SELECT COUNT(*) n FROM functions "
                    "WHERE library_url=? AND class_name=? AND name=? AND signature=?",
                    (library_url, class_name, name, signature),
                ).fetchone()["n"]
            )
        if duplicate_count > 1:
            base += f"@0x{int(row['native_offset']):x}"
        return base

    def _module_entity(self, row: sqlite3.Row) -> pm.ProgramEntity:
        url = str(row["url"])
        ownership = flutter_ownership(url)
        evidence_ref = self._evidence_ref(
            {
                "kind": "dart-library",
                "library_url": url,
                "source_file": str(row["source_file"]),
                "line": int(row["line"]),
            }
        )
        key = self.module_key(url)
        return pm.ProgramEntity(
            self.snapshot.snapshot_id,
            pm.entity_id(self.snapshot, "MODULE", key),
            key,
            "MODULE",
            str(row["name"] or url),
            REPRESENTATION,
            ownership["scope"],
            {"module_kind": "dart-library", "uri": url},
            (evidence_ref,),
        )

    def _class_entity(
        self,
        row: sqlite3.Row,
        *,
        library_url: str | None = None,
    ) -> pm.ProgramEntity:
        if library_url is None:
            module = self._module_row_by_id(str(row["library_id"]))
            library_url = str(module["url"] if module is not None else "")
        ownership = flutter_ownership(library_url)
        class_name = str(row["name"])
        evidence_ref = self._evidence_ref(
            {
                "kind": "dart-class",
                "library_url": library_url,
                "class_name": class_name,
                "source_file": str(row["source_file"]),
                "line": int(row["line"]),
            }
        )
        key = self.class_key(library_url, class_name)
        return pm.ProgramEntity(
            self.snapshot.snapshot_id,
            pm.entity_id(self.snapshot, "CLASS", key),
            key,
            "CLASS",
            f"{library_url}::{class_name}",
            REPRESENTATION,
            ownership["scope"],
            {"qualified_name": f"{library_url}::{class_name}"},
            (evidence_ref,),
        )

    def _function_entity(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        duplicate_count: int | None = None,
    ) -> pm.ProgramEntity:
        library_url = str(row["library_url"])
        ownership = flutter_ownership(library_url)
        if duplicate_count is None and "duplicate_count" in row.keys():
            duplicate_count = int(row["duplicate_count"])
        key = self._function_key(
            conn,
            row,
            duplicate_count=duplicate_count,
        )
        evidence_ref = self._evidence_ref(
            {
                "kind": "dart-function",
                "library_url": library_url,
                "class_name": str(row["class_name"]),
                "name": str(row["name"]),
                "source_file": str(row["source_file"]),
                "line": int(row["line"]),
                "native_offset": int(row["native_offset"]),
            }
        )
        return pm.ProgramEntity(
            self.snapshot.snapshot_id,
            pm.entity_id(self.snapshot, "FUNCTION", key),
            key,
            "FUNCTION",
            f"{library_url}::{row['class_name']}::{row['name']}",
            REPRESENTATION,
            ownership["scope"],
            {
                "signature": str(row["signature"]),
                "native_offset": int(row["native_offset"]),
                "size": int(row["size"]),
                "implementation": "present",
            },
            (evidence_ref,),
        )

    def _module_row_by_id(self, library_id: str) -> sqlite3.Row | None:
        conn = semantic._open_db(self.index_path)
        try:
            return conn.execute(
                "SELECT * FROM libraries WHERE id=?",
                (library_id,),
            ).fetchone()
        finally:
            conn.close()

    def _boundary(
        self,
        *,
        library_url: str,
        class_name: str,
        name: str,
        ownership: dict[str, Any],
        evidence_refs: tuple[str, ...],
    ) -> pm.ProgramEntity:
        scope = str(ownership.get("scope") or "UNKNOWN")
        boundary_kind = (
            "platform"
            if scope == "PLATFORM"
            else "third-party-sdk"
            if scope == "THIRD_PARTY"
            else "external-unresolved"
        )
        target = f"{library_url}::{class_name}::{name}"
        key = f"boundary:v1:{boundary_kind}:{target}"
        props: dict[str, Any] = {
            "boundary_kind": boundary_kind,
            "target": target,
        }
        if ownership.get("owner"):
            props["owner"] = str(ownership["owner"])
        if ownership.get("sdk"):
            props["sdk"] = str(ownership["sdk"])
        item = pm.ProgramEntity(
            self.snapshot.snapshot_id,
            pm.entity_id(self.snapshot, "EXTERNAL_BOUNDARY", key),
            key,
            "EXTERNAL_BOUNDARY",
            str(ownership.get("sdk") or ownership.get("owner") or target),
            REPRESENTATION,
            scope,
            props,
            evidence_refs,
        )
        self._boundary_entities[item.entity_id] = item
        return item

    def _find_entity_rows(
        self,
        identifier: str,
    ) -> tuple[str | None, sqlite3.Row | None, bool]:
        started = time.monotonic()
        conn = semantic._open_db(self.index_path)
        try:
            scanned = 0
            for row in conn.execute(
                "SELECT * FROM libraries ORDER BY url LIMIT ?",
                (MAX_PROVIDER_SCAN_ROWS + 1,),
            ):
                scanned += 1
                if scanned > MAX_PROVIDER_SCAN_ROWS:
                    return None, None, True
                if time.monotonic() - started > MAX_PROVIDER_QUERY_SECONDS:
                    return None, None, True
                if self._module_entity(row).entity_id == identifier:
                    return "MODULE", row, False

            scanned = 0
            for row in conn.execute(
                "SELECT c.*,l.url AS library_url FROM classes c "
                "JOIN libraries l ON l.id=c.library_id "
                "ORDER BY l.url,c.name,c.id LIMIT ?",
                (MAX_PROVIDER_SCAN_ROWS + 1,),
            ):
                scanned += 1
                if scanned > MAX_PROVIDER_SCAN_ROWS:
                    return None, None, True
                if time.monotonic() - started > MAX_PROVIDER_QUERY_SECONDS:
                    return None, None, True
                if self._class_entity(
                    row,
                    library_url=str(row["library_url"]),
                ).entity_id == identifier:
                    return "CLASS", row, False

            scanned = 0
            for row in conn.execute(
                _FUNCTION_SCAN_SQL,
                (MAX_PROVIDER_SCAN_ROWS + 1,),
            ):
                scanned += 1
                if scanned > MAX_PROVIDER_SCAN_ROWS:
                    return None, None, True
                if time.monotonic() - started > MAX_PROVIDER_QUERY_SECONDS:
                    return None, None, True
                if self._function_entity(conn, row).entity_id == identifier:
                    return "FUNCTION", row, False
        finally:
            conn.close()
        return None, None, False

    def get_entity(self, entity_id: str) -> pm.ProgramEntity | None:
        app = self._application()
        if app.entity_id == entity_id:
            return app
        if entity_id in self._boundary_entities:
            return self._boundary_entities[entity_id]
        kind, row, _ = self._find_entity_rows(entity_id)
        if row is None:
            return None
        if kind == "MODULE":
            return self._module_entity(row)
        if kind == "CLASS":
            library_url = str(row["library_url"]) if "library_url" in row.keys() else None
            return self._class_entity(row, library_url=library_url)
        if kind == "FUNCTION":
            conn = semantic._open_db(self.index_path)
            try:
                return self._function_entity(conn, row)
            finally:
                conn.close()
        return None

    @staticmethod
    def _finish_page(
        accepted: list[Any],
        *,
        limit: int,
        truncated: bool,
    ) -> pm.ProviderPage:
        accepted.sort(
            key=(
                pm.entity_sort_key
                if not accepted or isinstance(accepted[0], pm.ProgramEntity)
                else pm.relationship_sort_key
            )
        )
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

        if kind in {None, "APPLICATION"} and self._kind_may_follow("APPLICATION", after):
            if consider(self._application()):
                return self._finish_page(accepted, limit=limit, truncated=False)

        conn = semantic._open_db(self.index_path)
        try:
            if kind in {None, "CLASS"} and self._kind_may_follow("CLASS", after):
                rows = conn.execute(
                    "SELECT c.*,l.url AS library_url FROM classes c "
                    "JOIN libraries l ON l.id=c.library_id "
                    "ORDER BY l.url,c.name,c.id LIMIT ?",
                    (MAX_PROVIDER_SCAN_ROWS + 1,),
                )
                scanned = 0
                for row in rows:
                    scanned += 1
                    if scanned > MAX_PROVIDER_SCAN_ROWS:
                        truncated = True
                        break
                    if time.monotonic() - started > MAX_PROVIDER_QUERY_SECONDS:
                        truncated = True
                        break
                    if consider(
                        self._class_entity(
                            row,
                            library_url=str(row["library_url"]),
                        )
                    ):
                        return self._finish_page(
                            accepted,
                            limit=limit,
                            truncated=truncated,
                        )

            if kind in {None, "FUNCTION"} and self._kind_may_follow("FUNCTION", after):
                rows = conn.execute(
                    _FUNCTION_SCAN_SQL,
                    (MAX_PROVIDER_SCAN_ROWS + 1,),
                )
                scanned = 0
                for row in rows:
                    scanned += 1
                    if scanned > MAX_PROVIDER_SCAN_ROWS:
                        truncated = True
                        break
                    if time.monotonic() - started > MAX_PROVIDER_QUERY_SECONDS:
                        truncated = True
                        break
                    if consider(self._function_entity(conn, row)):
                        return self._finish_page(
                            accepted,
                            limit=limit,
                            truncated=truncated,
                        )

            if kind in {None, "MODULE"} and self._kind_may_follow("MODULE", after):
                rows = conn.execute(
                    "SELECT * FROM libraries ORDER BY url LIMIT ?",
                    (MAX_PROVIDER_SCAN_ROWS + 1,),
                )
                scanned = 0
                for row in rows:
                    scanned += 1
                    if scanned > MAX_PROVIDER_SCAN_ROWS:
                        truncated = True
                        break
                    if time.monotonic() - started > MAX_PROVIDER_QUERY_SECONDS:
                        truncated = True
                        break
                    if consider(self._module_entity(row)):
                        return self._finish_page(
                            accepted,
                            limit=limit,
                            truncated=truncated,
                        )
        finally:
            conn.close()

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

    def _xref_relationship(
        self,
        conn: sqlite3.Connection,
        caller: pm.ProgramEntity,
        row: sqlite3.Row,
    ) -> pm.ProgramRelationship:
        library_url = str(row["target_library_url"])
        class_name = str(row["target_class_name"])
        name = str(row["target_name"])
        evidence_ref = self._evidence_ref(
            {
                "kind": "flutter-xref",
                "caller": caller.semantic_key,
                "target_library_url": library_url,
                "target_class_name": class_name,
                "target_name": name,
                "source_file": str(row["source_file"]),
                "line": int(row["line"]),
            }
        )
        ownership = flutter_ownership(library_url)
        target: pm.ProgramEntity | None = None
        if row["target_id"]:
            target_row = conn.execute(
                "SELECT * FROM functions WHERE id=?",
                (row["target_id"],),
            ).fetchone()
            if target_row is not None:
                target = self._function_entity(conn, target_row)
        if target is None or ownership["scope"] in {
            "THIRD_PARTY",
            "PLATFORM",
            "GENERATED",
        }:
            target = self._boundary(
                library_url=library_url,
                class_name=class_name,
                name=name,
                ownership=ownership,
                evidence_refs=(evidence_ref,),
            )
        return pm.ProgramRelationship(
            self.snapshot.snapshot_id,
            pm.relationship_id(
                self.snapshot,
                "XREF",
                caller.entity_id,
                target.entity_id,
                f"{row['source_file']}:{row['line']}",
            ),
            "XREF",
            caller.entity_id,
            target.entity_id,
            REPRESENTATION,
            {
                "reference_kind": "blutter-xref",
                "reference_offset": int(row["line"]),
            },
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

        entity_kind, entity_row, scan_truncated = self._find_entity_rows(entity_id)
        truncated = truncated or scan_truncated
        conn = semantic._open_db(self.index_path)
        try:
            if entity_id == app.entity_id and direction in {"outgoing", "both"}:
                rows = conn.execute(
                    "SELECT * FROM libraries ORDER BY url LIMIT ?",
                    (MAX_PROVIDER_SCAN_ROWS + 1,),
                )
                scanned = 0
                for row in rows:
                    scanned += 1
                    if scanned > MAX_PROVIDER_SCAN_ROWS:
                        truncated = True
                        break
                    if time.monotonic() - started > MAX_PROVIDER_QUERY_SECONDS:
                        truncated = True
                        break
                    module = self._module_entity(row)
                    if not ownership_scope_accepts(module.ownership, scope):
                        continue
                    if consider(self._declares(app, module)):
                        break

            if entity_kind == "MODULE" and entity_row is not None:
                module = self._module_entity(entity_row)
                if direction in {"incoming", "both"}:
                    consider(self._declares(app, module))
                if direction in {"outgoing", "both"} and len(accepted) <= limit:
                    rows = conn.execute(
                        "SELECT c.*,l.url AS library_url FROM classes c "
                        "JOIN libraries l ON l.id=c.library_id "
                        "WHERE c.library_id=? ORDER BY c.name,c.id LIMIT ?",
                        (entity_row["id"], MAX_PROVIDER_SCAN_ROWS + 1),
                    )
                    scanned = 0
                    for row in rows:
                        scanned += 1
                        if scanned > MAX_PROVIDER_SCAN_ROWS:
                            truncated = True
                            break
                        if time.monotonic() - started > MAX_PROVIDER_QUERY_SECONDS:
                            truncated = True
                            break
                        target = self._class_entity(
                            row,
                            library_url=str(row["library_url"]),
                        )
                        if not ownership_scope_accepts(target.ownership, scope):
                            continue
                        if consider(self._declares(module, target)):
                            break

            if entity_kind == "CLASS" and entity_row is not None:
                class_library_url = (
                    str(entity_row["library_url"])
                    if "library_url" in entity_row.keys()
                    else None
                )
                clazz = self._class_entity(
                    entity_row,
                    library_url=class_library_url,
                )
                module_row = conn.execute(
                    "SELECT * FROM libraries WHERE id=?",
                    (entity_row["library_id"],),
                ).fetchone()
                if module_row is not None and direction in {"incoming", "both"}:
                    consider(self._declares(self._module_entity(module_row), clazz))
                if direction in {"outgoing", "both"} and len(accepted) <= limit:
                    rows = conn.execute(
                        "SELECT f.*,COUNT(*) OVER ("
                        "PARTITION BY library_url,class_name,name,signature"
                        ") AS duplicate_count FROM functions f "
                        "WHERE class_id_ref=? "
                        "ORDER BY name,signature,native_offset LIMIT ?",
                        (entity_row["id"], MAX_PROVIDER_SCAN_ROWS + 1),
                    )
                    scanned = 0
                    for row in rows:
                        scanned += 1
                        if scanned > MAX_PROVIDER_SCAN_ROWS:
                            truncated = True
                            break
                        if time.monotonic() - started > MAX_PROVIDER_QUERY_SECONDS:
                            truncated = True
                            break
                        target = self._function_entity(conn, row)
                        if not ownership_scope_accepts(target.ownership, scope):
                            continue
                        if consider(self._declares(clazz, target)):
                            break

            if entity_kind == "FUNCTION" and entity_row is not None:
                function = self._function_entity(conn, entity_row)
                class_row = conn.execute(
                    "SELECT c.*,l.url AS library_url FROM classes c "
                    "JOIN libraries l ON l.id=c.library_id WHERE c.id=?",
                    (entity_row["class_id_ref"],),
                ).fetchone()
                if class_row is not None and direction in {"incoming", "both"}:
                    consider(
                        self._declares(
                            self._class_entity(
                                class_row,
                                library_url=str(class_row["library_url"]),
                            ),
                            function,
                        )
                    )

                if len(accepted) <= limit:
                    clauses = []
                    params: list[Any] = []
                    if direction in {"outgoing", "both"}:
                        clauses.append("caller_id=?")
                        params.append(entity_row["id"])
                    if direction in {"incoming", "both"}:
                        clauses.append("target_id=?")
                        params.append(entity_row["id"])
                    if clauses:
                        rows = conn.execute(
                            "SELECT * FROM xrefs WHERE "
                            + " OR ".join(clauses)
                            + " ORDER BY source_file,line,id LIMIT ?",
                            (*params, MAX_PROVIDER_XREFS + 1),
                        )
                        scanned = 0
                        for row in rows:
                            scanned += 1
                            if scanned > MAX_PROVIDER_XREFS:
                                truncated = True
                                break
                            if time.monotonic() - started > MAX_PROVIDER_QUERY_SECONDS:
                                truncated = True
                                break
                            caller_row = conn.execute(
                                "SELECT * FROM functions WHERE id=?",
                                (row["caller_id"],),
                            ).fetchone()
                            if caller_row is None:
                                continue
                            relation = self._xref_relationship(
                                conn,
                                self._function_entity(conn, caller_row),
                                row,
                            )
                            if consider(relation):
                                break
        finally:
            conn.close()

        return self._finish_page(accepted, limit=limit, truncated=truncated)

    def get_evidence(self, evidence_ref: str) -> dict[str, Any] | None:
        return self._evidence.get(str(evidence_ref))
