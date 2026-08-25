from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pu_index
import pu_ownership

MAX_QUERY_SCAN = 200_000
MAX_XREF_ROOTS = 200
SQLITE_ID_BATCH = 500


def _classifier(job: Path) -> pu_ownership.CodeOwnershipClassifier:
    return pu_ownership.CodeOwnershipClassifier.for_job(job)


def _annotated_method(
    row: sqlite3.Row,
    classifier: pu_ownership.CodeOwnershipClassifier,
) -> dict[str, Any]:
    value = pu_index.method_row(row)
    value["ownership"] = classifier.classify(
        value["class"], external=bool(value.get("external"))
    )
    return value


def _scope_match(
    classifier: pu_ownership.CodeOwnershipClassifier,
    class_name: str,
    external: bool,
    scope: str,
) -> tuple[bool, dict[str, Any]]:
    decision = classifier.classify(class_name, external=external)
    return pu_ownership.scope_accepts(decision, scope), decision


def _matching_rows(
    conn: sqlite3.Connection,
    query: str,
):
    return conn.execute(
        "SELECT * FROM methods "
        "WHERE instr(lower(class||' '||name||' '||descriptor||' '||id), ?) > 0 "
        "ORDER BY external,class,name,id",
        (query.lower(),),
    )


def find_symbols(
    job: Path,
    workspace: Path,
    caps: dict[str, Any],
    query: str,
    *,
    scope: str = "application",
    limit: int = 100,
):
    if not query or len(query) > 512:
        raise ValueError("query must be 1..512 characters")
    scope = pu_ownership.validate_query_scope(scope)
    pu_index.ensure_index(job, workspace, caps)
    classifier = _classifier(job)
    cap = max(1, min(int(limit), 500))
    matches: list[dict[str, Any]] = []
    scanned = 0
    accepted = 0
    scan_truncated = False
    with pu_index.connect(job) as conn:
        for row in _matching_rows(conn, query):
            if scanned >= MAX_QUERY_SCAN:
                scan_truncated = True
                break
            scanned += 1
            allowed, _decision = _scope_match(
                classifier, row["class"], bool(row["external"]), scope
            )
            if not allowed:
                continue
            accepted += 1
            if len(matches) < cap:
                matches.append(_annotated_method(row, classifier))
        kind = pu_index.meta_get(conn, "analysis_kind")
    return {
        "job_id": job.name,
        "query": query,
        "scope": scope,
        "analysis_kind": kind,
        "matches": matches,
        "returned_count": len(matches),
        "matched_count": accepted,
        "scanned_count": scanned,
        "has_more": accepted > len(matches) or scan_truncated,
        "truncated": scan_truncated,
        "ownership_model": classifier.descriptor(),
    }


def _symbol_class(symbol_id: str) -> str:
    if "#" in symbol_id:
        return symbol_id.split("#", 1)[0]
    token = symbol_id.split(" ", 1)[0]
    return pu_index.normalize_class_descriptor(token)


def _method_lookup(conn: sqlite3.Connection, ids: set[str]) -> dict[str, sqlite3.Row]:
    result: dict[str, sqlite3.Row] = {}
    values = sorted(ids)
    for start in range(0, len(values), SQLITE_ID_BATCH):
        batch = values[start : start + SQLITE_ID_BATCH]
        if not batch:
            continue
        marks = ",".join("?" for _ in batch)
        for row in conn.execute(f"SELECT * FROM methods WHERE id IN ({marks})", batch):
            result[row["id"]] = row
    return result


def _endpoint_ownership(
    symbol_id: str,
    row: sqlite3.Row | None,
    classifier: pu_ownership.CodeOwnershipClassifier,
) -> dict[str, Any]:
    if row is not None:
        return classifier.classify(row["class"], external=bool(row["external"]))
    return classifier.classify(_symbol_class(symbol_id), external=True)


def find_xrefs(
    job: Path,
    workspace: Path,
    caps: dict[str, Any],
    query: str,
    *,
    direction: str = "both",
    scope: str = "application",
    limit: int = 200,
):
    if not query or len(query) > 512:
        raise ValueError("query must be 1..512 characters")
    if direction not in {"incoming", "outgoing", "both"}:
        raise ValueError("invalid direction")
    scope = pu_ownership.validate_query_scope(scope)
    pu_index.ensure_index(job, workspace, caps)
    classifier = _classifier(job)
    cap = max(1, min(int(limit), 1000))
    ids: list[str] = []
    scanned = 0
    roots_truncated = False
    with pu_index.connect(job) as conn:
        for row in _matching_rows(conn, query):
            if scanned >= MAX_QUERY_SCAN:
                roots_truncated = True
                break
            scanned += 1
            allowed, _decision = _scope_match(
                classifier, row["class"], bool(row["external"]), scope
            )
            if not allowed:
                continue
            if len(ids) < MAX_XREF_ROOTS:
                ids.append(row["id"])
            else:
                roots_truncated = True
                break

        raw_edges: list[sqlite3.Row] = []
        edge_has_more = False
        if ids:
            marks = ",".join("?" for _ in ids)
            if direction == "incoming":
                sql = (
                    f"SELECT * FROM call_edges WHERE callee IN ({marks}) "
                    "ORDER BY caller,callee,offset LIMIT ?"
                )
                params: list[Any] = [*ids, cap + 1]
            elif direction == "outgoing":
                sql = (
                    f"SELECT * FROM call_edges WHERE caller IN ({marks}) "
                    "ORDER BY caller,callee,offset LIMIT ?"
                )
                params = [*ids, cap + 1]
            else:
                sql = (
                    f"SELECT * FROM call_edges WHERE callee IN ({marks}) "
                    f"OR caller IN ({marks}) ORDER BY caller,callee,offset LIMIT ?"
                )
                params = [*ids, *ids, cap + 1]
            raw_edges = list(conn.execute(sql, params))
            if len(raw_edges) > cap:
                edge_has_more = True
                raw_edges = raw_edges[:cap]

        endpoint_ids = {
            value
            for row in raw_edges
            for value in (row["caller"], row["callee"])
        }
        lookup = _method_lookup(conn, endpoint_ids)
        edges: list[dict[str, Any]] = []
        boundary_count = 0
        application_scopes = {"FIRST_PARTY", "UNKNOWN"}
        for row in raw_edges:
            caller = row["caller"]
            callee = row["callee"]
            from_ownership = _endpoint_ownership(caller, lookup.get(caller), classifier)
            to_ownership = _endpoint_ownership(callee, lookup.get(callee), classifier)
            boundary = (
                (from_ownership["scope"] in application_scopes)
                != (to_ownership["scope"] in application_scopes)
            )
            if boundary:
                boundary_count += 1
            edges.append(
                {
                    "from": caller,
                    "to": callee,
                    "offset": row["offset"],
                    "confidence": row["confidence"],
                    "kind": row["kind"],
                    "from_ownership": from_ownership,
                    "to_ownership": to_ownership,
                    "boundary": boundary,
                }
            )
        kind = pu_index.meta_get(conn, "analysis_kind")
    return {
        "job_id": job.name,
        "query": query,
        "direction": direction,
        "scope": scope,
        "matched_symbols": ids,
        "matched_symbol_count": len(ids),
        "matched_symbols_truncated": roots_truncated,
        "xrefs": edges,
        "boundary_edge_count": boundary_count,
        "has_more": edge_has_more or roots_truncated,
        "analysis_kind": kind,
        "ownership_model": classifier.descriptor(),
    }


def get_cfg(
    job: Path,
    workspace: Path,
    query: str,
    *,
    scope: str = "application",
    max_blocks: int = 500,
):
    if not query or len(query) > 512:
        raise ValueError("query must be 1..512 characters")
    scope = pu_ownership.validate_query_scope(scope)
    input_artifact = pu_index.artifact(job, workspace)
    classifier = _classifier(job)
    remaining = max(1, min(int(max_blocks), 10_000))
    needle = query.lower()
    matches: list[dict[str, Any]] = []
    method_scan_count = 0
    method_scan_truncated = False
    with pu_index.androguard_analysis(input_artifact) as (analysis, class_members):
        for method in analysis.get_methods():
            if method_scan_count >= MAX_QUERY_SCAN:
                method_scan_truncated = True
                break
            method_scan_count += 1
            record = pu_index.method_record(method, class_members)
            haystack = (
                f"{record['class']} {record['name']} "
                f"{record['descriptor']} {record['id']}"
            ).lower()
            if needle not in haystack:
                continue
            if hasattr(method, "is_external") and method.is_external():
                continue
            decision = classifier.classify(record["class"], external=False)
            if not pu_ownership.scope_accepts(decision, scope):
                continue
            blocks = []
            for block in method.get_basic_blocks():
                if remaining <= 0:
                    break
                successors = []
                for child in block.get_next():
                    target = child[-1] if isinstance(child, (tuple, list)) and child else child
                    try:
                        successors.append(int(target.get_start()))
                    except Exception:
                        pass
                blocks.append(
                    {
                        "start": int(block.get_start()),
                        "end": int(block.get_end()),
                        "name": str(block.get_name()),
                        "successors": successors,
                    }
                )
                remaining -= 1
            record["ownership"] = decision
            matches.append(
                {
                    "method": record,
                    "blocks": blocks,
                    "truncated": remaining <= 0,
                }
            )
            if remaining <= 0 or len(matches) >= 20:
                break
    block_truncated = remaining <= 0
    return {
        "job_id": job.name,
        "query": query,
        "scope": scope,
        "matches": matches,
        "analyzer": "androguard",
        "confidence": 0.98,
        "method_scan_count": method_scan_count,
        "method_scan_truncated": method_scan_truncated,
        "has_more": method_scan_truncated or block_truncated or len(matches) >= 20,
        "truncated": method_scan_truncated or block_truncated,
        "ownership_model": classifier.descriptor(),
    }
