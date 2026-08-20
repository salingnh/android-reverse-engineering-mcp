from __future__ import annotations

from collections import defaultdict
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

import pu_index

MAX_DEPTH = 32
MAX_PATHS = 50
MAX_VISITED_NODES = 200_000
MAX_SCANNED_EDGES = 500_000
MAX_CANDIDATES = 200
SQL_BATCH = 400


@contextmanager
def _connection(job: Path):
    conn = pu_index.connect(job)
    try:
        yield conn
    finally:
        conn.close()


def _chunks(values: list[str], size: int = SQL_BATCH) -> Iterable[list[str]]:
    for index in range(0, len(values), size):
        yield values[index:index + size]


def _query(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 512:
        raise ValueError(f"{label} must be 1..512 characters")
    return text


def _candidate_rows(conn, query: str) -> tuple[list[Any], bool]:
    exact = conn.execute("SELECT * FROM methods WHERE id=? LIMIT 1", (query,)).fetchall()
    if exact:
        return exact, False
    rows = conn.execute(
        "SELECT * FROM methods "
        "WHERE instr(lower(class||' '||name||' '||descriptor||' '||id), ?) > 0 "
        "ORDER BY external,class,name,descriptor,id LIMIT ?",
        (query.lower(), MAX_CANDIDATES + 1),
    ).fetchall()
    return rows[:MAX_CANDIDATES], len(rows) > MAX_CANDIDATES


def _resolution(rows: list[Any], truncated: bool) -> dict[str, Any]:
    if not rows:
        status = "unresolved"
    elif len(rows) == 1 and not truncated:
        status = "resolved"
    else:
        status = "candidate-set"
    return {
        "status": status,
        "candidate_count": len(rows),
        "truncated": truncated,
        "candidates": [pu_index.method_row(row) for row in rows],
    }


def _index_truncation_reasons(index_truncated: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if index_truncated.get("methods"):
        reasons.append("index_methods_truncated")
    if index_truncated.get("edges"):
        reasons.append("index_edges_truncated")
    return reasons


def _edge_dict(row: Any, direction: str) -> dict[str, Any]:
    caller = row["caller"]
    callee = row["callee"]
    traversal_from, traversal_to = (caller, callee) if direction == "forward" else (callee, caller)
    return {
        "traversal_from": traversal_from,
        "traversal_to": traversal_to,
        "caller": caller,
        "callee": callee,
        "offset": int(row["offset"]),
        "confidence": float(row["confidence"]),
        "kind": row["kind"],
    }


def _frontier_edges(conn, frontier: list[str], direction: str, budget: int) -> tuple[list[Any], bool]:
    field = "caller" if direction == "forward" else "callee"
    output: list[Any] = []
    chunks = list(_chunks(sorted(frontier)))
    for chunk in chunks:
        remaining = budget - len(output)
        marks = ",".join("?" for _ in chunk)
        if remaining <= 0:
            probe = conn.execute(
                f"SELECT 1 FROM call_edges WHERE {field} IN ({marks}) LIMIT 1",
                chunk,
            ).fetchone()
            if probe is not None:
                return output, True
            continue
        sql = (
            f"SELECT caller,callee,offset,confidence,kind FROM call_edges "
            f"WHERE {field} IN ({marks}) "
            "ORDER BY caller,callee,offset,kind,confidence LIMIT ?"
        )
        rows = conn.execute(sql, [*chunk, remaining + 1]).fetchall()
        if len(rows) > remaining:
            output.extend(rows[:remaining])
            return output, True
        output.extend(rows)
    return output, False


def _load_methods(conn, ids: set[str]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    values = sorted(ids)
    for chunk in _chunks(values):
        marks = ",".join("?" for _ in chunk)
        for row in conn.execute(f"SELECT * FROM methods WHERE id IN ({marks})", chunk):
            output[row["id"]] = pu_index.method_row(row)
    for symbol_id in values:
        output.setdefault(symbol_id, {"id": symbol_id, "external": None, "source": {}})
    return output


def _enumerate_paths(
    target_ids: list[str],
    source_ids: set[str],
    parents: dict[str, list[tuple[str, dict[str, Any]]]],
    max_paths: int,
) -> tuple[list[tuple[list[str], list[dict[str, Any]]]], bool]:
    output: list[tuple[list[str], list[dict[str, Any]]]] = []
    seen: set[tuple[tuple[str, ...], tuple[tuple[Any, ...], ...]]] = set()
    hard_limit = max_paths + 1

    def walk(node: str, reversed_nodes: list[str], reversed_edges: list[dict[str, Any]]) -> None:
        if len(output) >= hard_limit:
            return
        if node in source_ids:
            nodes = list(reversed(reversed_nodes))
            edges = list(reversed(reversed_edges))
            edge_key = tuple(
                (edge["caller"], edge["callee"], edge["offset"], edge["kind"])
                for edge in edges
            )
            key = (tuple(nodes), edge_key)
            if key not in seen:
                seen.add(key)
                output.append((nodes, edges))
            return
        for previous, edge in sorted(
            parents.get(node, []),
            key=lambda item: (
                item[0], item[1]["caller"], item[1]["callee"], item[1]["offset"], item[1]["kind"]
            ),
        ):
            walk(previous, [*reversed_nodes, previous], [*reversed_edges, edge])
            if len(output) >= hard_limit:
                return

    for target in sorted(target_ids):
        walk(target, [target], [])
        if len(output) >= hard_limit:
            break
    return output[:max_paths], len(output) > max_paths


def trace_call_path(
    job: Path,
    workspace: Path,
    caps: dict[str, Any],
    source: str,
    target: str,
    *,
    direction: str = "forward",
    max_depth: int = 12,
    max_paths: int = 20,
    max_visited_nodes: int = 50_000,
    max_scanned_edges: int = 200_000,
) -> dict[str, Any]:
    source = _query(source, "source")
    target = _query(target, "target")
    if direction not in {"forward", "reverse"}:
        raise ValueError("direction must be forward or reverse")
    max_depth = max(1, min(int(max_depth), MAX_DEPTH))
    max_paths = max(1, min(int(max_paths), MAX_PATHS))
    max_visited_nodes = max(MAX_CANDIDATES, min(int(max_visited_nodes), MAX_VISITED_NODES))
    max_scanned_edges = max(100, min(int(max_scanned_edges), MAX_SCANNED_EDGES))

    pu_index.ensure_index(job, workspace, caps)
    with _connection(job) as conn:
        analysis_kind = pu_index.meta_get(conn, "analysis_kind")
        index_truncated = pu_index.meta_get(conn, "truncated", {}) or {}
        source_rows, source_truncated = _candidate_rows(conn, source)
        target_rows, target_truncated = _candidate_rows(conn, target)
        source_resolution = _resolution(source_rows, source_truncated)
        target_resolution = _resolution(target_rows, target_truncated)
        base = {
            "schema_version": 1,
            "job_id": job.name,
            "analysis_kind": analysis_kind,
            "direction": direction,
            "source_query": source,
            "target_query": target,
            "source_resolution": source_resolution,
            "target_resolution": target_resolution,
            "index_truncated": index_truncated,
        }
        initial_truncation_reasons = _index_truncation_reasons(index_truncated)
        if source_truncated:
            initial_truncation_reasons.append("source_candidates_truncated")
        if target_truncated:
            initial_truncation_reasons.append("target_candidates_truncated")

        if analysis_kind != "dex-xref":
            return {
                **base,
                "available": False,
                "unavailable_reason": "program_index_has_no_dex_xref_graph",
                "found": False,
                "shortest_depth": None,
                "paths": [],
                "truncated": bool(initial_truncation_reasons),
                "truncation_reasons": initial_truncation_reasons,
                "resolution_reasons": [],
                "search_complete": False,
                "stats": {"visited_nodes": 0, "scanned_edges": 0, "expanded_depth": 0},
                "notes": ["Call-path traversal requires a DEX XREF index; source fallback does not claim call edges."],
            }
        if not source_rows or not target_rows:
            resolution_reasons = []
            if not source_rows:
                resolution_reasons.append("source_unresolved")
            if not target_rows:
                resolution_reasons.append("target_unresolved")
            return {
                **base,
                "available": True,
                "unavailable_reason": None,
                "found": False,
                "shortest_depth": None,
                "paths": [],
                "truncated": bool(initial_truncation_reasons),
                "truncation_reasons": initial_truncation_reasons,
                "resolution_reasons": resolution_reasons,
                "search_complete": False,
                "stats": {"visited_nodes": 0, "scanned_edges": 0, "expanded_depth": 0},
                "notes": ["No traversal is attempted until both endpoint queries resolve to at least one exact symbol candidate."],
            }

        source_ids = {row["id"] for row in source_rows}
        target_ids = {row["id"] for row in target_rows}
        overlap = sorted(source_ids & target_ids)
        parents: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
        parent_keys: dict[str, set[tuple[Any, ...]]] = defaultdict(set)
        distance = {symbol_id: 0 for symbol_id in source_ids}
        scanned_edges = 0
        expanded_depth = 0
        budget_reason: str | None = None
        found_depth: int | None = 0 if overlap else None
        found_targets: list[str] = overlap
        frontier = sorted(source_ids)

        if found_depth is None:
            for depth in range(max_depth):
                if not frontier:
                    break
                expanded_depth = depth + 1
                next_frontier: set[str] = set()
                rows, overflow = _frontier_edges(
                    conn, frontier, direction, max_scanned_edges - scanned_edges
                )
                scanned_edges += len(rows)
                for row in rows:
                    edge = _edge_dict(row, direction)
                    current = edge["traversal_from"]
                    neighbour = edge["traversal_to"]
                    if current not in distance or distance[current] != depth:
                        continue
                    existing_depth = distance.get(neighbour)
                    if existing_depth is None:
                        if len(distance) >= max_visited_nodes:
                            budget_reason = "node_budget"
                            break
                        distance[neighbour] = depth + 1
                        next_frontier.add(neighbour)
                    if distance.get(neighbour) == depth + 1:
                        key = (current, edge["caller"], edge["callee"], edge["offset"], edge["kind"])
                        if key not in parent_keys[neighbour]:
                            parent_keys[neighbour].add(key)
                            parents[neighbour].append((current, edge))
                layer_targets = sorted(target_ids & next_frontier)
                if layer_targets:
                    found_depth = depth + 1
                    found_targets = layer_targets
                    if overflow:
                        budget_reason = "edge_budget"
                    break
                if budget_reason == "node_budget":
                    break
                if overflow:
                    budget_reason = "edge_budget"
                    break
                frontier = sorted(next_frontier)
            if found_depth is None and budget_reason is None and frontier and expanded_depth >= max_depth:
                budget_reason = "depth_limit"

        raw_paths, path_overflow = (
            _enumerate_paths(found_targets, source_ids, parents, max_paths)
            if found_depth is not None else ([], False)
        )
        node_ids: set[str] = set()
        for nodes, _ in raw_paths:
            node_ids.update(nodes)
        methods = _load_methods(conn, node_ids)
        paths = [
            {"depth": len(edges), "nodes": [methods[node] for node in nodes], "edges": edges}
            for nodes, edges in raw_paths
        ]
        reasons: list[str] = [*initial_truncation_reasons]
        if budget_reason:
            reasons.append(budget_reason)
        if path_overflow:
            reasons.append("path_limit")
        reasons = list(dict.fromkeys(reasons))
        return {
            **base,
            "available": True,
            "unavailable_reason": None,
            "found": bool(paths),
            "shortest_depth": found_depth,
            "paths": paths,
            "truncated": bool(reasons),
            "truncation_reasons": reasons,
            "resolution_reasons": [],
            "search_complete": not reasons,
            "stats": {
                "visited_nodes": len(distance), "scanned_edges": scanned_edges, "expanded_depth": expanded_depth,
                "max_depth": max_depth, "max_paths": max_paths,
                "max_visited_nodes": max_visited_nodes, "max_scanned_edges": max_scanned_edges,
            },
            "notes": [
                "Paths contain exact symbol IDs; broad endpoint queries remain explicit candidate sets and are never merged into synthetic methods.",
                "Only shortest paths within the current XREF index are returned.",
                "A missing path is conclusive only when candidate/index/search truncation is false.",
                "CALL/XREF adjacency is not data-flow evidence.",
            ],
        }
