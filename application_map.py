from __future__ import annotations

import json
import time
from typing import Any, Iterable

import program_model as pm
from ownership_contract import validate_ownership_scope

APPLICATION_MAP_VERSION = 1
DEFAULT_NODE_LIMIT = 40
DEFAULT_EDGE_LIMIT = 100
MAX_NODE_LIMIT = 80
MAX_EDGE_LIMIT = 200
MAX_ENTITY_SCAN = 1200
MAX_QUERY_PAGES = 12
MAX_RELATIONSHIP_ROOTS = 16
MAX_RELATIONSHIPS_PER_ROOT = 80
MAX_EVIDENCE_REFS = 8
MAX_RESPONSE_BYTES = 64 * 1024
MAX_WALL_CLOCK_SECONDS = 10

_KIND_SCORE = {
    "APPLICATION": 10_000,
    "ENDPOINT": 9_000,
    "STORAGE": 8_500,
    "FEATURE": 8_000,
    "COMPONENT": 7_500,
    "MODULE": 7_000,
    "CLASS": 6_000,
    "FUNCTION": 5_000,
    "EXTERNAL_BOUNDARY": 8_800,
    "VALUE": 2_000,
    "EVIDENCE": 1_000,
}

_NAME_HINTS = (
    "main",
    "login",
    "auth",
    "token",
    "session",
    "request",
    "api",
    "client",
    "service",
    "repository",
    "controller",
    "activity",
    "fragment",
    "endpoint",
    "storage",
)

_ROLE_BY_KIND = {
    "APPLICATION": "application-root",
    "MODULE": "module",
    "FEATURE": "feature",
    "COMPONENT": "component",
    "CLASS": "component",
    "FUNCTION": "important-function",
    "ENDPOINT": "endpoint",
    "STORAGE": "storage",
    "EXTERNAL_BOUNDARY": "external-boundary",
    "VALUE": "value",
    "EVIDENCE": "evidence",
}


class ApplicationMapError(ValueError):
    pass


def _bounded_limit(value: Any, default: int, maximum: int, field: str) -> int:
    try:
        parsed = int(default if value is None else value)
    except (TypeError, ValueError) as exc:
        raise ApplicationMapError(f"{field} must be an integer") from exc
    if parsed < 1:
        raise ApplicationMapError(f"{field} must be positive")
    return min(parsed, maximum)


def _importance(item: pm.ProgramEntity) -> int:
    score = _KIND_SCORE.get(item.kind, 0)
    if item.ownership == "FIRST_PARTY":
        score += 500
    elif item.ownership == "UNKNOWN":
        score += 250
    name = (item.display_name + " " + item.semantic_key).lower()
    score += sum(50 for hint in _NAME_HINTS if hint in name)
    if item.kind == "EXTERNAL_BOUNDARY":
        score += 400
    return score


def _rank_key(item: pm.ProgramEntity) -> tuple[int, str, str]:
    return (-_importance(item), item.display_name.lower(), item.entity_id)


def _node(item: pm.ProgramEntity) -> dict[str, Any]:
    return {
        "entity_id": item.entity_id,
        "kind": item.kind,
        "display_name": item.display_name,
        "ownership": item.ownership,
        "representation": item.representation,
        "map_role": _ROLE_BY_KIND.get(item.kind, "semantic-node"),
        "importance": _importance(item),
        "expandable": item.kind != "EVIDENCE",
        "collapsed": item.kind == "EXTERNAL_BOUNDARY",
        "properties": dict(item.properties),
        "evidence_refs": list(item.evidence_refs[:MAX_EVIDENCE_REFS]),
    }


def _edge(item: pm.ProgramRelationship) -> dict[str, Any]:
    return {
        "relationship_id": item.relationship_id,
        "kind": item.kind,
        "source_entity_id": item.source_entity_id,
        "target_entity_id": item.target_entity_id,
        "collapsed": item.kind in {"CALLS_EXTERNAL"},
        "evidence_refs": list(item.evidence_refs[:MAX_EVIDENCE_REFS]),
    }


def _payload_size(payload: dict[str, Any]) -> int:
    try:
        return len(
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        )
    except (TypeError, ValueError) as exc:
        raise ApplicationMapError("application map is not canonical JSON") from exc


def _response_candidate(
    payload: dict[str, Any],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    *,
    trimmed: bool,
) -> dict[str, Any]:
    result = {**payload, "nodes": nodes, "edges": edges}
    result["returned_nodes"] = len(nodes)
    result["returned_edges"] = len(edges)
    warnings = list(payload.get("warnings") or [])
    if trimmed:
        result["truncated"] = True
        result["has_more"] = True
        if "response_size_budget_reached" not in warnings:
            warnings.append("response_size_budget_reached")
    result["warnings"] = warnings
    # Reserve the full five-digit budget value while deciding fit so adding the
    # final serialized byte count can never push a previously fitting response over.
    result["serialized_bytes"] = MAX_RESPONSE_BYTES
    return result


def _fit_response(payload: dict[str, Any]) -> dict[str, Any]:
    nodes = list(payload.get("nodes") or [])
    edges = list(payload.get("edges") or [])
    trimmed = False
    while True:
        result = _response_candidate(payload, nodes, edges, trimmed=trimmed)
        if _payload_size(result) <= MAX_RESPONSE_BYTES:
            break
        if edges:
            edges.pop()
            trimmed = True
            continue
        if len(nodes) > 1:
            removed = nodes.pop()
            removed_id = removed.get("entity_id")
            edges = [
                edge
                for edge in edges
                if removed_id
                not in {edge.get("source_entity_id"), edge.get("target_entity_id")}
            ]
            trimmed = True
            continue
        raise ApplicationMapError("application map minimum response exceeds size bound")
    # The reserved value above has the maximum digit width of any valid final
    # byte count. Two iterations make the reported count equal the serialized form.
    for _ in range(2):
        result["serialized_bytes"] = _payload_size(result)
    if _payload_size(result) > MAX_RESPONSE_BYTES:
        raise ApplicationMapError("application map final response exceeds size bound")
    return result


class ApplicationMapProjector:
    def __init__(self, repository: pm.ProgramRepository) -> None:
        self.repository = repository

    def _scan_kind(
        self,
        kind: str,
        ownership_scope: str,
        *,
        maximum: int,
        started: float,
    ) -> tuple[list[pm.ProgramEntity], bool]:
        items: list[pm.ProgramEntity] = []
        cursor: str | None = None
        truncated = False
        pages = 0
        while len(items) < maximum and pages < MAX_QUERY_PAGES:
            if time.monotonic() - started >= MAX_WALL_CLOCK_SECONDS:
                return items, True
            page = self.repository.find_entities(
                kind=kind,
                ownership_scope=ownership_scope,
                limit=min(pm.MAX_PAGE_SIZE, maximum - len(items)),
                cursor=cursor,
            )
            items.extend(page.items)
            pages += 1
            truncated = truncated or page.truncated
            if not page.has_more:
                break
            if not page.cursor:
                truncated = True
                break
            cursor = page.cursor
        if pages >= MAX_QUERY_PAGES and len(items) >= maximum:
            truncated = True
        return items[:maximum], truncated

    def get_application_map(
        self,
        *,
        ownership_scope: str = "application",
        node_limit: int = DEFAULT_NODE_LIMIT,
        edge_limit: int = DEFAULT_EDGE_LIMIT,
    ) -> dict[str, Any]:
        scope = validate_ownership_scope(ownership_scope)
        node_limit = _bounded_limit(
            node_limit, DEFAULT_NODE_LIMIT, MAX_NODE_LIMIT, "node_limit"
        )
        edge_limit = _bounded_limit(
            edge_limit, DEFAULT_EDGE_LIMIT, MAX_EDGE_LIMIT, "edge_limit"
        )
        started = time.monotonic()
        candidates: dict[str, pm.ProgramEntity] = {}
        truncated = False

        scan_plan = (
            ("APPLICATION", 4),
            ("ENDPOINT", 100),
            ("STORAGE", 100),
            ("FEATURE", 100),
            ("COMPONENT", 150),
            ("MODULE", 150),
            ("CLASS", 300),
            ("FUNCTION", 500),
        )
        remaining_scan = MAX_ENTITY_SCAN
        for kind, requested in scan_plan:
            if remaining_scan <= 0:
                truncated = True
                break
            batch, hit_bound = self._scan_kind(
                kind,
                scope,
                maximum=min(requested, remaining_scan),
                started=started,
            )
            for item in batch:
                candidates[item.entity_id] = item
            remaining_scan -= len(batch)
            truncated = truncated or hit_bound
            if time.monotonic() - started >= MAX_WALL_CLOCK_SECONDS:
                truncated = True
                break

        ordered = sorted(candidates.values(), key=_rank_key)
        reserve = min(8, max(0, node_limit // 5))
        selected = ordered[: max(1, node_limit - reserve)]
        selected_ids = {item.entity_id for item in selected}
        app_ids = {item.entity_id for item in selected if item.kind == "APPLICATION"}
        relationships: dict[str, pm.ProgramRelationship] = {}
        discovered: dict[str, pm.ProgramEntity] = {}

        relation_roots = sorted(
            selected,
            key=lambda item: (
                0 if item.entity_id in app_ids else 1,
                _rank_key(item),
            ),
        )[:MAX_RELATIONSHIP_ROOTS]

        for root in relation_roots:
            if time.monotonic() - started >= MAX_WALL_CLOCK_SECONDS:
                truncated = True
                break
            page = self.repository.find_relationships(
                entity_id=root.entity_id,
                direction="both",
                ownership_scope=scope,
                limit=min(MAX_RELATIONSHIPS_PER_ROOT, edge_limit),
            )
            truncated = truncated or page.truncated or page.has_more
            for relation in page.items:
                relationships[relation.relationship_id] = relation
                neighbor_id = (
                    relation.target_entity_id
                    if relation.source_entity_id == root.entity_id
                    else relation.source_entity_id
                )
                if neighbor_id in selected_ids or neighbor_id in discovered:
                    continue
                neighbor = self.repository.get_entity(neighbor_id)
                if neighbor is None:
                    continue
                if neighbor.kind == "EXTERNAL_BOUNDARY":
                    discovered[neighbor.entity_id] = neighbor

        for item in sorted(discovered.values(), key=_rank_key):
            if len(selected) >= node_limit:
                truncated = True
                break
            selected.append(item)
            selected_ids.add(item.entity_id)

        visible_edges = [
            relation
            for relation in relationships.values()
            if relation.source_entity_id in selected_ids
            and relation.target_entity_id in selected_ids
        ]
        visible_edges.sort(key=pm.relationship_sort_key)
        if len(visible_edges) > edge_limit:
            visible_edges = visible_edges[:edge_limit]
            truncated = True

        payload = {
            "status": "ok",
            "application_map_version": APPLICATION_MAP_VERSION,
            "program_model_version": pm.PROGRAM_MODEL_VERSION,
            "snapshot_id": self.repository.snapshot.snapshot_id,
            "artifact_sha256": self.repository.snapshot.artifact_sha256,
            "ownership_scope": scope,
            "nodes": [_node(item) for item in selected],
            "edges": [_edge(item) for item in visible_edges],
            "returned_nodes": len(selected),
            "returned_edges": len(visible_edges),
            "has_more": truncated or len(ordered) > len(selected),
            "truncated": truncated or len(ordered) > len(selected),
            "cursor": None,
            "projection_version": APPLICATION_MAP_VERSION,
            "limits": {
                "node_limit": node_limit,
                "edge_limit": edge_limit,
                "entity_scan": MAX_ENTITY_SCAN,
                "relationship_roots": MAX_RELATIONSHIP_ROOTS,
                "relationships_per_root": MAX_RELATIONSHIPS_PER_ROOT,
                "wall_clock_seconds": MAX_WALL_CLOCK_SECONDS,
                "response_bytes": MAX_RESPONSE_BYTES,
            },
            "warnings": [],
        }
        return _fit_response(payload)

    def expand_application_node(
        self,
        *,
        entity_id: str,
        ownership_scope: str = "application",
        direction: str = "both",
        relationship_kinds: Iterable[str] | None = None,
        node_limit: int = 40,
        edge_limit: int = 100,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        scope = validate_ownership_scope(ownership_scope)
        node_limit = _bounded_limit(node_limit, 40, MAX_NODE_LIMIT, "node_limit")
        edge_limit = _bounded_limit(edge_limit, 100, MAX_EDGE_LIMIT, "edge_limit")
        root = self.repository.get_entity(str(entity_id or ""))
        if root is None:
            raise ApplicationMapError(
                "application map entity was not found in this Program Snapshot"
            )
        page = self.repository.find_relationships(
            entity_id=root.entity_id,
            kinds=relationship_kinds,
            direction=direction,
            ownership_scope=scope,
            limit=edge_limit,
            cursor=cursor,
        )
        nodes: dict[str, pm.ProgramEntity] = {root.entity_id: root}
        edges: list[pm.ProgramRelationship] = []
        truncated = page.truncated
        for relation in page.items:
            if len(edges) >= edge_limit:
                truncated = True
                break
            other_id = (
                relation.target_entity_id
                if relation.source_entity_id == root.entity_id
                else relation.source_entity_id
            )
            if other_id not in nodes:
                if len(nodes) >= node_limit:
                    truncated = True
                    continue
                item = self.repository.get_entity(other_id)
                if item is None:
                    continue
                nodes[item.entity_id] = item
            edges.append(relation)

        ordered_nodes = [root] + sorted(
            (item for key, item in nodes.items() if key != root.entity_id),
            key=_rank_key,
        )
        edges.sort(key=pm.relationship_sort_key)
        payload = {
            "status": "ok",
            "application_map_version": APPLICATION_MAP_VERSION,
            "program_model_version": pm.PROGRAM_MODEL_VERSION,
            "snapshot_id": self.repository.snapshot.snapshot_id,
            "artifact_sha256": self.repository.snapshot.artifact_sha256,
            "ownership_scope": scope,
            "root_entity_id": root.entity_id,
            "nodes": [_node(item) for item in ordered_nodes[:node_limit]],
            "edges": [_edge(item) for item in edges[:edge_limit]],
            "returned_nodes": min(len(ordered_nodes), node_limit),
            "returned_edges": min(len(edges), edge_limit),
            "has_more": page.has_more or truncated,
            "truncated": truncated,
            "cursor": page.cursor,
            "projection_version": APPLICATION_MAP_VERSION,
            "limits": {
                "node_limit": node_limit,
                "edge_limit": edge_limit,
                "wall_clock_seconds": pm.MAX_QUERY_SECONDS,
                "response_bytes": MAX_RESPONSE_BYTES,
            },
            "warnings": [],
        }
        return _fit_response(payload)


def descriptor() -> dict[str, Any]:
    return {
        "application_map_version": APPLICATION_MAP_VERSION,
        "program_model_version": pm.PROGRAM_MODEL_VERSION,
        "projection_only": True,
        "persistent_map_storage": False,
        "llm_required": False,
        "canonical_entity_ids_reused": True,
        "default_node_limit": DEFAULT_NODE_LIMIT,
        "default_edge_limit": DEFAULT_EDGE_LIMIT,
        "max_node_limit": MAX_NODE_LIMIT,
        "max_edge_limit": MAX_EDGE_LIMIT,
        "max_response_bytes": MAX_RESPONSE_BYTES,
    }
