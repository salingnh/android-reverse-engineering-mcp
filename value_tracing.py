from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

import flow_ir as flow

VALUE_TRACING_VERSION = 1
MAX_TRACE_DEPTH = 32
MAX_TRACE_NODES = 500
MAX_TRACE_PATHS = 100
MAX_TRACE_STATES = 10_000
SELECTOR_KINDS = ("parameter", "return", "field", "node")


class ValueTracingError(ValueError):
    pass


def _bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueTracingError(f"invalid {name}") from exc
    if result < minimum or result > maximum:
        raise ValueTracingError(f"invalid {name}")
    return result


def _selector_nodes(
    document: flow.FlowDocument,
    owner_entity_id: str,
    selector: dict[str, Any],
) -> tuple[flow.FlowNode, ...]:
    if not isinstance(selector, dict):
        raise ValueTracingError("selector must be an object")
    kind = str(selector.get("kind") or "").strip().lower()
    if kind not in SELECTOR_KINDS:
        raise ValueTracingError(f"unsupported selector kind: {kind or '<empty>'}")
    owner = str(owner_entity_id or "").strip()
    if not owner:
        raise ValueTracingError("owner_entity_id must be non-empty")

    if kind == "node":
        node_id = str(selector.get("node_id") or "").strip()
        if not node_id or len(node_id) > 256:
            raise ValueTracingError("invalid selector node_id")
        return tuple(item for item in document.nodes if item.node_id == node_id)

    candidates = [item for item in document.nodes if item.owner_entity_id == owner]
    if kind == "parameter":
        index = _bounded_int(selector.get("index"), "parameter index", 0, 1024)
        return tuple(
            item
            for item in candidates
            if item.value_kind == "PARAMETER"
            and item.properties.get("parameter_index") == index
        )
    if kind == "return":
        return tuple(item for item in candidates if item.value_kind == "RETURN")

    name = str(selector.get("name") or "").strip()
    if not name or len(name) > 512:
        raise ValueTracingError("invalid field selector name")
    needle = name.lower()
    return tuple(
        item
        for item in document.nodes
        if item.value_kind == "FIELD"
        and (
            needle in str(item.properties.get("field_name") or "").lower()
            or needle in item.semantic_key.lower()
        )
    )


def _index_edges(document: flow.FlowDocument):
    outgoing: dict[str, list[flow.FlowEdge]] = defaultdict(list)
    incoming: dict[str, list[flow.FlowEdge]] = defaultdict(list)
    for edge in document.edges:
        outgoing[edge.source_node_id].append(edge)
        incoming[edge.target_node_id].append(edge)
    for values in outgoing.values():
        values.sort(key=lambda item: item.edge_id)
    for values in incoming.values():
        values.sort(key=lambda item: item.edge_id)
    return outgoing, incoming


def _gap_subset(
    document: flow.FlowDocument,
    selected: set[str],
    nodes: dict[str, flow.FlowNode],
    *,
    max_nodes: int,
) -> tuple[list[flow.FlowGap], bool]:
    result: list[flow.FlowGap] = []
    truncated = False
    for gap in sorted(document.gaps, key=lambda item: item.gap_id):
        endpoints = {item for item in (gap.source_node_id, gap.target_node_id) if item}
        if not endpoints.intersection(selected):
            continue
        missing = [node_id for node_id in endpoints if node_id not in selected]
        if missing:
            if len(selected) + len(missing) > max_nodes:
                truncated = True
                continue
            for node_id in missing:
                if node_id in nodes:
                    selected.add(node_id)
        result.append(gap)
    return result, truncated


def _subdocument(
    document: flow.FlowDocument,
    selected_nodes: set[str],
    selected_edges: set[str],
    gaps: list[flow.FlowGap],
    paths: tuple[flow.FlowPath, ...] = (),
) -> flow.FlowDocument:
    nodes = tuple(item for item in document.nodes if item.node_id in selected_nodes)
    edges = tuple(item for item in document.edges if item.edge_id in selected_edges)
    return flow.FlowDocument(
        snapshot_id=document.snapshot_id,
        nodes=nodes,
        edges=edges,
        gaps=tuple(gaps),
        paths=paths,
    )


def trace_value(
    document: flow.FlowDocument,
    *,
    owner_entity_id: str,
    selector: dict[str, Any],
    direction: str = "both",
    max_depth: int = 8,
    max_nodes: int = 160,
) -> dict[str, Any]:
    direction = str(direction or "both").strip().lower()
    if direction not in {"forward", "backward", "both"}:
        raise ValueTracingError("direction must be forward, backward, or both")
    depth_limit = _bounded_int(max_depth, "max_depth", 0, MAX_TRACE_DEPTH)
    node_limit = _bounded_int(max_nodes, "max_nodes", 1, MAX_TRACE_NODES)
    seeds = _selector_nodes(document, owner_entity_id, selector)
    if not seeds:
        raise ValueTracingError("semantic seed did not resolve to a FlowNode")

    nodes = {item.node_id: item for item in document.nodes}
    outgoing, incoming = _index_edges(document)
    selected = {item.node_id for item in seeds}
    queue = deque((item.node_id, 0) for item in sorted(seeds, key=lambda item: item.node_id))
    edge_ids: set[str] = set()
    truncated = False

    while queue:
        node_id, depth = queue.popleft()
        if depth >= depth_limit:
            continue
        choices: list[tuple[flow.FlowEdge, str]] = []
        if direction in {"forward", "both"}:
            choices.extend((edge, edge.target_node_id) for edge in outgoing.get(node_id, ()))
        if direction in {"backward", "both"}:
            choices.extend((edge, edge.source_node_id) for edge in incoming.get(node_id, ()))
        choices.sort(key=lambda item: (item[0].edge_id, item[1]))
        for edge, neighbor in choices:
            if neighbor not in selected:
                if len(selected) >= node_limit:
                    truncated = True
                    continue
                selected.add(neighbor)
                queue.append((neighbor, depth + 1))
            edge_ids.add(edge.edge_id)

    gaps, gap_truncated = _gap_subset(document, selected, nodes, max_nodes=node_limit)
    truncated = truncated or gap_truncated
    result = _subdocument(document, selected, edge_ids, gaps)
    return {
        "value_tracing_version": VALUE_TRACING_VERSION,
        "operation": "trace_value",
        "seed_node_ids": [item.node_id for item in sorted(seeds, key=lambda item: item.node_id)],
        "direction": direction,
        "max_depth": depth_limit,
        "truncated": truncated,
        "flow": result.to_dict(),
    }


def find_source_to_sink(
    document: flow.FlowDocument,
    *,
    owner_entity_id: str,
    source_selector: dict[str, Any],
    sink_selector: dict[str, Any],
    max_depth: int = 12,
    max_paths: int = 20,
    max_nodes: int = 240,
) -> dict[str, Any]:
    depth_limit = _bounded_int(max_depth, "max_depth", 1, MAX_TRACE_DEPTH)
    path_limit = _bounded_int(max_paths, "max_paths", 1, MAX_TRACE_PATHS)
    node_limit = _bounded_int(max_nodes, "max_nodes", 2, MAX_TRACE_NODES)
    sources = _selector_nodes(document, owner_entity_id, source_selector)
    sinks = _selector_nodes(document, owner_entity_id, sink_selector)
    if not sources:
        raise ValueTracingError("source selector did not resolve to a FlowNode")
    if not sinks:
        raise ValueTracingError("sink selector did not resolve to a FlowNode")

    outgoing, _ = _index_edges(document)
    sink_ids = {item.node_id for item in sinks}
    found: dict[str, flow.FlowPath] = {}
    selected_nodes: set[str] = set()
    selected_edges: set[str] = set()
    reachable: set[str] = {item.node_id for item in sources}
    truncated = False
    explored_states = 0

    queue = deque(
        (source.node_id, (source.node_id,), ())
        for source in sorted(sources, key=lambda item: item.node_id)
    )
    while queue and len(found) < path_limit:
        explored_states += 1
        if explored_states > MAX_TRACE_STATES:
            truncated = True
            break
        node_id, node_path, edge_path = queue.popleft()
        if len(edge_path) >= depth_limit:
            continue
        for edge in outgoing.get(node_id, ()):
            target = edge.target_node_id
            if target in node_path:
                continue
            if target not in reachable and len(reachable) >= node_limit:
                truncated = True
                continue
            next_nodes = node_path + (target,)
            next_edges = edge_path + (edge.edge_id,)
            reachable.add(target)
            if target in sink_ids:
                path_id = flow.flow_path_id(document.snapshot_id, next_nodes, next_edges)
                found[path_id] = flow.FlowPath(
                    document.snapshot_id,
                    path_id,
                    next_nodes,
                    next_edges,
                    True,
                )
                if len(found) >= path_limit:
                    truncated = bool(queue) or any(
                        candidate.edge_id != edge.edge_id
                        for candidate in outgoing.get(node_id, ())
                    )
                    break
            else:
                if len(queue) >= MAX_TRACE_STATES:
                    truncated = True
                    continue
                queue.append((target, next_nodes, next_edges))

    for path in found.values():
        selected_nodes.update(path.node_ids)
        selected_edges.update(path.segment_ids)
    if not selected_nodes:
        selected_nodes.update(item.node_id for item in sources)
        selected_nodes.update(item.node_id for item in sinks)
    if len(selected_nodes) > node_limit:
        raise ValueTracingError("composed source-to-sink paths exceed max_nodes")

    nodes = {item.node_id: item for item in document.nodes}
    relevant_for_gaps = reachable | {item.node_id for item in sinks}
    gaps, gap_truncated = _gap_subset(
        document,
        relevant_for_gaps,
        nodes,
        max_nodes=node_limit,
    )
    gap_node_ids = {
        node_id
        for gap in gaps
        for node_id in (gap.source_node_id, gap.target_node_id)
        if node_id
    }
    if len(selected_nodes | gap_node_ids) <= node_limit:
        selected_nodes.update(gap_node_ids)
    else:
        gaps = []
        gap_truncated = True
    truncated = truncated or gap_truncated

    result = _subdocument(
        document,
        selected_nodes,
        selected_edges,
        gaps,
        tuple(sorted(found.values(), key=lambda item: item.path_id)),
    )
    return {
        "value_tracing_version": VALUE_TRACING_VERSION,
        "operation": "find_source_to_sink",
        "source_node_ids": [item.node_id for item in sorted(sources, key=lambda item: item.node_id)],
        "sink_node_ids": [item.node_id for item in sorted(sinks, key=lambda item: item.node_id)],
        "complete_path_count": len(found),
        "truncated": truncated,
        "flow": result.to_dict(),
    }


def descriptor() -> dict[str, Any]:
    return {
        "value_tracing_version": VALUE_TRACING_VERSION,
        "flow_ir_version": flow.FLOW_IR_VERSION,
        "semantic_selectors": list(SELECTOR_KINDS),
        "calls_xref_are_data_flow": False,
        "gaps_are_traversable": False,
        "max_trace_depth": MAX_TRACE_DEPTH,
        "max_trace_nodes": MAX_TRACE_NODES,
        "max_trace_paths": MAX_TRACE_PATHS,
        "max_trace_states": MAX_TRACE_STATES,
    }
