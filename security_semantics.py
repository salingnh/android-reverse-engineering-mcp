from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Iterable

import flow_ir as flow

SECURITY_SEMANTICS_VERSION = 1
MAX_SECURITY_SIGNALS = 512
MAX_SECURITY_FINDINGS = 100
MAX_SECURITY_BOUNDARIES = 256
MAX_SECURITY_PATH_DEPTH = 32
MAX_SECURITY_PATH_STATES = 10_000
MAX_SECURITY_RESULT_BYTES = 256 * 1024
MAX_SECURITY_EVIDENCE_REFS = 32
MAX_SECURITY_TEXT = 256
MAX_SECURITY_PROPERTIES = 8

ANCHOR_TYPES = ("FLOW_NODE", "FLOW_EDGE", "FLOW_GAP")
AUTH_FOCUS = ("any", "authorization_header", "bearer", "refresh_token", "api_key")
CRYPTO_FAMILIES = ("any", "hmac", "aes")

SIGNAL_KINDS = (
    "AUTHORIZATION_HEADER_SINK",
    "API_KEY_HEADER_SINK",
    "API_KEY_QUERY_SINK",
    "TOKEN_SOURCE_BOUNDARY",
    "REFRESH_TOKEN_SOURCE_BOUNDARY",
    "TOKEN_EXCHANGE_SINK",
    "BEARER_SCHEME_MARKER",
    "HMAC_KEY_INPUT",
    "HMAC_PAYLOAD_INPUT",
    "HMAC_OUTPUT_BOUNDARY",
    "SIGNATURE_HEADER_SINK",
    "SIGNATURE_QUERY_SINK",
    "CRYPTO_KEY_INPUT",
    "CRYPTO_IV_INPUT",
    "AES_PAYLOAD_INPUT",
    "AES_OUTPUT_BOUNDARY",
    "CRYPTO_ALGORITHM_MARKER",
    "IDENTITY_SDK_BOUNDARY",
    "PAYMENT_SDK_BOUNDARY",
)

FINDING_KINDS = (
    "AUTHORIZATION_HEADER_FLOW",
    "BEARER_AUTH_FLOW",
    "REFRESH_TOKEN_EXCHANGE",
    "API_KEY_HEADER_FLOW",
    "API_KEY_QUERY_FLOW",
    "HMAC_KEY_INPUT_FLOW",
    "HMAC_PAYLOAD_INPUT_FLOW",
    "HMAC_OUTPUT_TO_SIGNATURE_SINK",
    "AES_KEY_INPUT_FLOW",
    "AES_IV_INPUT_FLOW",
    "AES_PAYLOAD_INPUT_FLOW",
    "AES_OUTPUT_FLOW",
)

SAFE_PROPERTY_KEYS = frozenset(
    {
        "provider",
        "family",
        "variant",
        "channel",
        "contract",
        "token_kind",
        "boundary_kind",
        "role",
    }
)

ROOT_VALUE_KINDS = frozenset({"PARAMETER", "FIELD", "STORAGE", "CONSTANT"})


class SecuritySemanticsError(ValueError):
    pass


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash(*parts: str) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(str(part).encode("utf-8", "replace"))
        digest.update(b"\0")
    return digest.hexdigest()


def _text(value: Any, name: str, maximum: int, *, empty: bool = False) -> str:
    if not isinstance(value, str):
        raise SecuritySemanticsError(f"{name} must be a string")
    result = value.strip()
    if not result and not empty:
        raise SecuritySemanticsError(f"{name} must be non-empty")
    if len(result) > maximum:
        raise SecuritySemanticsError(f"{name} exceeds size bound")
    return result


def _enum(value: Any, allowed: Iterable[str], name: str) -> str:
    result = _text(value, name, 128).upper()
    options = {str(item).upper() for item in allowed}
    if result not in options:
        raise SecuritySemanticsError(f"unsupported {name}: {result}")
    return result


def _lower_enum(value: Any, allowed: Iterable[str], name: str) -> str:
    result = _text(value, name, 64).lower()
    if result not in set(allowed):
        raise SecuritySemanticsError(f"unsupported {name}: {result}")
    return result


def _bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SecuritySemanticsError(f"invalid {name}")
    if value < minimum or value > maximum:
        raise SecuritySemanticsError(f"invalid {name}")
    return value


def _properties(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > MAX_SECURITY_PROPERTIES:
        raise SecuritySemanticsError("invalid security signal properties")
    result: dict[str, str] = {}
    for key, raw in value.items():
        if key not in SAFE_PROPERTY_KEYS:
            raise SecuritySemanticsError(f"unsupported security property: {key}")
        text = _text(raw, f"security property {key}", MAX_SECURITY_TEXT)
        if any(ord(char) < 32 for char in text):
            raise SecuritySemanticsError(f"invalid security property {key}")
        result[key] = text
    return dict(sorted(result.items()))


def _refs(value: Iterable[str]) -> tuple[str, ...]:
    items = tuple(sorted({_text(item, "evidence_ref", 256) for item in value}))
    if len(items) > MAX_SECURITY_EVIDENCE_REFS:
        raise SecuritySemanticsError("security signal exceeds evidence reference bound")
    return items


def security_signal_id(
    snapshot_id: str,
    kind: str,
    anchor_type: str,
    anchor_id: str,
    discriminator: str = "",
) -> str:
    snapshot = _text(snapshot_id, "snapshot_id", 128)
    signal_kind = _enum(kind, SIGNAL_KINDS, "security signal kind")
    anchor = _enum(anchor_type, ANCHOR_TYPES, "security anchor type")
    record_id = _text(anchor_id, "security anchor id", 256)
    disc = _text(discriminator, "security signal discriminator", 512, empty=True)
    return (
        f"secsig:v{SECURITY_SEMANTICS_VERSION}:{signal_kind.lower()}:"
        f"{_hash(snapshot, signal_kind, anchor, record_id, disc)}"
    )


def security_finding_id(
    snapshot_id: str,
    kind: str,
    source_signal_ids: Iterable[str],
    sink_signal_ids: Iterable[str],
    path_ids: Iterable[str],
) -> str:
    snapshot = _text(snapshot_id, "snapshot_id", 128)
    finding_kind = _enum(kind, FINDING_KINDS, "security finding kind")
    sources = tuple(sorted(_text(item, "source_signal_id", 256) for item in source_signal_ids))
    sinks = tuple(sorted(_text(item, "sink_signal_id", 256) for item in sink_signal_ids))
    paths = tuple(sorted(_text(item, "path_id", 256) for item in path_ids))
    if not paths:
        raise SecuritySemanticsError("security finding requires a proven Flow path")
    return (
        f"secfind:v{SECURITY_SEMANTICS_VERSION}:{finding_kind.lower()}:"
        f"{_hash(snapshot, finding_kind, *sources, 'sinks', *sinks, 'paths', *paths)}"
    )


@dataclass(frozen=True)
class SecuritySignal:
    snapshot_id: str
    signal_id: str
    kind: str
    owner_entity_id: str
    representation: str
    anchor_type: str
    anchor_id: str
    producer: str
    discriminator: str = ""
    properties: dict[str, str] = field(default_factory=dict)
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        snapshot = _text(self.snapshot_id, "snapshot_id", 128)
        signal_id = _text(self.signal_id, "signal_id", 256)
        kind = _enum(self.kind, SIGNAL_KINDS, "security signal kind")
        owner = _text(self.owner_entity_id, "owner_entity_id", 256)
        representation = _text(self.representation, "representation", 64).lower()
        anchor_type = _enum(self.anchor_type, ANCHOR_TYPES, "security anchor type")
        anchor_id = _text(self.anchor_id, "security anchor id", 256)
        producer = _text(self.producer, "security signal producer", 128)
        discriminator = _text(
            self.discriminator,
            "security signal discriminator",
            512,
            empty=True,
        )
        properties = _properties(self.properties)
        evidence = _refs(self.evidence_refs)
        for name, value in (
            ("snapshot_id", snapshot),
            ("signal_id", signal_id),
            ("kind", kind),
            ("owner_entity_id", owner),
            ("representation", representation),
            ("anchor_type", anchor_type),
            ("anchor_id", anchor_id),
            ("producer", producer),
            ("discriminator", discriminator),
            ("properties", properties),
            ("evidence_refs", evidence),
        ):
            object.__setattr__(self, name, value)
        if signal_id != security_signal_id(
            snapshot, kind, anchor_type, anchor_id, discriminator
        ):
            raise SecuritySemanticsError("security signal id does not match canonical identity")

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "kind": self.kind,
            "owner_entity_id": self.owner_entity_id,
            "representation": self.representation,
            "anchor_type": self.anchor_type,
            "anchor_id": self.anchor_id,
            "producer": self.producer,
            "discriminator": self.discriminator,
            "properties": dict(self.properties),
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class SecurityFinding:
    snapshot_id: str
    finding_id: str
    kind: str
    source_signal_ids: tuple[str, ...]
    sink_signal_ids: tuple[str, ...]
    path_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        snapshot = _text(self.snapshot_id, "snapshot_id", 128)
        finding_id = _text(self.finding_id, "finding_id", 256)
        kind = _enum(self.kind, FINDING_KINDS, "security finding kind")
        sources = tuple(sorted({_text(item, "source_signal_id", 256) for item in self.source_signal_ids}))
        sinks = tuple(sorted({_text(item, "sink_signal_id", 256) for item in self.sink_signal_ids}))
        paths = tuple(sorted({_text(item, "path_id", 256) for item in self.path_ids}))
        expected = security_finding_id(snapshot, kind, sources, sinks, paths)
        if finding_id != expected:
            raise SecuritySemanticsError("security finding id does not match canonical identity")
        for name, value in (
            ("snapshot_id", snapshot),
            ("finding_id", finding_id),
            ("kind", kind),
            ("source_signal_ids", sources),
            ("sink_signal_ids", sinks),
            ("path_ids", paths),
        ):
            object.__setattr__(self, name, value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "kind": self.kind,
            "source_signal_ids": list(self.source_signal_ids),
            "sink_signal_ids": list(self.sink_signal_ids),
            "path_ids": list(self.path_ids),
            "complete": True,
        }


@dataclass(frozen=True)
class SecurityOverlay:
    snapshot_id: str
    signals: tuple[SecuritySignal, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        snapshot = _text(self.snapshot_id, "snapshot_id", 128)
        if len(self.signals) > MAX_SECURITY_SIGNALS:
            raise SecuritySemanticsError("security overlay exceeds signal count bound")
        result: dict[str, SecuritySignal] = {}
        for item in self.signals:
            if item.snapshot_id != snapshot:
                raise SecuritySemanticsError("security overlay contains snapshot mismatch")
            if item.signal_id in result:
                raise SecuritySemanticsError(f"duplicate security signal id: {item.signal_id}")
            result[item.signal_id] = item
        object.__setattr__(self, "snapshot_id", snapshot)
        object.__setattr__(
            self,
            "signals",
            tuple(sorted(result.values(), key=lambda item: item.signal_id)),
        )

    def validate_anchors(self, document: flow.FlowDocument) -> None:
        if document.snapshot_id != self.snapshot_id:
            raise SecuritySemanticsError("security overlay and Flow IR snapshot mismatch")
        node_ids = {item.node_id for item in document.nodes}
        edge_ids = {item.edge_id for item in document.edges}
        gap_ids = {item.gap_id for item in document.gaps}
        anchors = {
            "FLOW_NODE": node_ids,
            "FLOW_EDGE": edge_ids,
            "FLOW_GAP": gap_ids,
        }
        for signal in self.signals:
            if signal.anchor_id not in anchors[signal.anchor_type]:
                raise SecuritySemanticsError(
                    f"security signal anchor does not resolve: {signal.signal_id}"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "security_semantics_version": SECURITY_SEMANTICS_VERSION,
            "snapshot_id": self.snapshot_id,
            "signals": [item.to_dict() for item in self.signals],
            "count": len(self.signals),
        }


def _edge_indexes(document: flow.FlowDocument):
    outgoing: dict[str, list[flow.FlowEdge]] = defaultdict(list)
    incoming: dict[str, list[flow.FlowEdge]] = defaultdict(list)
    for edge in document.edges:
        outgoing[edge.source_node_id].append(edge)
        incoming[edge.target_node_id].append(edge)
    for values in (*outgoing.values(), *incoming.values()):
        values.sort(key=lambda item: item.edge_id)
    return outgoing, incoming


def _anchor_node_ids(
    signal: SecuritySignal,
    document: flow.FlowDocument,
) -> tuple[str, ...]:
    if signal.anchor_type == "FLOW_NODE":
        return (signal.anchor_id,)
    if signal.anchor_type == "FLOW_EDGE":
        edge = next(item for item in document.edges if item.edge_id == signal.anchor_id)
        return (edge.source_node_id, edge.target_node_id)
    gap = next(item for item in document.gaps if item.gap_id == signal.anchor_id)
    return tuple(
        item for item in (gap.source_node_id, gap.target_node_id) if item is not None
    )


def _source_nodes(document: flow.FlowDocument) -> set[str]:
    _, incoming = _edge_indexes(document)
    result: set[str] = set()
    for node in document.nodes:
        if node.value_kind in ROOT_VALUE_KINDS or not incoming.get(node.node_id):
            result.add(node.node_id)
    return result


def _find_paths(
    document: flow.FlowDocument,
    source_ids: set[str],
    sink_ids: set[str],
    *,
    max_depth: int,
    max_paths: int,
) -> tuple[tuple[flow.FlowPath, ...], bool]:
    depth_limit = _bounded_int(
        max_depth, "security path depth", 1, MAX_SECURITY_PATH_DEPTH
    )
    path_limit = _bounded_int(max_paths, "security finding limit", 1, MAX_SECURITY_FINDINGS)
    if not source_ids or not sink_ids:
        return (), False
    outgoing, _ = _edge_indexes(document)
    found: dict[str, flow.FlowPath] = {}
    queue = deque(
        (source, (source,), ()) for source in sorted(source_ids)
    )
    states = 0
    truncated = False
    while queue and len(found) < path_limit:
        node_id, node_path, edge_path = queue.popleft()
        states += 1
        if states > MAX_SECURITY_PATH_STATES:
            truncated = True
            break
        if len(edge_path) >= depth_limit:
            if outgoing.get(node_id):
                truncated = True
            continue
        for edge in outgoing.get(node_id, ()):
            target = edge.target_node_id
            if target in node_path:
                continue
            next_nodes = node_path + (target,)
            next_edges = edge_path + (edge.edge_id,)
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
                    truncated = bool(queue) or len(outgoing.get(node_id, ())) > 1
                    break
            else:
                queue.append((target, next_nodes, next_edges))
    return tuple(sorted(found.values(), key=lambda item: item.path_id)), truncated


def _signals_by_kind(overlay: SecurityOverlay) -> dict[str, list[SecuritySignal]]:
    result: dict[str, list[SecuritySignal]] = defaultdict(list)
    for signal in overlay.signals:
        result[signal.kind].append(signal)
    for values in result.values():
        values.sort(key=lambda item: item.signal_id)
    return result


def _node_signal_map(
    overlay: SecurityOverlay,
    document: flow.FlowDocument,
) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for signal in overlay.signals:
        for node_id in _anchor_node_ids(signal, document):
            result[node_id].add(signal.kind)
    return result


def _finding(
    document: flow.FlowDocument,
    kind: str,
    source_signals: Iterable[SecuritySignal],
    sink_signals: Iterable[SecuritySignal],
    paths: Iterable[flow.FlowPath],
) -> SecurityFinding:
    source_ids = tuple(sorted(item.signal_id for item in source_signals))
    sink_ids = tuple(sorted(item.signal_id for item in sink_signals))
    path_ids = tuple(sorted(item.path_id for item in paths))
    finding_id = security_finding_id(
        document.snapshot_id,
        kind,
        source_ids,
        sink_ids,
        path_ids,
    )
    return SecurityFinding(
        document.snapshot_id,
        finding_id,
        kind,
        source_ids,
        sink_ids,
        path_ids,
    )


def _relevant_boundaries(
    document: flow.FlowDocument,
    overlay: SecurityOverlay,
    selected_nodes: set[str],
) -> tuple[flow.FlowGap, ...]:
    explicit_gap_ids = {
        signal.anchor_id
        for signal in overlay.signals
        if signal.anchor_type == "FLOW_GAP"
    }
    result: list[flow.FlowGap] = []
    for gap in sorted(document.gaps, key=lambda item: item.gap_id):
        endpoints = {item for item in (gap.source_node_id, gap.target_node_id) if item}
        if gap.gap_id in explicit_gap_ids or endpoints.intersection(selected_nodes):
            result.append(gap)
        if len(result) >= MAX_SECURITY_BOUNDARIES:
            break
    return tuple(result)


def _result(
    operation: str,
    document: flow.FlowDocument,
    overlay: SecurityOverlay,
    findings: Iterable[SecurityFinding],
    paths: Iterable[flow.FlowPath],
    *,
    truncated: bool,
    focus: str,
) -> dict[str, Any]:
    finding_items = tuple(sorted(findings, key=lambda item: item.finding_id))
    path_items = tuple(sorted({item.path_id: item for item in paths}.values(), key=lambda item: item.path_id))
    selected_nodes = {node for path in path_items for node in path.node_ids}
    boundaries = _relevant_boundaries(document, overlay, selected_nodes)
    payload = {
        "security_semantics_version": SECURITY_SEMANTICS_VERSION,
        "operation": operation,
        "focus": focus,
        "findings": [item.to_dict() for item in finding_items],
        "signals": [item.to_dict() for item in overlay.signals],
        "paths": [item.to_dict() for item in path_items],
        "boundaries": [item.to_dict() for item in boundaries],
        "counts": {
            "findings": len(finding_items),
            "signals": len(overlay.signals),
            "paths": len(path_items),
            "boundaries": len(boundaries),
        },
        "truncated": bool(truncated),
        "calls_xref_are_data_flow": False,
        "gaps_are_traversable": False,
    }
    if len(_canonical_json(payload).encode("utf-8")) > MAX_SECURITY_RESULT_BYTES:
        raise SecuritySemanticsError("security semantic result exceeds serialized size bound")
    return payload


def find_auth_flow(
    document: flow.FlowDocument,
    overlay: SecurityOverlay,
    *,
    focus: str = "any",
    max_depth: int = 16,
    max_findings: int = 50,
) -> dict[str, Any]:
    focus_value = _lower_enum(focus, AUTH_FOCUS, "auth focus")
    limit = _bounded_int(max_findings, "security finding limit", 1, MAX_SECURITY_FINDINGS)
    overlay.validate_anchors(document)
    by_kind = _signals_by_kind(overlay)
    roots = _source_nodes(document)
    node_signals = _node_signal_map(overlay, document)
    findings: list[SecurityFinding] = []
    all_paths: list[flow.FlowPath] = []
    truncated = False

    def add_root_to_sink(sink: SecuritySignal, finding_kind: str) -> None:
        nonlocal truncated
        if len(findings) >= limit:
            truncated = True
            return
        sink_nodes = set(_anchor_node_ids(sink, document))
        paths, cut = _find_paths(
            document,
            roots,
            sink_nodes,
            max_depth=max_depth,
            max_paths=limit - len(findings),
        )
        truncated |= cut
        for path in paths:
            kind = finding_kind
            if finding_kind == "AUTHORIZATION_HEADER_FLOW" and any(
                "BEARER_SCHEME_MARKER" in node_signals.get(node_id, set())
                for node_id in path.node_ids
            ):
                kind = "BEARER_AUTH_FLOW"
            findings.append(_finding(document, kind, (), (sink,), (path,)))
            all_paths.append(path)
            if len(findings) >= limit:
                break

    if focus_value in {"any", "authorization_header", "bearer"}:
        for sink in by_kind.get("AUTHORIZATION_HEADER_SINK", ()):
            add_root_to_sink(sink, "AUTHORIZATION_HEADER_FLOW")
    if focus_value in {"any", "api_key"}:
        for sink in by_kind.get("API_KEY_HEADER_SINK", ()):
            add_root_to_sink(sink, "API_KEY_HEADER_FLOW")
        for sink in by_kind.get("API_KEY_QUERY_SINK", ()):
            add_root_to_sink(sink, "API_KEY_QUERY_FLOW")
    if focus_value in {"any", "refresh_token"}:
        sources = by_kind.get("REFRESH_TOKEN_SOURCE_BOUNDARY", ())
        source_nodes = {
            node_id
            for signal in sources
            for node_id in _anchor_node_ids(signal, document)
        }
        for sink in by_kind.get("TOKEN_EXCHANGE_SINK", ()):
            if len(findings) >= limit:
                truncated = True
                break
            sink_nodes = set(_anchor_node_ids(sink, document))
            paths, cut = _find_paths(
                document,
                source_nodes,
                sink_nodes,
                max_depth=max_depth,
                max_paths=limit - len(findings),
            )
            truncated |= cut
            for path in paths:
                findings.append(
                    _finding(document, "REFRESH_TOKEN_EXCHANGE", sources, (sink,), (path,))
                )
                all_paths.append(path)
                if len(findings) >= limit:
                    break

    if focus_value == "bearer":
        findings = [item for item in findings if item.kind == "BEARER_AUTH_FLOW"]
        wanted_paths = {path_id for item in findings for path_id in item.path_ids}
        all_paths = [item for item in all_paths if item.path_id in wanted_paths]

    return _result(
        "find_auth_flow",
        document,
        overlay,
        findings,
        all_paths,
        truncated=truncated,
        focus=focus_value,
    )


def trace_crypto(
    document: flow.FlowDocument,
    overlay: SecurityOverlay,
    *,
    family: str = "any",
    max_depth: int = 16,
    max_findings: int = 50,
) -> dict[str, Any]:
    family_value = _lower_enum(family, CRYPTO_FAMILIES, "crypto family")
    limit = _bounded_int(max_findings, "security finding limit", 1, MAX_SECURITY_FINDINGS)
    overlay.validate_anchors(document)
    by_kind = _signals_by_kind(overlay)
    roots = _source_nodes(document)
    findings: list[SecurityFinding] = []
    all_paths: list[flow.FlowPath] = []
    truncated = False

    def input_paths(signal_kind: str, finding_kind: str) -> None:
        nonlocal truncated
        for sink in by_kind.get(signal_kind, ()):
            if len(findings) >= limit:
                truncated = True
                return
            sink_nodes = set(_anchor_node_ids(sink, document))
            paths, cut = _find_paths(
                document,
                roots,
                sink_nodes,
                max_depth=max_depth,
                max_paths=limit - len(findings),
            )
            truncated |= cut
            for path in paths:
                findings.append(_finding(document, finding_kind, (), (sink,), (path,)))
                all_paths.append(path)
                if len(findings) >= limit:
                    return

    if family_value in {"any", "hmac"}:
        input_paths("HMAC_KEY_INPUT", "HMAC_KEY_INPUT_FLOW")
        input_paths("HMAC_PAYLOAD_INPUT", "HMAC_PAYLOAD_INPUT_FLOW")
        outputs = by_kind.get("HMAC_OUTPUT_BOUNDARY", ())
        signature_sinks = list(by_kind.get("SIGNATURE_HEADER_SINK", ()))
        signature_sinks.extend(by_kind.get("SIGNATURE_QUERY_SINK", ()))
        for output in outputs:
            source_nodes = set(_anchor_node_ids(output, document))
            if output.anchor_type == "FLOW_GAP":
                gap = next(item for item in document.gaps if item.gap_id == output.anchor_id)
                source_nodes = {gap.target_node_id} if gap.target_node_id else set()
            for sink in signature_sinks:
                if len(findings) >= limit:
                    truncated = True
                    break
                paths, cut = _find_paths(
                    document,
                    source_nodes,
                    set(_anchor_node_ids(sink, document)),
                    max_depth=max_depth,
                    max_paths=limit - len(findings),
                )
                truncated |= cut
                for path in paths:
                    findings.append(
                        _finding(
                            document,
                            "HMAC_OUTPUT_TO_SIGNATURE_SINK",
                            (output,),
                            (sink,),
                            (path,),
                        )
                    )
                    all_paths.append(path)
                    if len(findings) >= limit:
                        break

    if family_value in {"any", "aes"}:
        input_paths("CRYPTO_KEY_INPUT", "AES_KEY_INPUT_FLOW")
        input_paths("CRYPTO_IV_INPUT", "AES_IV_INPUT_FLOW")
        input_paths("AES_PAYLOAD_INPUT", "AES_PAYLOAD_INPUT_FLOW")
        _, incoming = _edge_indexes(document)
        outgoing, _ = _edge_indexes(document)
        for output in by_kind.get("AES_OUTPUT_BOUNDARY", ()):
            source_nodes = set(_anchor_node_ids(output, document))
            if output.anchor_type == "FLOW_GAP":
                gap = next(item for item in document.gaps if item.gap_id == output.anchor_id)
                source_nodes = {gap.target_node_id} if gap.target_node_id else set()
            terminals = {
                node.node_id
                for node in document.nodes
                if node.node_id not in source_nodes
                and not outgoing.get(node.node_id)
                and incoming.get(node.node_id)
            }
            if not terminals:
                continue
            paths, cut = _find_paths(
                document,
                source_nodes,
                terminals,
                max_depth=max_depth,
                max_paths=limit - len(findings),
            )
            truncated |= cut
            for path in paths:
                findings.append(
                    _finding(document, "AES_OUTPUT_FLOW", (output,), (), (path,))
                )
                all_paths.append(path)
                if len(findings) >= limit:
                    truncated = True
                    break

    return _result(
        "trace_crypto",
        document,
        overlay,
        findings,
        all_paths,
        truncated=truncated,
        focus=family_value,
    )


def descriptor() -> dict[str, Any]:
    return {
        "security_semantics_version": SECURITY_SEMANTICS_VERSION,
        "flow_ir_version": flow.FLOW_IR_VERSION,
        "signal_kinds": list(SIGNAL_KINDS),
        "finding_kinds": list(FINDING_KINDS),
        "auth_focus": list(AUTH_FOCUS),
        "crypto_families": list(CRYPTO_FAMILIES),
        "calls_xref_are_data_flow": False,
        "gaps_are_traversable": False,
        "raw_secret_values": False,
        "persistent_security_storage": False,
        "max_signals": MAX_SECURITY_SIGNALS,
        "max_findings": MAX_SECURITY_FINDINGS,
        "max_boundaries": MAX_SECURITY_BOUNDARIES,
        "max_path_depth": MAX_SECURITY_PATH_DEPTH,
        "max_path_states": MAX_SECURITY_PATH_STATES,
        "max_result_bytes": MAX_SECURITY_RESULT_BYTES,
    }
