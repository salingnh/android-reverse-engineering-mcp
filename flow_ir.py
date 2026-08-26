from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

import program_model as pm

FLOW_IR_VERSION = 1
MAX_FLOW_NODES = 5_000
MAX_FLOW_EDGES = 10_000
MAX_FLOW_GAPS = 2_000
MAX_FLOW_PATHS = 1_000
MAX_PATH_NODES = 256
MAX_EVIDENCE_REFS = 128
MAX_EVIDENCE_REF_CHARS = 256
MAX_TEXT_CHARS = 2_048
MAX_SEMANTIC_KEY_CHARS = 4_096
MAX_PROPERTY_JSON_BYTES = 32 * 1024
MAX_FLOW_DOCUMENT_BYTES = 2 * 1024 * 1024

VALUE_KINDS = (
    "PARAMETER", "ARGUMENT", "RETURN", "CONSTANT", "LOCAL", "FIELD", "STORAGE", "UNKNOWN",
)
SEMANTIC_ROLES = ("SOURCE", "SINK", "SANITIZER", "TRANSFORMATION")
FLOW_EDGE_KINDS = (
    "ASSIGNMENT", "ARGUMENT_TO_PARAMETER", "RETURN_TO_CALLSITE", "FIELD_WRITE", "FIELD_READ",
    "CONSTANT_TO_VALUE", "TRANSFORMS", "FLOWS_TO", "SANITIZES",
)
FLOW_GAP_KINDS = (
    "REFLECTION", "NATIVE", "DYNAMIC_DISPATCH", "UNSUPPORTED_INSTRUCTION",
    "EXTERNAL_BOUNDARY", "MISSING_EVIDENCE", "BUDGET", "UNKNOWN",
)
NODE_PROPERTY_ALLOWLIST = {
    "PARAMETER": frozenset({"parameter_index", "type"}),
    "ARGUMENT": frozenset({"argument_index", "type"}),
    "RETURN": frozenset({"type"}),
    "CONSTANT": frozenset({"literal_kind", "type", "value_fingerprint"}),
    "LOCAL": frozenset({"slot", "name", "type"}),
    "FIELD": frozenset({"field_name", "type", "static"}),
    "STORAGE": frozenset({"storage_kind", "name"}),
    "UNKNOWN": frozenset({"type"}),
}
EDGE_PROPERTY_ALLOWLIST = {
    "ASSIGNMENT": frozenset({"statement_offset"}),
    "ARGUMENT_TO_PARAMETER": frozenset({"argument_index", "parameter_index", "callsite_offset"}),
    "RETURN_TO_CALLSITE": frozenset({"callsite_offset"}),
    "FIELD_WRITE": frozenset({"field_name", "access_offset"}),
    "FIELD_READ": frozenset({"field_name", "access_offset"}),
    "CONSTANT_TO_VALUE": frozenset({"statement_offset"}),
    "TRANSFORMS": frozenset({"transform_kind"}),
    "FLOWS_TO": frozenset({"flow_kind"}),
    "SANITIZES": frozenset({"sanitizer_kind"}),
}


class FlowIRError(ValueError):
    pass


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise FlowIRError(f"value is not canonical JSON: {exc}") from exc


def _text(value: Any, name: str, limit: int, *, empty: bool = False) -> str:
    text = str(value if value is not None else "").strip()
    if not text and not empty:
        raise FlowIRError(f"{name} must be non-empty")
    if len(text) > limit:
        raise FlowIRError(f"{name} exceeds {limit} characters")
    return text


def _optional_text(value: Any, name: str, limit: int) -> str | None:
    if value is None or not str(value).strip():
        return None
    return _text(value, name, limit)


def _enum(value: Any, allowed: tuple[str, ...], name: str) -> str:
    result = _text(value, name, 128).upper()
    if result not in allowed:
        raise FlowIRError(f"unsupported {name}: {result}")
    return result


def _refs(values: Iterable[Any] | None) -> tuple[str, ...]:
    result: set[str] = set()
    for value in values or ():
        result.add(_text(value, "evidence_ref", MAX_EVIDENCE_REF_CHARS))
        if len(result) > MAX_EVIDENCE_REFS:
            raise FlowIRError("evidence_refs exceed count bound")
    return tuple(sorted(result))


def _properties(value: dict[str, Any] | None, allowlist: frozenset[str]) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise FlowIRError("properties must be an object")
    unknown = sorted(set(value) - set(allowlist))
    if unknown:
        raise FlowIRError("properties contain non-canonical fields: " + ", ".join(unknown[:10]))
    encoded = _canonical_json(value)
    if len(encoded) > MAX_PROPERTY_JSON_BYTES:
        raise FlowIRError("properties exceed serialized size bound")
    return json.loads(encoded.decode("utf-8"))


def _property_text(properties: dict[str, Any], name: str, limit: int) -> None:
    if name in properties:
        if not isinstance(properties[name], str):
            raise FlowIRError(f"property {name} must be a string")
        _text(properties[name], f"property {name}", limit, empty=True)


def _property_int(properties: dict[str, Any], name: str) -> None:
    if name in properties:
        value = properties[name]
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**63 - 1:
            raise FlowIRError(f"property {name} must be a bounded non-negative integer")


def _node_properties(kind: str, value: dict[str, Any] | None) -> dict[str, Any]:
    result = _properties(value, NODE_PROPERTY_ALLOWLIST[kind])
    for name, limit in (("type", 512), ("literal_kind", 128), ("name", 512), ("field_name", 1024), ("storage_kind", 128)):
        _property_text(result, name, limit)
    for name in ("parameter_index", "argument_index", "slot"):
        _property_int(result, name)
    if "static" in result and not isinstance(result["static"], bool):
        raise FlowIRError("property static must be a boolean")
    if "value_fingerprint" in result:
        fingerprint = result["value_fingerprint"]
        if not isinstance(fingerprint, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", fingerprint) is None:
            raise FlowIRError("property value_fingerprint must be sha256:<64 lowercase hex>")
    return result


def _edge_properties(kind: str, value: dict[str, Any] | None) -> dict[str, Any]:
    result = _properties(value, EDGE_PROPERTY_ALLOWLIST[kind])
    for name, limit in (("field_name", 1024), ("transform_kind", 256), ("flow_kind", 256), ("sanitizer_kind", 256)):
        _property_text(result, name, limit)
    for name in ("statement_offset", "argument_index", "parameter_index", "callsite_offset", "access_offset"):
        _property_int(result, name)
    return result


def _hash(*parts: str) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part.encode("utf-8", "replace")); digest.update(b"\0")
    return digest.hexdigest()


def constant_semantic_key(*identity_parts: str) -> str:
    parts = tuple(_text(part, "constant identity part", 1024) for part in identity_parts)
    if not parts:
        raise FlowIRError("constant semantic identity requires at least one part")
    return "constant:" + _hash(*parts)


def flow_node_id(snapshot_id: str, value_kind: str, owner_entity_id: str, semantic_key: str) -> str:
    snapshot = _text(snapshot_id, "snapshot_id", 128); kind = _enum(value_kind, VALUE_KINDS, "value kind")
    owner = _text(owner_entity_id, "owner_entity_id", 256); key = _text(semantic_key, "semantic_key", MAX_SEMANTIC_KEY_CHARS)
    return f"flown:v{FLOW_IR_VERSION}:{kind.lower()}:{_hash(snapshot, kind, owner, key)}"


def flow_edge_id(snapshot_id: str, kind: str, source_node_id: str, target_node_id: str, discriminator: str = "") -> str:
    snapshot = _text(snapshot_id, "snapshot_id", 128); edge_kind = _enum(kind, FLOW_EDGE_KINDS, "flow edge kind")
    source = _text(source_node_id, "source_node_id", 256); target = _text(target_node_id, "target_node_id", 256); disc = _text(discriminator, "flow edge discriminator", 1024, empty=True)
    return f"flowe:v{FLOW_IR_VERSION}:{edge_kind.lower()}:{_hash(snapshot, edge_kind, source, target, disc)}"


def flow_gap_id(snapshot_id: str, kind: str, owner_entity_id: str, source_node_id: str | None = None, target_node_id: str | None = None, discriminator: str = "") -> str:
    snapshot = _text(snapshot_id, "snapshot_id", 128); gap_kind = _enum(kind, FLOW_GAP_KINDS, "flow gap kind")
    owner = _text(owner_entity_id, "owner_entity_id", 256); source = _optional_text(source_node_id, "source_node_id", 256) or ""; target = _optional_text(target_node_id, "target_node_id", 256) or ""; disc = _text(discriminator, "flow gap discriminator", 1024, empty=True)
    return f"flowg:v{FLOW_IR_VERSION}:{gap_kind.lower()}:{_hash(snapshot, gap_kind, owner, source, target, disc)}"


def flow_path_id(snapshot_id: str, node_ids: Iterable[str], segment_ids: Iterable[str]) -> str:
    snapshot = _text(snapshot_id, "snapshot_id", 128); nodes = tuple(_text(item, "node_id", 256) for item in node_ids); segments = tuple(_text(item, "segment_id", 256) for item in segment_ids)
    if not nodes:
        raise FlowIRError("flow path must contain at least one node")
    return f"flowp:v{FLOW_IR_VERSION}:{_hash(snapshot, *nodes, 'segments', *segments)}"


@dataclass(frozen=True)
class FlowNode:
    snapshot_id: str; node_id: str; semantic_key: str; value_kind: str; owner_entity_id: str; representation: str
    program_entity_id: str | None = None; roles: tuple[str, ...] = field(default_factory=tuple); label: str = ""
    properties: dict[str, Any] = field(default_factory=dict); evidence_refs: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        snapshot = _text(self.snapshot_id, "snapshot_id", 128); kind = _enum(self.value_kind, VALUE_KINDS, "value kind")
        node = _text(self.node_id, "node_id", 256); key = _text(self.semantic_key, "semantic_key", MAX_SEMANTIC_KEY_CHARS); owner = _text(self.owner_entity_id, "owner_entity_id", 256)
        representation = _text(self.representation, "representation", pm.MAX_REPRESENTATION_CHARS).lower(); program_entity = _optional_text(self.program_entity_id, "program_entity_id", 256)
        roles = tuple(sorted({_enum(item, SEMANTIC_ROLES, "semantic role") for item in self.roles})); label = _text(self.label, "label", MAX_TEXT_CHARS, empty=True)
        if kind == "CONSTANT":
            if label:
                raise FlowIRError("constant label must be empty; raw constant values are not IR labels")
            if re.fullmatch(r"constant:[0-9a-f]{64}", key) is None:
                raise FlowIRError("constant semantic_key must be constant:<64 lowercase hex>")
        properties = _node_properties(kind, self.properties); evidence = _refs(self.evidence_refs)
        for name, value in (("snapshot_id", snapshot), ("node_id", node), ("semantic_key", key), ("value_kind", kind), ("owner_entity_id", owner), ("representation", representation), ("program_entity_id", program_entity), ("roles", roles), ("label", label), ("properties", properties), ("evidence_refs", evidence)):
            object.__setattr__(self, name, value)
        if self.node_id != flow_node_id(snapshot, kind, owner, key):
            raise FlowIRError("flow node id does not match canonical identity")

    def to_dict(self) -> dict[str, Any]:
        return {"node_id": self.node_id, "semantic_key": self.semantic_key, "value_kind": self.value_kind, "owner_entity_id": self.owner_entity_id, "program_entity_id": self.program_entity_id, "representation": self.representation, "roles": list(self.roles), "label": self.label, "properties": dict(self.properties), "evidence_refs": list(self.evidence_refs)}


@dataclass(frozen=True)
class FlowEdge:
    snapshot_id: str; edge_id: str; kind: str; source_node_id: str; target_node_id: str; representation: str; producer: str
    discriminator: str = ""; properties: dict[str, Any] = field(default_factory=dict); evidence_refs: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        snapshot = _text(self.snapshot_id, "snapshot_id", 128); kind = _enum(self.kind, FLOW_EDGE_KINDS, "flow edge kind"); edge = _text(self.edge_id, "edge_id", 256)
        source = _text(self.source_node_id, "source_node_id", 256); target = _text(self.target_node_id, "target_node_id", 256); representation = _text(self.representation, "representation", pm.MAX_REPRESENTATION_CHARS).lower(); producer = _text(self.producer, "producer", 256); discriminator = _text(self.discriminator, "flow edge discriminator", 1024, empty=True)
        properties = _edge_properties(kind, self.properties); evidence = _refs(self.evidence_refs)
        for name, value in (("snapshot_id", snapshot), ("edge_id", edge), ("kind", kind), ("source_node_id", source), ("target_node_id", target), ("representation", representation), ("producer", producer), ("discriminator", discriminator), ("properties", properties), ("evidence_refs", evidence)):
            object.__setattr__(self, name, value)
        if self.edge_id != flow_edge_id(snapshot, kind, source, target, discriminator):
            raise FlowIRError("flow edge id does not match canonical identity")

    def to_dict(self) -> dict[str, Any]:
        return {"edge_id": self.edge_id, "kind": self.kind, "source_node_id": self.source_node_id, "target_node_id": self.target_node_id, "representation": self.representation, "producer": self.producer, "discriminator": self.discriminator, "properties": dict(self.properties), "evidence_refs": list(self.evidence_refs)}


@dataclass(frozen=True)
class FlowGap:
    snapshot_id: str; gap_id: str; kind: str; owner_entity_id: str; representation: str; producer: str
    source_node_id: str | None = None; target_node_id: str | None = None; discriminator: str = ""; reason: str = ""; evidence_refs: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        snapshot = _text(self.snapshot_id, "snapshot_id", 128); kind = _enum(self.kind, FLOW_GAP_KINDS, "flow gap kind"); gap = _text(self.gap_id, "gap_id", 256); owner = _text(self.owner_entity_id, "owner_entity_id", 256)
        representation = _text(self.representation, "representation", pm.MAX_REPRESENTATION_CHARS).lower(); producer = _text(self.producer, "producer", 256); source = _optional_text(self.source_node_id, "source_node_id", 256); target = _optional_text(self.target_node_id, "target_node_id", 256); discriminator = _text(self.discriminator, "flow gap discriminator", 1024, empty=True); reason = _text(self.reason, "reason", MAX_TEXT_CHARS, empty=True); evidence = _refs(self.evidence_refs)
        if source is None and target is None:
            raise FlowIRError("flow gap must anchor at least one known node")
        for name, value in (("snapshot_id", snapshot), ("gap_id", gap), ("kind", kind), ("owner_entity_id", owner), ("representation", representation), ("producer", producer), ("source_node_id", source), ("target_node_id", target), ("discriminator", discriminator), ("reason", reason), ("evidence_refs", evidence)):
            object.__setattr__(self, name, value)
        if self.gap_id != flow_gap_id(snapshot, kind, owner, source, target, discriminator):
            raise FlowIRError("flow gap id does not match canonical identity")

    def to_dict(self) -> dict[str, Any]:
        return {"gap_id": self.gap_id, "kind": self.kind, "owner_entity_id": self.owner_entity_id, "source_node_id": self.source_node_id, "target_node_id": self.target_node_id, "representation": self.representation, "producer": self.producer, "discriminator": self.discriminator, "reason": self.reason, "evidence_refs": list(self.evidence_refs)}


@dataclass(frozen=True)
class FlowPath:
    snapshot_id: str; path_id: str; node_ids: tuple[str, ...]; segment_ids: tuple[str, ...]; complete: bool

    def __post_init__(self) -> None:
        snapshot = _text(self.snapshot_id, "snapshot_id", 128); path = _text(self.path_id, "path_id", 256); nodes = tuple(_text(item, "node_id", 256) for item in self.node_ids); segments = tuple(_text(item, "segment_id", 256) for item in self.segment_ids)
        if not nodes:
            raise FlowIRError("flow path must contain at least one node")
        if len(nodes) > MAX_PATH_NODES:
            raise FlowIRError("flow path exceeds node count bound")
        if len(segments) != len(nodes) - 1:
            raise FlowIRError("flow path must have exactly one segment per adjacent node pair")
        if not isinstance(self.complete, bool):
            raise FlowIRError("flow path complete must be boolean")
        for name, value in (("snapshot_id", snapshot), ("path_id", path), ("node_ids", nodes), ("segment_ids", segments)):
            object.__setattr__(self, name, value)
        if self.path_id != flow_path_id(snapshot, nodes, segments):
            raise FlowIRError("flow path id does not match canonical identity")

    def to_dict(self) -> dict[str, Any]:
        return {"path_id": self.path_id, "node_ids": list(self.node_ids), "segment_ids": list(self.segment_ids), "complete": self.complete}


@dataclass(frozen=True)
class FlowDocument:
    snapshot_id: str; nodes: tuple[FlowNode, ...] = field(default_factory=tuple); edges: tuple[FlowEdge, ...] = field(default_factory=tuple); gaps: tuple[FlowGap, ...] = field(default_factory=tuple); paths: tuple[FlowPath, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        snapshot = _text(self.snapshot_id, "snapshot_id", 128)
        for size, limit, label in ((len(self.nodes), MAX_FLOW_NODES, "node"), (len(self.edges), MAX_FLOW_EDGES, "edge"), (len(self.gaps), MAX_FLOW_GAPS, "gap"), (len(self.paths), MAX_FLOW_PATHS, "path")):
            if size > limit:
                raise FlowIRError(f"flow document exceeds {label} count bound")
        nodes = self._unique("node", self.nodes, "node_id"); edges = self._unique("edge", self.edges, "edge_id"); gaps = self._unique("gap", self.gaps, "gap_id"); paths = self._unique("path", self.paths, "path_id")
        for item in (*nodes.values(), *edges.values(), *gaps.values(), *paths.values()):
            if item.snapshot_id != snapshot:
                raise FlowIRError("flow document contains snapshot mismatch")
        for edge in edges.values():
            if edge.source_node_id not in nodes or edge.target_node_id not in nodes:
                raise FlowIRError("flow edge endpoint does not resolve in document")
        for gap in gaps.values():
            if gap.source_node_id is not None and gap.source_node_id not in nodes:
                raise FlowIRError("flow gap source does not resolve in document")
            if gap.target_node_id is not None and gap.target_node_id not in nodes:
                raise FlowIRError("flow gap target does not resolve in document")
        if set(edges) & set(gaps):
            raise FlowIRError("flow edge and gap IDs must be disjoint")
        for path in paths.values():
            if any(node_id not in nodes for node_id in path.node_ids):
                raise FlowIRError("flow path node does not resolve in document")
            has_gap = False
            for index, segment_id in enumerate(path.segment_ids):
                segment = edges.get(segment_id) or gaps.get(segment_id)
                if segment is None:
                    raise FlowIRError("flow path segment does not resolve in document")
                has_gap |= segment_id in gaps
                if segment.source_node_id != path.node_ids[index] or segment.target_node_id != path.node_ids[index + 1]:
                    raise FlowIRError("flow path segment does not connect adjacent nodes")
            if path.complete and has_gap:
                raise FlowIRError("complete flow path cannot contain a gap")
            if not path.complete and not has_gap:
                raise FlowIRError("incomplete flow path must contain a gap")
        object.__setattr__(self, "snapshot_id", snapshot)
        object.__setattr__(self, "nodes", tuple(sorted(nodes.values(), key=lambda item: item.node_id))); object.__setattr__(self, "edges", tuple(sorted(edges.values(), key=lambda item: item.edge_id))); object.__setattr__(self, "gaps", tuple(sorted(gaps.values(), key=lambda item: item.gap_id))); object.__setattr__(self, "paths", tuple(sorted(paths.values(), key=lambda item: item.path_id)))
        if len(_canonical_json(self.to_dict())) > MAX_FLOW_DOCUMENT_BYTES:
            raise FlowIRError("flow document exceeds serialized size bound")

    @staticmethod
    def _unique(label: str, items: Iterable[Any], attribute: str) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for item in items:
            item_id = getattr(item, attribute)
            if item_id in result:
                raise FlowIRError(f"duplicate flow {label} id: {item_id}")
            result[item_id] = item
        return result

    def to_dict(self) -> dict[str, Any]:
        return {"flow_ir_version": FLOW_IR_VERSION, "program_model_version": pm.PROGRAM_MODEL_VERSION, "snapshot_id": self.snapshot_id, "nodes": [item.to_dict() for item in self.nodes], "edges": [item.to_dict() for item in self.edges], "gaps": [item.to_dict() for item in self.gaps], "paths": [item.to_dict() for item in self.paths], "counts": {"nodes": len(self.nodes), "edges": len(self.edges), "gaps": len(self.gaps), "paths": len(self.paths)}}


def descriptor() -> dict[str, Any]:
    return {"flow_ir_version": FLOW_IR_VERSION, "program_model_version": pm.PROGRAM_MODEL_VERSION, "durable_concepts": ["FlowNode", "FlowEdge", "FlowPath", "FlowGap"], "value_kinds": list(VALUE_KINDS), "semantic_roles": list(SEMANTIC_ROLES), "edge_kinds": list(FLOW_EDGE_KINDS), "gap_kinds": list(FLOW_GAP_KINDS), "calls_xref_are_data_flow": False, "persistent_flow_storage": False, "public_operation_added": False, "raw_constant_values": False, "max_document_bytes": MAX_FLOW_DOCUMENT_BYTES}
