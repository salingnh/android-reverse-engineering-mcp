from __future__ import annotations

import hashlib
import json
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
    "PARAMETER",
    "ARGUMENT",
    "RETURN",
    "CONSTANT",
    "LOCAL",
    "FIELD",
    "STORAGE",
    "UNKNOWN",
)
SEMANTIC_ROLES = (
    "SOURCE",
    "SINK",
    "SANITIZER",
    "TRANSFORMATION",
)
FLOW_EDGE_KINDS = (
    "ASSIGNMENT",
    "ARGUMENT_TO_PARAMETER",
    "RETURN_TO_CALLSITE",
    "FIELD_WRITE",
    "FIELD_READ",
    "CONSTANT_TO_VALUE",
    "TRANSFORMS",
    "FLOWS_TO",
    "SANITIZES",
)
FLOW_GAP_KINDS = (
    "REFLECTION",
    "NATIVE",
    "DYNAMIC_DISPATCH",
    "UNSUPPORTED_INSTRUCTION",
    "EXTERNAL_BOUNDARY",
    "MISSING_EVIDENCE",
    "BUDGET",
    "UNKNOWN",
)

NODE_PROPERTY_ALLOWLIST: dict[str, frozenset[str]] = {
    "PARAMETER": frozenset({"parameter_index", "type"}),
    "ARGUMENT": frozenset({"argument_index", "type"}),
    "RETURN": frozenset({"type"}),
    "CONSTANT": frozenset({"literal_kind", "type", "value_fingerprint"}),
    "LOCAL": frozenset({"slot", "name", "type"}),
    "FIELD": frozenset({"field_name", "type", "static"}),
    "STORAGE": frozenset({"storage_kind", "name"}),
    "UNKNOWN": frozenset({"type"}),
}
EDGE_PROPERTY_ALLOWLIST: dict[str, frozenset[str]] = {
    "ASSIGNMENT": frozenset({"statement_offset"}),
    "ARGUMENT_TO_PARAMETER": frozenset(
        {"argument_index", "parameter_index", "callsite_offset"}
    ),
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
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise FlowIRError(f"value is not canonical JSON: {exc}") from exc


def _bounded_text(
    value: Any,
    field_name: str,
    limit: int,
    *,
    allow_empty: bool = False,
) -> str:
    text = str(value if value is not None else "").strip()
    if not text and not allow_empty:
        raise FlowIRError(f"{field_name} must be non-empty")
    if len(text) > limit:
        raise FlowIRError(f"{field_name} exceeds {limit} characters")
    return text


def _optional_text(value: Any, field_name: str, limit: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) > limit:
        raise FlowIRError(f"{field_name} exceeds {limit} characters")
    return text


def _enum(value: Any, allowed: tuple[str, ...], field_name: str) -> str:
    text = _bounded_text(value, field_name, 128).upper()
    if text not in allowed:
        raise FlowIRError(f"unsupported {field_name}: {text}")
    return text


def _validate_evidence_refs(values: Iterable[Any] | None) -> tuple[str, ...]:
    refs: set[str] = set()
    for raw in values or ():
        refs.add(_bounded_text(raw, "evidence_ref", MAX_EVIDENCE_REF_CHARS))
        if len(refs) > MAX_EVIDENCE_REFS:
            raise FlowIRError("evidence_refs exceed count bound")
    return tuple(sorted(refs))


def _validate_properties(
    value: dict[str, Any] | None,
    *,
    allowlist: frozenset[str],
) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise FlowIRError("properties must be an object")
    unknown = sorted(set(value) - set(allowlist))
    if unknown:
        raise FlowIRError(
            "properties contain non-canonical fields: " + ", ".join(unknown[:10])
        )
    encoded = _canonical_json(value)
    if len(encoded) > MAX_PROPERTY_JSON_BYTES:
        raise FlowIRError("properties exceed serialized size bound")
    return json.loads(encoded.decode("utf-8"))


def _hash_parts(*parts: str) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part.encode("utf-8", "replace"))
        digest.update(b"\0")
    return digest.hexdigest()


def flow_node_id(
    snapshot_id: str,
    value_kind: str,
    owner_entity_id: str,
    semantic_key: str,
) -> str:
    snapshot = _bounded_text(snapshot_id, "snapshot_id", 128)
    kind = _enum(value_kind, VALUE_KINDS, "value kind")
    owner = _bounded_text(owner_entity_id, "owner_entity_id", 256)
    key = _bounded_text(semantic_key, "semantic_key", MAX_SEMANTIC_KEY_CHARS)
    return f"flown:v{FLOW_IR_VERSION}:{kind.lower()}:{_hash_parts(snapshot, kind, owner, key)}"


def flow_edge_id(
    snapshot_id: str,
    kind: str,
    source_node_id: str,
    target_node_id: str,
) -> str:
    snapshot = _bounded_text(snapshot_id, "snapshot_id", 128)
    edge_kind = _enum(kind, FLOW_EDGE_KINDS, "flow edge kind")
    source = _bounded_text(source_node_id, "source_node_id", 256)
    target = _bounded_text(target_node_id, "target_node_id", 256)
    return f"flowe:v{FLOW_IR_VERSION}:{edge_kind.lower()}:{_hash_parts(snapshot, edge_kind, source, target)}"


def flow_gap_id(
    snapshot_id: str,
    kind: str,
    owner_entity_id: str,
    source_node_id: str | None = None,
    target_node_id: str | None = None,
) -> str:
    snapshot = _bounded_text(snapshot_id, "snapshot_id", 128)
    gap_kind = _enum(kind, FLOW_GAP_KINDS, "flow gap kind")
    owner = _bounded_text(owner_entity_id, "owner_entity_id", 256)
    source = _optional_text(source_node_id, "source_node_id", 256) or ""
    target = _optional_text(target_node_id, "target_node_id", 256) or ""
    return f"flowg:v{FLOW_IR_VERSION}:{gap_kind.lower()}:{_hash_parts(snapshot, gap_kind, owner, source, target)}"


def flow_path_id(
    snapshot_id: str,
    node_ids: Iterable[str],
    segment_ids: Iterable[str],
) -> str:
    snapshot = _bounded_text(snapshot_id, "snapshot_id", 128)
    nodes = tuple(_bounded_text(item, "node_id", 256) for item in node_ids)
    segments = tuple(_bounded_text(item, "segment_id", 256) for item in segment_ids)
    if not nodes:
        raise FlowIRError("flow path must contain at least one node")
    return f"flowp:v{FLOW_IR_VERSION}:{_hash_parts(snapshot, *nodes, 'segments', *segments)}"


@dataclass(frozen=True)
class FlowNode:
    snapshot_id: str
    node_id: str
    semantic_key: str
    value_kind: str
    owner_entity_id: str
    representation: str
    program_entity_id: str | None = None
    roles: tuple[str, ...] = field(default_factory=tuple)
    label: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        kind = _enum(self.value_kind, VALUE_KINDS, "value kind")
        roles = tuple(
            sorted({_enum(item, SEMANTIC_ROLES, "semantic role") for item in self.roles})
        )
        object.__setattr__(self, "snapshot_id", _bounded_text(self.snapshot_id, "snapshot_id", 128))
        object.__setattr__(self, "node_id", _bounded_text(self.node_id, "node_id", 256))
        object.__setattr__(
            self,
            "semantic_key",
            _bounded_text(self.semantic_key, "semantic_key", MAX_SEMANTIC_KEY_CHARS),
        )
        object.__setattr__(self, "value_kind", kind)
        object.__setattr__(
            self,
            "owner_entity_id",
            _bounded_text(self.owner_entity_id, "owner_entity_id", 256),
        )
        object.__setattr__(
            self,
            "representation",
            _bounded_text(
                self.representation,
                "representation",
                pm.MAX_REPRESENTATION_CHARS,
            ).lower(),
        )
        object.__setattr__(
            self,
            "program_entity_id",
            _optional_text(self.program_entity_id, "program_entity_id", 256),
        )
        object.__setattr__(self, "roles", roles)
        object.__setattr__(
            self,
            "label",
            _bounded_text(self.label, "label", MAX_TEXT_CHARS, allow_empty=True),
        )
        object.__setattr__(
            self,
            "properties",
            _validate_properties(
                self.properties,
                allowlist=NODE_PROPERTY_ALLOWLIST[kind],
            ),
        )
        object.__setattr__(
            self, "evidence_refs", _validate_evidence_refs(self.evidence_refs)
        )
        expected = flow_node_id(
            self.snapshot_id,
            self.value_kind,
            self.owner_entity_id,
            self.semantic_key,
        )
        if self.node_id != expected:
            raise FlowIRError("flow node id does not match canonical identity")

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "semantic_key": self.semantic_key,
            "value_kind": self.value_kind,
            "owner_entity_id": self.owner_entity_id,
            "program_entity_id": self.program_entity_id,
            "representation": self.representation,
            "roles": list(self.roles),
            "label": self.label,
            "properties": dict(self.properties),
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class FlowEdge:
    snapshot_id: str
    edge_id: str
    kind: str
    source_node_id: str
    target_node_id: str
    representation: str
    producer: str
    properties: dict[str, Any] = field(default_factory=dict)
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        kind = _enum(self.kind, FLOW_EDGE_KINDS, "flow edge kind")
        object.__setattr__(self, "snapshot_id", _bounded_text(self.snapshot_id, "snapshot_id", 128))
        object.__setattr__(self, "edge_id", _bounded_text(self.edge_id, "edge_id", 256))
        object.__setattr__(self, "kind", kind)
        object.__setattr__(
            self,
            "source_node_id",
            _bounded_text(self.source_node_id, "source_node_id", 256),
        )
        object.__setattr__(
            self,
            "target_node_id",
            _bounded_text(self.target_node_id, "target_node_id", 256),
        )
        object.__setattr__(
            self,
            "representation",
            _bounded_text(
                self.representation,
                "representation",
                pm.MAX_REPRESENTATION_CHARS,
            ).lower(),
        )
        object.__setattr__(
            self, "producer", _bounded_text(self.producer, "producer", 256)
        )
        object.__setattr__(
            self,
            "properties",
            _validate_properties(
                self.properties,
                allowlist=EDGE_PROPERTY_ALLOWLIST[kind],
            ),
        )
        object.__setattr__(
            self, "evidence_refs", _validate_evidence_refs(self.evidence_refs)
        )
        expected = flow_edge_id(
            self.snapshot_id,
            self.kind,
            self.source_node_id,
            self.target_node_id,
        )
        if self.edge_id != expected:
            raise FlowIRError("flow edge id does not match canonical identity")

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "kind": self.kind,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "representation": self.representation,
            "producer": self.producer,
            "properties": dict(self.properties),
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class FlowGap:
    snapshot_id: str
    gap_id: str
    kind: str
    owner_entity_id: str
    representation: str
    producer: str
    source_node_id: str | None = None
    target_node_id: str | None = None
    reason: str = ""
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "snapshot_id", _bounded_text(self.snapshot_id, "snapshot_id", 128)
        )
        object.__setattr__(self, "gap_id", _bounded_text(self.gap_id, "gap_id", 256))
        object.__setattr__(
            self, "kind", _enum(self.kind, FLOW_GAP_KINDS, "flow gap kind")
        )
        object.__setattr__(
            self,
            "owner_entity_id",
            _bounded_text(self.owner_entity_id, "owner_entity_id", 256),
        )
        object.__setattr__(
            self,
            "representation",
            _bounded_text(
                self.representation,
                "representation",
                pm.MAX_REPRESENTATION_CHARS,
            ).lower(),
        )
        object.__setattr__(
            self, "producer", _bounded_text(self.producer, "producer", 256)
        )
        object.__setattr__(
            self,
            "source_node_id",
            _optional_text(self.source_node_id, "source_node_id", 256),
        )
        object.__setattr__(
            self,
            "target_node_id",
            _optional_text(self.target_node_id, "target_node_id", 256),
        )
        object.__setattr__(
            self,
            "reason",
            _bounded_text(self.reason, "reason", MAX_TEXT_CHARS, allow_empty=True),
        )
        object.__setattr__(
            self, "evidence_refs", _validate_evidence_refs(self.evidence_refs)
        )
        if self.source_node_id is None and self.target_node_id is None:
            raise FlowIRError("flow gap must anchor at least one known node")
        expected = flow_gap_id(
            self.snapshot_id,
            self.kind,
            self.owner_entity_id,
            self.source_node_id,
            self.target_node_id,
        )
        if self.gap_id != expected:
            raise FlowIRError("flow gap id does not match canonical identity")

    def to_dict(self) -> dict[str, Any]:
        return {
            "gap_id": self.gap_id,
            "kind": self.kind,
            "owner_entity_id": self.owner_entity_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "representation": self.representation,
            "producer": self.producer,
            "reason": self.reason,
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class FlowPath:
    snapshot_id: str
    path_id: str
    node_ids: tuple[str, ...]
    segment_ids: tuple[str, ...]
    complete: bool

    def __post_init__(self) -> None:
        snapshot = _bounded_text(self.snapshot_id, "snapshot_id", 128)
        path = _bounded_text(self.path_id, "path_id", 256)
        nodes = tuple(_bounded_text(item, "node_id", 256) for item in self.node_ids)
        segments = tuple(
            _bounded_text(item, "segment_id", 256) for item in self.segment_ids
        )
        if not nodes:
            raise FlowIRError("flow path must contain at least one node")
        if len(nodes) > MAX_PATH_NODES:
            raise FlowIRError("flow path exceeds node count bound")
        if len(segments) != len(nodes) - 1:
            raise FlowIRError(
                "flow path must have exactly one segment per adjacent node pair"
            )
        object.__setattr__(self, "snapshot_id", snapshot)
        object.__setattr__(self, "path_id", path)
        object.__setattr__(self, "node_ids", nodes)
        object.__setattr__(self, "segment_ids", segments)
        object.__setattr__(self, "complete", bool(self.complete))
        expected = flow_path_id(self.snapshot_id, self.node_ids, self.segment_ids)
        if self.path_id != expected:
            raise FlowIRError("flow path id does not match canonical identity")

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_id": self.path_id,
            "node_ids": list(self.node_ids),
            "segment_ids": list(self.segment_ids),
            "complete": self.complete,
        }


@dataclass(frozen=True)
class FlowDocument:
    snapshot_id: str
    nodes: tuple[FlowNode, ...] = field(default_factory=tuple)
    edges: tuple[FlowEdge, ...] = field(default_factory=tuple)
    gaps: tuple[FlowGap, ...] = field(default_factory=tuple)
    paths: tuple[FlowPath, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        snapshot = _bounded_text(self.snapshot_id, "snapshot_id", 128)
        if len(self.nodes) > MAX_FLOW_NODES:
            raise FlowIRError("flow document exceeds node count bound")
        if len(self.edges) > MAX_FLOW_EDGES:
            raise FlowIRError("flow document exceeds edge count bound")
        if len(self.gaps) > MAX_FLOW_GAPS:
            raise FlowIRError("flow document exceeds gap count bound")
        if len(self.paths) > MAX_FLOW_PATHS:
            raise FlowIRError("flow document exceeds path count bound")

        nodes = self._unique("node", self.nodes, lambda item: item.node_id)
        edges = self._unique("edge", self.edges, lambda item: item.edge_id)
        gaps = self._unique("gap", self.gaps, lambda item: item.gap_id)
        paths = self._unique("path", self.paths, lambda item: item.path_id)
        for collection in (nodes.values(), edges.values(), gaps.values(), paths.values()):
            for item in collection:
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

        segment_ids = set(edges) | set(gaps)
        if set(edges) & set(gaps):
            raise FlowIRError("flow edge and gap IDs must be disjoint")
        for path in paths.values():
            for node_id in path.node_ids:
                if node_id not in nodes:
                    raise FlowIRError("flow path node does not resolve in document")
            if any(segment_id not in segment_ids for segment_id in path.segment_ids):
                raise FlowIRError("flow path segment does not resolve in document")
            has_gap = False
            for index, segment_id in enumerate(path.segment_ids):
                source_id = path.node_ids[index]
                target_id = path.node_ids[index + 1]
                if segment_id in edges:
                    segment = edges[segment_id]
                else:
                    has_gap = True
                    segment = gaps[segment_id]
                if (
                    segment.source_node_id != source_id
                    or segment.target_node_id != target_id
                ):
                    raise FlowIRError(
                        "flow path segment does not connect adjacent nodes"
                    )
            if path.complete and has_gap:
                raise FlowIRError("complete flow path cannot contain a gap")
            if not path.complete and not has_gap:
                raise FlowIRError("incomplete flow path must contain a gap")

        object.__setattr__(self, "snapshot_id", snapshot)
        object.__setattr__(
            self,
            "nodes",
            tuple(sorted(nodes.values(), key=lambda item: item.node_id)),
        )
        object.__setattr__(
            self,
            "edges",
            tuple(sorted(edges.values(), key=lambda item: item.edge_id)),
        )
        object.__setattr__(
            self,
            "gaps",
            tuple(sorted(gaps.values(), key=lambda item: item.gap_id)),
        )
        object.__setattr__(
            self,
            "paths",
            tuple(sorted(paths.values(), key=lambda item: item.path_id)),
        )
        encoded = _canonical_json(self.to_dict())
        if len(encoded) > MAX_FLOW_DOCUMENT_BYTES:
            raise FlowIRError("flow document exceeds serialized size bound")

    @staticmethod
    def _unique(label: str, items: Iterable[Any], key) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for item in items:
            item_id = key(item)
            if item_id in result:
                raise FlowIRError(f"duplicate flow {label} id: {item_id}")
            result[item_id] = item
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_ir_version": FLOW_IR_VERSION,
            "program_model_version": pm.PROGRAM_MODEL_VERSION,
            "snapshot_id": self.snapshot_id,
            "nodes": [item.to_dict() for item in self.nodes],
            "edges": [item.to_dict() for item in self.edges],
            "gaps": [item.to_dict() for item in self.gaps],
            "paths": [item.to_dict() for item in self.paths],
            "counts": {
                "nodes": len(self.nodes),
                "edges": len(self.edges),
                "gaps": len(self.gaps),
                "paths": len(self.paths),
            },
        }


def descriptor() -> dict[str, Any]:
    return {
        "flow_ir_version": FLOW_IR_VERSION,
        "program_model_version": pm.PROGRAM_MODEL_VERSION,
        "durable_concepts": ["FlowNode", "FlowEdge", "FlowPath", "FlowGap"],
        "value_kinds": list(VALUE_KINDS),
        "semantic_roles": list(SEMANTIC_ROLES),
        "edge_kinds": list(FLOW_EDGE_KINDS),
        "gap_kinds": list(FLOW_GAP_KINDS),
        "calls_xref_are_data_flow": False,
        "persistent_flow_storage": False,
        "public_operation_added": False,
        "max_document_bytes": MAX_FLOW_DOCUMENT_BYTES,
    }
