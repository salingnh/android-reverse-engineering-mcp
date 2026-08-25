from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Protocol, Sequence

from ownership_contract import (
    ownership_scope_accepts,
    validate_ownership,
    validate_ownership_scope,
)

PROGRAM_MODEL_VERSION = 1
MAX_SEMANTIC_KEY_CHARS = 4096
MAX_DISPLAY_NAME_CHARS = 2048
MAX_REPRESENTATION_CHARS = 128
MAX_PROPERTY_JSON_BYTES = 32 * 1024
MAX_EVIDENCE_REFS = 128
MAX_EVIDENCE_REF_CHARS = 256
MAX_QUERY_TEXT_CHARS = 512
MAX_PAGE_SIZE = 200
MAX_PROVIDER_PAGE_SIZE = 1000
MAX_QUERY_SECONDS = 10
MAX_CURSOR_BYTES = 4096
MAX_CURSOR_PAYLOAD_BYTES = 2048

ENTITY_KINDS = (
    "APPLICATION",
    "MODULE",
    "FEATURE",
    "COMPONENT",
    "CLASS",
    "FUNCTION",
    "VALUE",
    "ENDPOINT",
    "STORAGE",
    "EXTERNAL_BOUNDARY",
    "EVIDENCE",
)
RELATIONSHIP_KINDS = (
    "DECLARES",
    "CALLS",
    "XREF",
    "CALLS_EXTERNAL",
    "READS",
    "WRITES",
    "PASSES_ARGUMENT",
    "RETURNS",
    "TRANSFORMS",
    "FLOWS_TO",
    "SANITIZES",
    "BINDS_TO_NATIVE",
    "CONFIRMS",
    "CONTRADICTS",
)

ENTITY_PROPERTY_ALLOWLIST: dict[str, frozenset[str]] = {
    "APPLICATION": frozenset({"application_id", "artifact_kind"}),
    "MODULE": frozenset({"module_kind", "uri"}),
    "FEATURE": frozenset({"feature_kind"}),
    "COMPONENT": frozenset({"component_kind", "exported"}),
    "CLASS": frozenset({"qualified_name"}),
    "FUNCTION": frozenset(
        {"signature", "parameter_count", "implementation", "native_offset", "size"}
    ),
    "VALUE": frozenset({"value_kind", "type", "literal_kind"}),
    "ENDPOINT": frozenset({"scheme", "host", "port", "path_pattern", "http_method"}),
    "STORAGE": frozenset({"storage_kind", "name"}),
    "EXTERNAL_BOUNDARY": frozenset({"boundary_kind", "owner", "sdk", "target"}),
    "EVIDENCE": frozenset({"state", "producer"}),
}
RELATIONSHIP_PROPERTY_ALLOWLIST: dict[str, frozenset[str]] = {
    "DECLARES": frozenset(),
    "CALLS": frozenset({"callsite_offset", "dispatch"}),
    "XREF": frozenset({"reference_offset", "reference_kind"}),
    "CALLS_EXTERNAL": frozenset({"callsite_offset", "boundary_kind"}),
    "READS": frozenset({"access_kind"}),
    "WRITES": frozenset({"access_kind"}),
    "PASSES_ARGUMENT": frozenset({"argument_index", "parameter_index"}),
    "RETURNS": frozenset(),
    "TRANSFORMS": frozenset({"transform_kind"}),
    "FLOWS_TO": frozenset(),
    "SANITIZES": frozenset({"sanitizer_kind"}),
    "BINDS_TO_NATIVE": frozenset({"binding_kind"}),
    "CONFIRMS": frozenset(),
    "CONTRADICTS": frozenset(),
}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ProgramModelError(ValueError):
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
        raise ProgramModelError(f"value is not canonical JSON: {exc}") from exc


def _bounded_text(
    value: Any,
    field_name: str,
    limit: int,
    *,
    allow_empty: bool = False,
) -> str:
    text = str(value if value is not None else "").strip()
    if not text and not allow_empty:
        raise ProgramModelError(f"{field_name} must be non-empty")
    if len(text) > limit:
        raise ProgramModelError(f"{field_name} exceeds {limit} characters")
    return text


def _validate_kind(kind: Any, allowed: Sequence[str], field_name: str) -> str:
    value = _bounded_text(kind, field_name, 128).upper()
    if value not in allowed:
        raise ProgramModelError(f"unsupported {field_name}: {value}")
    return value


def _validate_properties(
    kind: str,
    value: dict[str, Any] | None,
    *,
    relationship: bool = False,
) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ProgramModelError("properties must be an object")
    allowlist = (
        RELATIONSHIP_PROPERTY_ALLOWLIST if relationship else ENTITY_PROPERTY_ALLOWLIST
    )[kind]
    unknown = sorted(set(value) - set(allowlist))
    if unknown:
        raise ProgramModelError(
            "properties contain non-canonical fields: " + ", ".join(unknown[:10])
        )
    encoded = _canonical_json(value)
    if len(encoded) > MAX_PROPERTY_JSON_BYTES:
        raise ProgramModelError("properties exceed serialized size bound")
    return json.loads(encoded.decode("utf-8"))


def _validate_evidence_refs(values: Iterable[Any] | None) -> tuple[str, ...]:
    result: set[str] = set()
    for raw in values or ():
        result.add(_bounded_text(raw, "evidence_ref", MAX_EVIDENCE_REF_CHARS))
        if len(result) > MAX_EVIDENCE_REFS:
            raise ProgramModelError("evidence_refs exceed count bound")
    return tuple(sorted(result))


def _hash_parts(*parts: str) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part.encode("utf-8", "replace"))
        digest.update(b"\0")
    return digest.hexdigest()


@dataclass(frozen=True)
class ProgramSnapshot:
    artifact_sha256: str
    artifact_kind: str = "artifact"

    def __post_init__(self) -> None:
        sha = str(self.artifact_sha256 or "").strip().lower()
        if not _SHA256_RE.fullmatch(sha):
            raise ProgramModelError(
                "artifact_sha256 must be 64 lowercase hexadecimal characters"
            )
        object.__setattr__(self, "artifact_sha256", sha)
        object.__setattr__(
            self,
            "artifact_kind",
            _bounded_text(self.artifact_kind, "artifact_kind", 128).lower(),
        )

    @property
    def snapshot_key(self) -> str:
        return f"pm-snapshot:v{PROGRAM_MODEL_VERSION}:{self.artifact_sha256}"

    @property
    def snapshot_id(self) -> str:
        return "pms:" + _hash_parts(self.snapshot_key)


def canonical_semantic_key(value: Any) -> str:
    return _bounded_text(value, "semantic_key", MAX_SEMANTIC_KEY_CHARS)


def entity_id(snapshot: ProgramSnapshot, kind: str, semantic_key: str) -> str:
    normalized_kind = _validate_kind(kind, ENTITY_KINDS, "entity kind")
    key = canonical_semantic_key(semantic_key)
    return (
        f"pm:v{PROGRAM_MODEL_VERSION}:{normalized_kind.lower()}:"
        f"{_hash_parts(snapshot.snapshot_key, normalized_kind, key)}"
    )


def relationship_id(
    snapshot: ProgramSnapshot,
    kind: str,
    source_entity_id: str,
    target_entity_id: str,
    discriminator: str = "",
) -> str:
    normalized_kind = _validate_kind(kind, RELATIONSHIP_KINDS, "relationship kind")
    source = _bounded_text(source_entity_id, "source_entity_id", 256)
    target = _bounded_text(target_entity_id, "target_entity_id", 256)
    disc = _bounded_text(
        discriminator,
        "relationship discriminator",
        1024,
        allow_empty=True,
    )
    return (
        f"pmr:v{PROGRAM_MODEL_VERSION}:{normalized_kind.lower()}:"
        f"{_hash_parts(snapshot.snapshot_key, normalized_kind, source, target, disc)}"
    )


def evidence_id(snapshot: ProgramSnapshot, producer: str, location: dict[str, Any]) -> str:
    producer_name = _bounded_text(producer, "producer", 256)
    encoded = _canonical_json(location)
    if len(encoded) > MAX_PROPERTY_JSON_BYTES:
        raise ProgramModelError("evidence location exceeds size bound")
    return "pme:v1:" + _hash_parts(
        snapshot.snapshot_key,
        producer_name,
        encoded.decode("utf-8"),
    )


@dataclass(frozen=True)
class ProgramEntity:
    snapshot_id: str
    entity_id: str
    semantic_key: str
    kind: str
    display_name: str
    representation: str
    ownership: str = "UNKNOWN"
    properties: dict[str, Any] = field(default_factory=dict)
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        kind = _validate_kind(self.kind, ENTITY_KINDS, "entity kind")
        object.__setattr__(
            self, "snapshot_id", _bounded_text(self.snapshot_id, "snapshot_id", 128)
        )
        object.__setattr__(
            self, "entity_id", _bounded_text(self.entity_id, "entity_id", 256)
        )
        object.__setattr__(self, "semantic_key", canonical_semantic_key(self.semantic_key))
        object.__setattr__(self, "kind", kind)
        object.__setattr__(
            self,
            "display_name",
            _bounded_text(
                self.display_name,
                "display_name",
                MAX_DISPLAY_NAME_CHARS,
                allow_empty=True,
            ),
        )
        object.__setattr__(
            self,
            "representation",
            _bounded_text(
                self.representation,
                "representation",
                MAX_REPRESENTATION_CHARS,
            ).lower(),
        )
        object.__setattr__(self, "ownership", validate_ownership(self.ownership))
        object.__setattr__(self, "properties", _validate_properties(kind, self.properties))
        object.__setattr__(
            self, "evidence_refs", _validate_evidence_refs(self.evidence_refs)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "semantic_key": self.semantic_key,
            "kind": self.kind,
            "display_name": self.display_name,
            "representation": self.representation,
            "ownership": self.ownership,
            "properties": dict(self.properties),
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class ProgramRelationship:
    snapshot_id: str
    relationship_id: str
    kind: str
    source_entity_id: str
    target_entity_id: str
    representation: str
    properties: dict[str, Any] = field(default_factory=dict)
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        kind = _validate_kind(self.kind, RELATIONSHIP_KINDS, "relationship kind")
        object.__setattr__(
            self, "snapshot_id", _bounded_text(self.snapshot_id, "snapshot_id", 128)
        )
        object.__setattr__(
            self,
            "relationship_id",
            _bounded_text(self.relationship_id, "relationship_id", 256),
        )
        object.__setattr__(self, "kind", kind)
        object.__setattr__(
            self,
            "source_entity_id",
            _bounded_text(self.source_entity_id, "source_entity_id", 256),
        )
        object.__setattr__(
            self,
            "target_entity_id",
            _bounded_text(self.target_entity_id, "target_entity_id", 256),
        )
        object.__setattr__(
            self,
            "representation",
            _bounded_text(
                self.representation,
                "representation",
                MAX_REPRESENTATION_CHARS,
            ).lower(),
        )
        object.__setattr__(
            self,
            "properties",
            _validate_properties(kind, self.properties, relationship=True),
        )
        object.__setattr__(
            self, "evidence_refs", _validate_evidence_refs(self.evidence_refs)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "relationship_id": self.relationship_id,
            "kind": self.kind,
            "source_entity_id": self.source_entity_id,
            "target_entity_id": self.target_entity_id,
            "representation": self.representation,
            "properties": dict(self.properties),
            "evidence_refs": list(self.evidence_refs),
        }


def merge_entity(left: ProgramEntity, right: ProgramEntity) -> ProgramEntity:
    if left.snapshot_id != right.snapshot_id or left.entity_id != right.entity_id:
        raise ProgramModelError("cannot merge different entities")
    if (
        left.semantic_key != right.semantic_key
        or left.kind != right.kind
        or left.representation != right.representation
    ):
        raise ProgramModelError("entity identity fields disagree")
    display_name = min((left.display_name, right.display_name), key=lambda value: (not bool(value), value))
    if left.ownership == right.ownership:
        ownership = left.ownership
    elif left.ownership == "UNKNOWN":
        ownership = right.ownership
    elif right.ownership == "UNKNOWN":
        ownership = left.ownership
    else:
        ownership = "UNKNOWN"
    properties: dict[str, Any] = {}
    for key in sorted(set(left.properties) | set(right.properties)):
        if key in left.properties and key in right.properties:
            if left.properties[key] == right.properties[key]:
                properties[key] = left.properties[key]
        elif key in left.properties:
            properties[key] = left.properties[key]
        else:
            properties[key] = right.properties[key]
    return ProgramEntity(
        left.snapshot_id,
        left.entity_id,
        left.semantic_key,
        left.kind,
        display_name,
        left.representation,
        ownership,
        properties,
        tuple(sorted(set(left.evidence_refs) | set(right.evidence_refs))),
    )


def merge_relationship(
    left: ProgramRelationship,
    right: ProgramRelationship,
) -> ProgramRelationship:
    if (
        left.snapshot_id != right.snapshot_id
        or left.relationship_id != right.relationship_id
    ):
        raise ProgramModelError("cannot merge different relationships")
    if (
        left.kind != right.kind
        or left.source_entity_id != right.source_entity_id
        or left.target_entity_id != right.target_entity_id
        or left.representation != right.representation
    ):
        raise ProgramModelError("relationship identity fields disagree")
    properties: dict[str, Any] = {}
    for key in sorted(set(left.properties) | set(right.properties)):
        if key in left.properties and key in right.properties:
            if left.properties[key] == right.properties[key]:
                properties[key] = left.properties[key]
        elif key in left.properties:
            properties[key] = left.properties[key]
        else:
            properties[key] = right.properties[key]
    return ProgramRelationship(
        left.snapshot_id,
        left.relationship_id,
        left.kind,
        left.source_entity_id,
        left.target_entity_id,
        left.representation,
        properties,
        tuple(sorted(set(left.evidence_refs) | set(right.evidence_refs))),
    )


def entity_sort_key(item: ProgramEntity) -> tuple[str, str, str, str]:
    return (item.kind, item.semantic_key, item.representation, item.entity_id)


def relationship_sort_key(item: ProgramRelationship) -> tuple[str, str, str, str]:
    return (
        item.kind,
        item.source_entity_id,
        item.target_entity_id,
        item.relationship_id,
    )


@dataclass(frozen=True)
class ProviderPage:
    items: tuple[Any, ...]
    has_more: bool = False
    truncated: bool = False

    def __post_init__(self) -> None:
        if len(self.items) > MAX_PROVIDER_PAGE_SIZE:
            raise ProgramModelError("provider page exceeds size bound")


@dataclass(frozen=True)
class ProgramPage:
    items: tuple[Any, ...]
    returned_count: int
    total_count: int | None
    truncated: bool
    has_more: bool
    cursor: str | None
    limits: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "items": [
                item.to_dict() if hasattr(item, "to_dict") else item
                for item in self.items
            ],
            "returned_count": self.returned_count,
            "total_count": self.total_count,
            "truncated": self.truncated,
            "has_more": self.has_more,
            "cursor": self.cursor,
            "limits": dict(self.limits),
        }


class ProgramProvider(Protocol):
    @property
    def snapshot(self) -> ProgramSnapshot: ...

    def get_entity(self, entity_id: str) -> ProgramEntity | None: ...

    def query_entities(
        self,
        *,
        kind: str | None = None,
        text: str | None = None,
        ownership_scope: str = "application",
        representation: str | None = None,
        after: tuple[str, str, str, str] | None = None,
        limit: int = MAX_PAGE_SIZE,
    ) -> ProviderPage: ...

    def query_relationships(
        self,
        *,
        entity_id: str,
        kinds: frozenset[str] | None = None,
        direction: str = "both",
        ownership_scope: str = "application",
        after: tuple[str, str, str, str] | None = None,
        limit: int = MAX_PAGE_SIZE,
    ) -> ProviderPage: ...

    def get_evidence(self, evidence_ref: str) -> dict[str, Any] | None: ...


def _query_fingerprint(payload: dict[str, Any]) -> str:
    return _hash_parts(_canonical_json(payload).decode("utf-8"))


def _encode_cursor(payload: dict[str, Any]) -> str:
    raw = _canonical_json(payload)
    if len(raw) > MAX_CURSOR_PAYLOAD_BYTES:
        raise ProgramModelError("cursor payload exceeds size bound")
    envelope = {"p": payload, "c": hashlib.sha256(raw).hexdigest()[:32]}
    encoded = base64.urlsafe_b64encode(_canonical_json(envelope)).rstrip(b"=").decode("ascii")
    if len(encoded) > MAX_CURSOR_BYTES:
        raise ProgramModelError("cursor exceeds size bound")
    return encoded


def _decode_cursor(cursor: str) -> dict[str, Any]:
    token = _bounded_text(cursor, "cursor", MAX_CURSOR_BYTES)
    try:
        padded = token + "=" * ((4 - len(token) % 4) % 4)
        envelope = json.loads(
            base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        )
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProgramModelError("cursor is invalid") from exc
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"p", "c"}
        or not isinstance(envelope["p"], dict)
    ):
        raise ProgramModelError("cursor is invalid")
    canonical = _canonical_json(envelope["p"])
    if envelope.get("c") != hashlib.sha256(canonical).hexdigest()[:32]:
        raise ProgramModelError("cursor checksum mismatch")
    if len(canonical) > MAX_CURSOR_PAYLOAD_BYTES:
        raise ProgramModelError("cursor payload exceeds size bound")
    return envelope["p"]


def _cursor_after(
    cursor: str | None,
    *,
    snapshot_id: str,
    fingerprint: str,
) -> tuple[str, str, str, str] | None:
    if not cursor:
        return None
    payload = _decode_cursor(cursor)
    if (
        payload.get("v") != PROGRAM_MODEL_VERSION
        or payload.get("s") != snapshot_id
        or payload.get("q") != fingerprint
    ):
        raise ProgramModelError(
            "cursor belongs to another snapshot, query, or Program Model version"
        )
    last = payload.get("a")
    if (
        not isinstance(last, list)
        or len(last) != 4
        or not all(isinstance(value, str) for value in last)
    ):
        raise ProgramModelError("cursor position is invalid")
    return tuple(last)


class ProgramRepository:
    def __init__(self, providers: Sequence[ProgramProvider]) -> None:
        if not providers:
            raise ProgramModelError("program repository requires at least one provider")
        snapshot = providers[0].snapshot
        for provider in providers[1:]:
            if provider.snapshot.snapshot_id != snapshot.snapshot_id:
                raise ProgramModelError(
                    "providers belong to different Program Snapshots; "
                    "explicit lineage/correlation is required"
                )
        self.providers = tuple(providers)
        self.snapshot = snapshot

    def get_entity(self, entity_id_value: str) -> ProgramEntity | None:
        identifier = _bounded_text(entity_id_value, "entity_id", 256)
        merged: ProgramEntity | None = None
        for provider in self.providers:
            item = provider.get_entity(identifier)
            if item is None:
                continue
            if item.snapshot_id != self.snapshot.snapshot_id:
                raise ProgramModelError("provider returned a foreign-snapshot entity")
            merged = item if merged is None else merge_entity(merged, item)
        return merged

    def find_entities(
        self,
        *,
        kind: str | None = None,
        text: str | None = None,
        ownership_scope: str = "application",
        representation: str | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> ProgramPage:
        started = time.monotonic()
        normalized_kind = (
            _validate_kind(kind, ENTITY_KINDS, "entity kind") if kind else None
        )
        normalized_text = (
            _bounded_text(text, "query text", MAX_QUERY_TEXT_CHARS)
            if text is not None
            else None
        )
        normalized_scope = validate_ownership_scope(ownership_scope)
        normalized_representation = (
            _bounded_text(
                representation,
                "representation",
                MAX_REPRESENTATION_CHARS,
            ).lower()
            if representation
            else None
        )
        page_size = max(1, min(int(limit), MAX_PAGE_SIZE))
        query_shape = {
            "op": "find_entities",
            "kind": normalized_kind,
            "text": normalized_text,
            "ownership_scope": normalized_scope,
            "representation": normalized_representation,
        }
        fingerprint = _query_fingerprint(query_shape)
        after = _cursor_after(
            cursor,
            snapshot_id=self.snapshot.snapshot_id,
            fingerprint=fingerprint,
        )
        provider_limit = min(MAX_PROVIDER_PAGE_SIZE, page_size + 1)
        merged: dict[str, ProgramEntity] = {}
        provider_has_more = False
        truncated = False

        for provider in self.providers:
            if time.monotonic() - started >= MAX_QUERY_SECONDS:
                truncated = True
                break
            page = provider.query_entities(
                kind=normalized_kind,
                text=normalized_text,
                ownership_scope=normalized_scope,
                representation=normalized_representation,
                after=after,
                limit=provider_limit,
            )
            provider_has_more = provider_has_more or page.has_more
            truncated = truncated or page.truncated
            previous_key: tuple[str, str, str, str] | None = None
            for item in page.items:
                if item.snapshot_id != self.snapshot.snapshot_id:
                    raise ProgramModelError("provider returned a foreign-snapshot entity")
                if not ownership_scope_accepts(item.ownership, normalized_scope):
                    continue
                if normalized_kind and item.kind != normalized_kind:
                    continue
                if normalized_representation and item.representation != normalized_representation:
                    continue
                key = entity_sort_key(item)
                if after is not None and key <= after:
                    raise ProgramModelError("provider returned an entity before continuation")
                if previous_key is not None and key < previous_key:
                    raise ProgramModelError("provider entity page is not deterministically ordered")
                previous_key = key
                current = merged.get(item.entity_id)
                merged[item.entity_id] = item if current is None else merge_entity(current, item)

        ordered = sorted(merged.values(), key=entity_sort_key)
        has_more = len(ordered) > page_size or provider_has_more or truncated
        selected = ordered[:page_size]
        next_cursor = (
            _encode_cursor(
                {
                    "v": PROGRAM_MODEL_VERSION,
                    "s": self.snapshot.snapshot_id,
                    "q": fingerprint,
                    "a": list(entity_sort_key(selected[-1])),
                }
            )
            if has_more and selected
            else None
        )
        return ProgramPage(
            tuple(selected),
            len(selected),
            None,
            truncated,
            has_more,
            next_cursor,
            {
                "page_size": page_size,
                "provider_page_size": provider_limit,
                "wall_clock_seconds": MAX_QUERY_SECONDS,
            },
        )

    def find_relationships(
        self,
        *,
        entity_id: str,
        kinds: Iterable[str] | None = None,
        direction: str = "both",
        ownership_scope: str = "application",
        limit: int = 100,
        cursor: str | None = None,
    ) -> ProgramPage:
        started = time.monotonic()
        identifier = _bounded_text(entity_id, "entity_id", 256)
        normalized_direction = str(direction or "both").lower()
        if normalized_direction not in {"incoming", "outgoing", "both"}:
            raise ProgramModelError("direction must be incoming, outgoing, or both")
        normalized_kinds = (
            frozenset(
                _validate_kind(value, RELATIONSHIP_KINDS, "relationship kind")
                for value in kinds
            )
            if kinds is not None
            else None
        )
        if normalized_kinds is not None and not normalized_kinds:
            raise ProgramModelError("relationship kinds must not be empty")
        normalized_scope = validate_ownership_scope(ownership_scope)
        page_size = max(1, min(int(limit), MAX_PAGE_SIZE))
        query_shape = {
            "op": "find_relationships",
            "entity_id": identifier,
            "kinds": sorted(normalized_kinds) if normalized_kinds else None,
            "direction": normalized_direction,
            "ownership_scope": normalized_scope,
        }
        fingerprint = _query_fingerprint(query_shape)
        after = _cursor_after(
            cursor,
            snapshot_id=self.snapshot.snapshot_id,
            fingerprint=fingerprint,
        )
        provider_limit = min(MAX_PROVIDER_PAGE_SIZE, page_size + 1)
        merged: dict[str, ProgramRelationship] = {}
        provider_has_more = False
        truncated = False

        for provider in self.providers:
            if time.monotonic() - started >= MAX_QUERY_SECONDS:
                truncated = True
                break
            page = provider.query_relationships(
                entity_id=identifier,
                kinds=normalized_kinds,
                direction=normalized_direction,
                ownership_scope=normalized_scope,
                after=after,
                limit=provider_limit,
            )
            provider_has_more = provider_has_more or page.has_more
            truncated = truncated or page.truncated
            previous_key: tuple[str, str, str, str] | None = None
            for item in page.items:
                if item.snapshot_id != self.snapshot.snapshot_id:
                    raise ProgramModelError(
                        "provider returned a foreign-snapshot relationship"
                    )
                if normalized_kinds and item.kind not in normalized_kinds:
                    continue
                if (
                    normalized_direction == "incoming"
                    and item.target_entity_id != identifier
                ):
                    continue
                if (
                    normalized_direction == "outgoing"
                    and item.source_entity_id != identifier
                ):
                    continue
                if (
                    normalized_direction == "both"
                    and identifier
                    not in {item.source_entity_id, item.target_entity_id}
                ):
                    continue
                key = relationship_sort_key(item)
                if after is not None and key <= after:
                    raise ProgramModelError(
                        "provider returned a relationship before continuation"
                    )
                if previous_key is not None and key < previous_key:
                    raise ProgramModelError(
                        "provider relationship page is not deterministically ordered"
                    )
                previous_key = key
                current = merged.get(item.relationship_id)
                merged[item.relationship_id] = (
                    item if current is None else merge_relationship(current, item)
                )

        ordered = sorted(merged.values(), key=relationship_sort_key)
        has_more = len(ordered) > page_size or provider_has_more or truncated
        selected = ordered[:page_size]
        next_cursor = (
            _encode_cursor(
                {
                    "v": PROGRAM_MODEL_VERSION,
                    "s": self.snapshot.snapshot_id,
                    "q": fingerprint,
                    "a": list(relationship_sort_key(selected[-1])),
                }
            )
            if has_more and selected
            else None
        )
        return ProgramPage(
            tuple(selected),
            len(selected),
            None,
            truncated,
            has_more,
            next_cursor,
            {
                "page_size": page_size,
                "provider_page_size": provider_limit,
                "wall_clock_seconds": MAX_QUERY_SECONDS,
            },
        )

    def get_evidence(self, evidence_refs: Iterable[str]) -> tuple[dict[str, Any], ...]:
        refs = _validate_evidence_refs(evidence_refs)
        results: list[dict[str, Any]] = []
        for ref in refs:
            found = None
            for provider in self.providers:
                found = provider.get_evidence(ref)
                if found is not None:
                    break
            if found is not None:
                encoded = _canonical_json(found)
                if len(encoded) > MAX_PROPERTY_JSON_BYTES:
                    raise ProgramModelError("evidence record exceeds size bound")
                results.append(json.loads(encoded.decode("utf-8")))
        return tuple(results)


def descriptor() -> dict[str, Any]:
    return {
        "program_model_version": PROGRAM_MODEL_VERSION,
        "entity_kinds": list(ENTITY_KINDS),
        "relationship_kinds": list(RELATIONSHIP_KINDS),
        "private_index_contract": True,
        "generic_public_query_surface": False,
        "calls_xref_are_data_flow": False,
        "provider_continuation": True,
        "pagination": {
            "max_page_size": MAX_PAGE_SIZE,
            "cursor_snapshot_bound": True,
            "cursor_query_bound": True,
            "provider_after_key": True,
            "explicit_truncation": True,
        },
    }
