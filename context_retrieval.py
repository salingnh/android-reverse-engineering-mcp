from __future__ import annotations

import json
import time
from typing import Any, Iterable, Protocol

import program_model as pm
from ownership_contract import ownership_scope_accepts, validate_ownership_scope

CONTEXT_RETRIEVAL_VERSION = 1
DEFAULT_RELATIONSHIP_LIMIT = 32
MAX_RELATIONSHIP_LIMIT = 120
DEFAULT_EVIDENCE_LIMIT = 12
MAX_EVIDENCE_LIMIT = 32
DEFAULT_SOURCE_LINE_LIMIT = 120
MAX_SOURCE_LINE_LIMIT = 400
DEFAULT_SOURCE_BYTE_LIMIT = 16 * 1024
MAX_SOURCE_BYTE_LIMIT = 64 * 1024
DEFAULT_RESPONSE_BUDGET_BYTES = 64 * 1024
MIN_RESPONSE_BUDGET_BYTES = 32 * 1024
MAX_RESPONSE_BUDGET_BYTES = 256 * 1024
MAX_STRUCTURAL_DEPTH = 3
MAX_STRUCTURAL_RELATIONSHIPS = 12
MAX_CONTEXT_ENTITIES = 160
MAX_SOURCE_SLICE_JSON_BYTES = 80 * 1024
MAX_WALL_CLOCK_SECONDS = 10
DEFAULT_RELATIONSHIP_KINDS = (
    "CALLS",
    "CALLS_EXTERNAL",
    "XREF",
)


class ContextRetrievalError(ValueError):
    pass


class ContextSourceProvider(Protocol):
    def source_slice(
        self,
        *,
        entity: pm.ProgramEntity,
        evidence: tuple[dict[str, Any], ...],
        line_limit: int,
        byte_limit: int,
    ) -> dict[str, Any] | None: ...


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
        raise ContextRetrievalError("context response is not canonical JSON") from exc


def _bounded_int(value: Any, default: int, minimum: int, maximum: int, field: str) -> int:
    try:
        parsed = int(default if value is None else value)
    except (TypeError, ValueError) as exc:
        raise ContextRetrievalError(f"{field} must be an integer") from exc
    if parsed < minimum:
        raise ContextRetrievalError(f"{field} must be at least {minimum}")
    return min(parsed, maximum)


def _normalize_relationship_kinds(values: Iterable[str] | None) -> tuple[str, ...]:
    if values is None:
        return DEFAULT_RELATIONSHIP_KINDS
    normalized: set[str] = set()
    for raw in values:
        value = str(raw or "").strip().upper()
        if value not in pm.RELATIONSHIP_KINDS:
            raise ContextRetrievalError(f"unsupported relationship kind: {value or '<empty>'}")
        normalized.add(value)
        if len(normalized) > 32:
            raise ContextRetrievalError("relationship_kinds exceeds count bound")
    if not normalized:
        raise ContextRetrievalError("relationship_kinds must not be empty")
    return tuple(sorted(normalized))


def _visible_in_scope(item: pm.ProgramEntity, ownership_scope: str) -> bool:
    if ownership_scope_accepts(item.ownership, ownership_scope):
        return True
    return ownership_scope == "application" and item.kind == "EXTERNAL_BOUNDARY"


def _validate_source_slice(value: dict[str, Any] | None) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ContextRetrievalError("source provider returned an invalid source slice")
    encoded = _canonical_json(value)
    if len(encoded) > MAX_SOURCE_SLICE_JSON_BYTES:
        raise ContextRetrievalError("source provider returned an oversized source slice")
    return json.loads(encoded.decode("utf-8"))


def _set_serialized_bytes(payload: dict[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    result["serialized_bytes"] = MAX_RESPONSE_BUDGET_BYTES
    for _ in range(3):
        result["serialized_bytes"] = len(_canonical_json(result))
    return result


def _finalize(payload: dict[str, Any], budget: int) -> dict[str, Any] | None:
    result = dict(payload)
    result["serialized_bytes"] = MAX_RESPONSE_BUDGET_BYTES
    if len(_canonical_json(result)) > budget:
        return None
    result = _set_serialized_bytes(result)
    if len(_canonical_json(result)) > budget:
        return None
    return result


def _relationship_dict(item: pm.ProgramRelationship) -> dict[str, Any]:
    result = item.to_dict()
    # Only a canonical FLOWS_TO edge is a data-flow claim. Structural topology is
    # retained for localization but never promoted by Stage E.
    result["data_flow_claim"] = item.kind == "FLOWS_TO"
    return result


class ContextRetriever:
    def __init__(
        self,
        repository: pm.ProgramRepository,
        source_provider: ContextSourceProvider | None = None,
    ) -> None:
        self.repository = repository
        self.source_provider = source_provider

    def _structural_context(
        self,
        root: pm.ProgramEntity,
        ownership_scope: str,
        *,
        started: float,
    ) -> tuple[list[pm.ProgramEntity], list[pm.ProgramRelationship], bool]:
        entities: dict[str, pm.ProgramEntity] = {}
        relationships: dict[str, pm.ProgramRelationship] = {}
        frontier = [root]
        truncated = False
        depth = 0
        while frontier and depth < MAX_STRUCTURAL_DEPTH:
            if time.monotonic() - started >= MAX_WALL_CLOCK_SECONDS:
                truncated = True
                break
            next_frontier: list[pm.ProgramEntity] = []
            for child in sorted(frontier, key=pm.entity_sort_key):
                remaining = MAX_STRUCTURAL_RELATIONSHIPS - len(relationships)
                if remaining <= 0:
                    truncated = True
                    break
                page = self.repository.find_relationships(
                    entity_id=child.entity_id,
                    kinds=("DECLARES",),
                    direction="incoming",
                    ownership_scope=ownership_scope,
                    limit=min(4, remaining),
                )
                truncated = truncated or page.truncated or page.has_more
                for relation in page.items:
                    parent = self.repository.get_entity(relation.source_entity_id)
                    if parent is None or not _visible_in_scope(parent, ownership_scope):
                        continue
                    relationships[relation.relationship_id] = relation
                    if parent.entity_id not in entities and parent.entity_id != root.entity_id:
                        entities[parent.entity_id] = parent
                        next_frontier.append(parent)
                if len(relationships) >= MAX_STRUCTURAL_RELATIONSHIPS:
                    truncated = True
                    break
            frontier = next_frontier
            depth += 1
        return (
            sorted(entities.values(), key=pm.entity_sort_key),
            sorted(relationships.values(), key=pm.relationship_sort_key),
            truncated,
        )

    def _evidence(
        self,
        refs: Iterable[str],
        *,
        item_limit: int,
        byte_budget: int,
    ) -> tuple[tuple[dict[str, Any], ...], bool]:
        selected_refs = tuple(sorted(set(str(ref) for ref in refs if str(ref))))
        limited_refs = selected_refs[:item_limit]
        records = self.repository.get_evidence(limited_refs)
        result: list[dict[str, Any]] = []
        used = 0
        truncated = len(selected_refs) > len(limited_refs)
        for record in records:
            encoded = _canonical_json(record)
            if used + len(encoded) > byte_budget:
                truncated = True
                break
            used += len(encoded)
            result.append(record)
        if len(records) < len(limited_refs):
            truncated = True
        return tuple(result), truncated

    def get_function_context(
        self,
        *,
        entity_id: str,
        ownership_scope: str = "application",
        direction: str = "both",
        relationship_kinds: Iterable[str] | None = None,
        relationship_limit: int = DEFAULT_RELATIONSHIP_LIMIT,
        evidence_limit: int = DEFAULT_EVIDENCE_LIMIT,
        source_line_limit: int = DEFAULT_SOURCE_LINE_LIMIT,
        source_byte_limit: int = DEFAULT_SOURCE_BYTE_LIMIT,
        response_budget_bytes: int = DEFAULT_RESPONSE_BUDGET_BYTES,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        scope = validate_ownership_scope(ownership_scope)
        normalized_direction = str(direction or "both").strip().lower()
        if normalized_direction not in {"incoming", "outgoing", "both"}:
            raise ContextRetrievalError("direction must be incoming, outgoing, or both")
        kinds = _normalize_relationship_kinds(relationship_kinds)
        relationship_limit = _bounded_int(
            relationship_limit,
            DEFAULT_RELATIONSHIP_LIMIT,
            1,
            MAX_RELATIONSHIP_LIMIT,
            "relationship_limit",
        )
        evidence_limit = _bounded_int(
            evidence_limit,
            DEFAULT_EVIDENCE_LIMIT,
            1,
            MAX_EVIDENCE_LIMIT,
            "evidence_limit",
        )
        source_line_limit = _bounded_int(
            source_line_limit,
            DEFAULT_SOURCE_LINE_LIMIT,
            1,
            MAX_SOURCE_LINE_LIMIT,
            "source_line_limit",
        )
        source_byte_limit = _bounded_int(
            source_byte_limit,
            DEFAULT_SOURCE_BYTE_LIMIT,
            1024,
            MAX_SOURCE_BYTE_LIMIT,
            "source_byte_limit",
        )
        response_budget = _bounded_int(
            response_budget_bytes,
            DEFAULT_RESPONSE_BUDGET_BYTES,
            MIN_RESPONSE_BUDGET_BYTES,
            MAX_RESPONSE_BUDGET_BYTES,
            "response_budget_bytes",
        )

        root = self.repository.get_entity(str(entity_id or ""))
        if root is None:
            raise ContextRetrievalError("function entity was not found in this Program Snapshot")
        if root.kind != "FUNCTION":
            raise ContextRetrievalError("get_function_context requires a FUNCTION entity")
        if not _visible_in_scope(root, scope):
            raise ContextRetrievalError("function is outside the requested ownership_scope")

        started = time.monotonic()
        structural_entities, structural_relationships, structural_truncated = (
            self._structural_context(root, scope, started=started)
        )

        page_limit = relationship_limit
        effective_evidence_limit = evidence_limit
        effective_source_byte_limit = min(
            source_byte_limit,
            max(1024, response_budget // 3),
        )
        source_enabled = self.source_provider is not None
        size_limited = False

        while True:
            if time.monotonic() - started >= MAX_WALL_CLOCK_SECONDS:
                raise ContextRetrievalError("context retrieval exceeded wall-clock budget")
            page = self.repository.find_relationships(
                entity_id=root.entity_id,
                kinds=kinds,
                direction=normalized_direction,
                ownership_scope=scope,
                limit=page_limit,
                cursor=cursor,
            )
            neighbors: dict[str, pm.ProgramEntity] = {}
            relationships: list[pm.ProgramRelationship] = []
            unresolved = False
            scope_filtered = False
            for relation in page.items:
                other_id = (
                    relation.target_entity_id
                    if relation.source_entity_id == root.entity_id
                    else relation.source_entity_id
                )
                other = self.repository.get_entity(other_id)
                if other is None:
                    # Preserve the canonical relationship itself. The repository
                    # cursor may advance past this item, so omitting the edge here
                    # would make the continuation lie about delivered evidence.
                    relationships.append(relation)
                    unresolved = True
                    continue
                if not _visible_in_scope(other, scope):
                    scope_filtered = True
                    continue
                if len(neighbors) >= MAX_CONTEXT_ENTITIES and other.entity_id not in neighbors:
                    relationships.append(relation)
                    unresolved = True
                    continue
                neighbors[other.entity_id] = other
                relationships.append(relation)

            ordered_neighbors = sorted(neighbors.values(), key=pm.entity_sort_key)
            relationships.sort(key=pm.relationship_sort_key)

            refs: set[str] = set(root.evidence_refs)
            for item in structural_entities:
                refs.update(item.evidence_refs)
            for item in structural_relationships:
                refs.update(item.evidence_refs)
            for item in ordered_neighbors:
                refs.update(item.evidence_refs)
            for item in relationships:
                refs.update(item.evidence_refs)

            evidence_budget = max(4096, response_budget // 3)
            evidence, evidence_truncated = self._evidence(
                refs,
                item_limit=effective_evidence_limit,
                byte_budget=evidence_budget,
            )
            root_evidence = self.repository.get_evidence(root.evidence_refs)
            source_slice = None
            source_unavailable = False
            source_truncated = False
            if source_enabled and self.source_provider is not None:
                source_slice = _validate_source_slice(
                    self.source_provider.source_slice(
                        entity=root,
                        evidence=root_evidence,
                        line_limit=source_line_limit,
                        byte_limit=effective_source_byte_limit,
                    )
                )
                source_unavailable = source_slice is None
                source_truncated = bool(
                    source_slice is not None and source_slice.get("truncated") is True
                )

            warnings: list[str] = []
            if structural_truncated:
                warnings.append("structural_context_truncated")
            if page.truncated:
                warnings.append("repository_relationship_budget_reached")
            if evidence_truncated:
                warnings.append("evidence_budget_reached")
            if unresolved:
                warnings.append("unresolved_relationship_endpoint")
            if scope_filtered:
                warnings.append("ownership_scope_filtered_relationships")
            if source_unavailable:
                warnings.append("source_slice_unavailable")
            if source_truncated:
                warnings.append("source_slice_truncated")
            if size_limited:
                warnings.append("response_size_budget_reached")

            payload = {
                "status": "ok",
                "context_retrieval_version": CONTEXT_RETRIEVAL_VERSION,
                "program_model_version": pm.PROGRAM_MODEL_VERSION,
                "snapshot_id": self.repository.snapshot.snapshot_id,
                "artifact_sha256": self.repository.snapshot.artifact_sha256,
                "ownership_scope": scope,
                "root": root.to_dict(),
                "structural_context": {
                    "entities": [item.to_dict() for item in structural_entities],
                    "relationships": [
                        _relationship_dict(item) for item in structural_relationships
                    ],
                },
                "neighbors": [item.to_dict() for item in ordered_neighbors],
                "relationships": [_relationship_dict(item) for item in relationships],
                "evidence": list(evidence),
                "source_slices": [source_slice] if source_slice is not None else [],
                "returned_neighbors": len(ordered_neighbors),
                "returned_relationships": len(relationships),
                "returned_evidence": len(evidence),
                "returned_source_slices": 1 if source_slice is not None else 0,
                # `has_more` is only pagination state. Evidence/source reduction is
                # represented by `truncated` + warnings because there is no cursor
                # for those dimensions.
                "has_more": page.has_more or page.truncated,
                "truncated": (
                    structural_truncated
                    or page.truncated
                    or evidence_truncated
                    or unresolved
                    or source_truncated
                    or size_limited
                ),
                "cursor": page.cursor,
                "limits": {
                    "relationship_limit": relationship_limit,
                    "relationship_page_limit": page_limit,
                    "evidence_limit": evidence_limit,
                    "effective_evidence_limit": effective_evidence_limit,
                    "source_line_limit": source_line_limit,
                    "source_byte_limit": source_byte_limit,
                    "effective_source_byte_limit": (
                        effective_source_byte_limit if source_enabled else 0
                    ),
                    "response_budget_bytes": response_budget,
                    "wall_clock_seconds": MAX_WALL_CLOCK_SECONDS,
                },
                "warnings": warnings,
            }
            result = _finalize(payload, response_budget)
            if result is not None:
                return result

            size_limited = True
            if effective_evidence_limit > 1:
                effective_evidence_limit = max(1, effective_evidence_limit // 2)
                continue
            if source_enabled:
                source_enabled = False
                continue
            if page_limit > 1:
                page_limit = max(1, page_limit // 2)
                continue
            raise ContextRetrievalError(
                "minimum function context exceeds requested response budget"
            )


def descriptor() -> dict[str, Any]:
    return {
        "context_retrieval_version": CONTEXT_RETRIEVAL_VERSION,
        "program_model_version": pm.PROGRAM_MODEL_VERSION,
        "progressive_semantic_retrieval": True,
        "persistent_context_storage": False,
        "llm_required": False,
        "calls_xref_are_data_flow": False,
        "default_response_budget_bytes": DEFAULT_RESPONSE_BUDGET_BYTES,
        "max_response_budget_bytes": MAX_RESPONSE_BUDGET_BYTES,
        "max_relationship_limit": MAX_RELATIONSHIP_LIMIT,
        "max_source_line_limit": MAX_SOURCE_LINE_LIMIT,
        "max_source_byte_limit": MAX_SOURCE_BYTE_LIMIT,
    }
