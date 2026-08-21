from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

PEG_SCHEMA_VERSION = 2
MAX_LOCATION_JSON_BYTES = 64 * 1024
MAX_PROPERTIES_JSON_BYTES = 256 * 1024
MAX_EVIDENCE_JSON_BYTES = 128 * 1024

NODE_TYPES = (
    "Artifact",
    "APK",
    "DexFile",
    "NativeLibrary",
    "AndroidComponent",
    "Class",
    "Method",
    "Field",
    "BasicBlock",
    "Value",
    "String",
    "DartLibrary",
    "DartClass",
    "DartFunction",
    "DartObject",
    "NativeFunction",
    "JNIBinding",
    "Host",
    "Endpoint",
    "HttpHeader",
    "CryptoOperation",
    "StorageKey",
    "ProtocolMessage",
    "RuntimeEvent",
    "Trace",
    "Finding",
    "Evidence",
)

EDGE_TYPES = (
    "CONTAINS",
    "DECLARES",
    "CALLS",
    "XREFS",
    "READS",
    "WRITES",
    "FLOWS_TO",
    "DERIVED_FROM",
    "RETURNS",
    "IMPLEMENTS",
    "JNI_BINDS",
    "BUILDS_REQUEST",
    "SENDS_TO",
    "AUTHENTICATES_WITH",
    "ENCODES_WITH",
    "ENCRYPTS_WITH",
    "OBSERVED_CALL",
    "OBSERVED_VALUE",
    "CONFIRMS",
    "CONTRADICTS",
)

EVIDENCE_STATES = ("observed", "derived", "hypothesized")


def schema_descriptor() -> dict[str, Any]:
    return {
        "schema_version": PEG_SCHEMA_VERSION,
        "node_types": list(NODE_TYPES),
        "edge_types": list(EDGE_TYPES),
        "evidence_states": list(EVIDENCE_STATES),
        "status": "foundation",
        "limits": {
            "location_json_bytes": MAX_LOCATION_JSON_BYTES,
            "properties_json_bytes": MAX_PROPERTIES_JSON_BYTES,
            "evidence_json_bytes": MAX_EVIDENCE_JSON_BYTES,
        },
    }


def _nonempty(value: Any, field: str, *, max_len: int = 4096) -> str:
    if value is None:
        text = ""
    else:
        text = str(value).strip()
    if not text:
        raise ValueError(f"{field} must be non-empty")
    if len(text) > max_len:
        raise ValueError(f"{field} exceeds {max_len} characters")
    return text


def _bounded_json_object(
    value: Any,
    field: str,
    *,
    max_bytes: int,
    allow_empty: bool = True,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    if not allow_empty and not value:
        raise ValueError(f"{field} must be a non-empty object")
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be JSON-serializable: {exc}") from exc
    if len(encoded) > max_bytes:
        raise ValueError(f"{field} exceeds {max_bytes} serialized bytes")
    return deepcopy(value)


def _validated_evidence_record(value: Any) -> dict[str, Any]:
    record = _bounded_json_object(
        value,
        "evidence_record",
        max_bytes=MAX_EVIDENCE_JSON_BYTES,
        allow_empty=False,
    )
    if record.get("schema_version") != PEG_SCHEMA_VERSION:
        raise ValueError("evidence_record schema_version does not match PEG schema")
    state = record.get("state")
    if state not in EVIDENCE_STATES:
        raise ValueError("evidence_record has an unsupported state")
    if not record.get("analysis_id") or not record.get("artifact_sha256"):
        raise ValueError("evidence_record is missing required provenance")
    analyzer = record.get("analyzer")
    if not isinstance(analyzer, dict) or not analyzer.get("name") or not analyzer.get(
        "version"
    ):
        raise ValueError("evidence_record is missing analyzer provenance")
    if not isinstance(record.get("location"), dict) or not record["location"]:
        raise ValueError("evidence_record is missing location provenance")
    return record


def evidence(
    *,
    analysis_id: str,
    artifact_sha256: str,
    analyzer_name: str,
    analyzer_version: str,
    state: str,
    location: dict[str, Any],
    image_version: str | None = None,
    build_commit: str | None = None,
    config_schema_version: int | str | None = None,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    """Build a normalized, bounded evidence envelope.

    Evidence state is categorical and provenance-oriented. Numeric confidence is
    intentionally not part of the base envelope; analyzers that emit calibrated
    scores must keep those scores in analyzer-specific properties with their
    calibration/meaning documented separately.
    """

    normalized_state = _nonempty(state, "state", max_len=64)
    if normalized_state not in EVIDENCE_STATES:
        raise ValueError(f"unsupported evidence state: {normalized_state}")
    sha = _nonempty(artifact_sha256, "artifact_sha256", max_len=128).lower()
    if len(sha) != 64 or any(ch not in "0123456789abcdef" for ch in sha):
        raise ValueError("artifact_sha256 must be a 64-character hexadecimal SHA-256")

    normalized_location = _bounded_json_object(
        location,
        "location",
        max_bytes=MAX_LOCATION_JSON_BYTES,
        allow_empty=False,
    )
    normalized_limitations = [
        _nonempty(item, "limitation", max_len=2048)
        for item in (limitations or [])[:100]
        if str(item).strip()
    ]

    result: dict[str, Any] = {
        "schema_version": PEG_SCHEMA_VERSION,
        "analysis_id": _nonempty(analysis_id, "analysis_id", max_len=256),
        "artifact_sha256": sha,
        "analyzer": {
            "name": _nonempty(analyzer_name, "analyzer_name", max_len=256),
            "version": _nonempty(analyzer_version, "analyzer_version", max_len=256),
        },
        "state": normalized_state,
        "location": normalized_location,
        "limitations": normalized_limitations,
    }
    if image_version:
        result["image_version"] = _nonempty(
            image_version, "image_version", max_len=256
        )
    if build_commit:
        result["build_commit"] = _nonempty(build_commit, "build_commit", max_len=256)
    if config_schema_version is not None:
        if not isinstance(config_schema_version, (int, str)):
            raise ValueError("config_schema_version must be an integer or string")
        result["config_schema_version"] = config_schema_version

    _bounded_json_object(
        result,
        "evidence",
        max_bytes=MAX_EVIDENCE_JSON_BYTES,
        allow_empty=False,
    )
    return result


def node(
    kind: str,
    node_id: str,
    *,
    properties: dict[str, Any] | None = None,
    evidence_record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_kind = _nonempty(kind, "node kind", max_len=128)
    if normalized_kind not in NODE_TYPES:
        raise ValueError(f"unsupported PEG node type: {normalized_kind}")
    normalized_properties = _bounded_json_object(
        properties or {},
        "properties",
        max_bytes=MAX_PROPERTIES_JSON_BYTES,
    )
    result: dict[str, Any] = {
        "schema_version": PEG_SCHEMA_VERSION,
        "kind": normalized_kind,
        "id": _nonempty(node_id, "node id", max_len=4096),
        "properties": normalized_properties,
    }
    if evidence_record is not None:
        result["evidence"] = _validated_evidence_record(evidence_record)
    return result


def edge(
    kind: str,
    source: str,
    target: str,
    *,
    properties: dict[str, Any] | None = None,
    evidence_record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_kind = _nonempty(kind, "edge kind", max_len=128)
    if normalized_kind not in EDGE_TYPES:
        raise ValueError(f"unsupported PEG edge type: {normalized_kind}")
    normalized_properties = _bounded_json_object(
        properties or {},
        "properties",
        max_bytes=MAX_PROPERTIES_JSON_BYTES,
    )
    result: dict[str, Any] = {
        "schema_version": PEG_SCHEMA_VERSION,
        "kind": normalized_kind,
        "source": _nonempty(source, "edge source", max_len=4096),
        "target": _nonempty(target, "edge target", max_len=4096),
        "properties": normalized_properties,
    }
    if evidence_record is not None:
        result["evidence"] = _validated_evidence_record(evidence_record)
    return result
