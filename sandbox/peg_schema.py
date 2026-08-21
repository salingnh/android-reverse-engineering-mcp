from __future__ import annotations

from copy import deepcopy
from typing import Any

PEG_SCHEMA_VERSION = 2

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
    }


def _nonempty(value: Any, field: str, *, max_len: int = 4096) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} must be non-empty")
    if len(text) > max_len:
        raise ValueError(f"{field} exceeds {max_len} characters")
    return text


def evidence(
    *,
    analysis_id: str,
    artifact_sha256: str,
    analyzer_name: str,
    analyzer_version: str,
    state: str,
    location: dict[str, Any],
    image_version: str | None = None,
    config_schema_version: int | str | None = None,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    """Build a normalized evidence envelope without model-invented confidence.

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
    if not isinstance(location, dict) or not location:
        raise ValueError("location must be a non-empty object")

    result: dict[str, Any] = {
        "schema_version": PEG_SCHEMA_VERSION,
        "analysis_id": _nonempty(analysis_id, "analysis_id", max_len=256),
        "artifact_sha256": sha,
        "analyzer": {
            "name": _nonempty(analyzer_name, "analyzer_name", max_len=256),
            "version": _nonempty(analyzer_version, "analyzer_version", max_len=256),
        },
        "state": normalized_state,
        "location": deepcopy(location),
        "limitations": [str(item)[:2048] for item in (limitations or [])[:100]],
    }
    if image_version:
        result["image_version"] = _nonempty(image_version, "image_version", max_len=256)
    if config_schema_version is not None:
        result["config_schema_version"] = config_schema_version
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
    result: dict[str, Any] = {
        "schema_version": PEG_SCHEMA_VERSION,
        "kind": normalized_kind,
        "id": _nonempty(node_id, "node id", max_len=4096),
        "properties": deepcopy(properties or {}),
    }
    if evidence_record is not None:
        result["evidence"] = deepcopy(evidence_record)
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
    result: dict[str, Any] = {
        "schema_version": PEG_SCHEMA_VERSION,
        "kind": normalized_kind,
        "source": _nonempty(source, "edge source", max_len=4096),
        "target": _nonempty(target, "edge target", max_len=4096),
        "properties": deepcopy(properties or {}),
    }
    if evidence_record is not None:
        result["evidence"] = deepcopy(evidence_record)
    return result
