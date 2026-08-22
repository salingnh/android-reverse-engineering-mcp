from __future__ import annotations

from copy import deepcopy
from typing import Any

from . import CAPABILITY_API_VERSION, EVIDENCE_ENVELOPE_VERSION, WORKER_ABI_VERSION
from .contracts import ContractError, EvidenceEnvelope, VALID_EVIDENCE_STATES

CONTRACT_KEY = "safe_reverser_contract"
EVIDENCE_KEY = "evidence_envelope"


def _provenance(payload: dict[str, Any]) -> dict[str, Any] | None:
    value = payload.get("provenance")
    if isinstance(value, dict):
        return value
    semantic = payload.get("semantic_index")
    if isinstance(semantic, dict):
        nested = semantic.get("provenance")
        if isinstance(nested, dict):
            return nested
    return None


def normalize_capability_result(
    *,
    capability_id: str,
    operation: str,
    producer_version: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Attach stable platform contracts without replacing analyzer-native payloads.

    Analyzer-local indexes and result schemas remain private implementation
    details. The control plane adds a stable compatibility descriptor to every
    result and, when material provenance is present, a common EvidenceEnvelope.
    No evidence state is invented when the producer did not provide one.
    """

    if not isinstance(payload, dict):
        raise ContractError("capability result must be an object")
    result = deepcopy(payload)
    result[CONTRACT_KEY] = {
        "capability_id": capability_id,
        "capability_api": CAPABILITY_API_VERSION,
        "worker_abi": WORKER_ABI_VERSION,
        "operation": operation,
        "evidence_envelope_version": EVIDENCE_ENVELOPE_VERSION,
    }

    provenance = _provenance(result)
    if provenance is None:
        return result
    analysis_id = str(provenance.get("analysis_id") or "")
    artifact_sha256 = str(provenance.get("artifact_sha256") or "").lower()
    evidence_state = str(provenance.get("evidence_state") or "")
    if not analysis_id or len(artifact_sha256) != 64:
        return result
    if evidence_state not in VALID_EVIDENCE_STATES:
        return result

    limitations_value = result.get("limitations")
    limitations: tuple[str, ...]
    if isinstance(limitations_value, list):
        limitations = tuple(str(item)[:4096] for item in limitations_value[:100])
    else:
        limitations = ()

    result[EVIDENCE_KEY] = EvidenceEnvelope(
        analysis_id=analysis_id,
        artifact_sha256=artifact_sha256,
        producer=capability_id,
        producer_version=producer_version,
        evidence_state=evidence_state,
        payload={
            "operation": operation,
            "provenance": deepcopy(provenance),
        },
        limitations=limitations,
    ).to_dict()
    return result
