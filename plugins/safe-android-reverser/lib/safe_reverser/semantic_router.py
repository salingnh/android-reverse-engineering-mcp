from __future__ import annotations

import re
from typing import Any, Mapping

from .adapters import CapabilityAdapter
from .contracts import ContractError
from .registry import CapabilityRegistry
from .semantic_operations import (
    CONTROL_PLANE_SEMANTIC_OPERATIONS,
    PROGRAM_MODEL_ROUTABLE_REPRESENTATIONS,
)

JOB_ID_RE = re.compile(r"^[0-9a-f]{12}$")


class SemanticRoutingError(RuntimeError):
    pass


def _analysis_locator(arguments: dict[str, Any]) -> tuple[str, str]:
    job_id = str(arguments.get("job_id") or "").strip().lower()
    if not JOB_ID_RE.fullmatch(job_id):
        raise SemanticRoutingError("invalid analysis job_id")
    representation = str(arguments.get("representation") or "").strip().lower()
    if representation not in PROGRAM_MODEL_ROUTABLE_REPRESENTATIONS:
        raise SemanticRoutingError(
            f"unsupported Program Model representation: {representation or '<empty>'}"
        )
    return job_id, representation


def route_program_model_operation(
    *,
    operation: str,
    arguments: dict[str, Any],
    registry: CapabilityRegistry,
    adapters: Mapping[str, CapabilityAdapter],
) -> tuple[str, dict[str, Any]]:
    if operation not in CONTROL_PLANE_SEMANTIC_OPERATIONS:
        raise SemanticRoutingError(
            f"operation is not a control-plane semantic operation: {operation}"
        )
    job_id, representation = _analysis_locator(arguments)
    try:
        manifest = registry.owner_for_representation(representation)
    except ContractError as exc:
        raise SemanticRoutingError(str(exc)) from exc
    adapter = adapters.get(manifest.capability_id)
    if adapter is None:
        raise SemanticRoutingError(
            f"capability for representation is not enabled: {representation}"
        )
    worker_arguments = dict(arguments)
    worker_arguments.pop("representation", None)
    worker_arguments["job_id"] = job_id
    try:
        payload = adapter.program_model_call(operation, worker_arguments)
    except AttributeError as exc:
        raise SemanticRoutingError(
            f"capability does not support Program Model projection: {representation}"
        ) from exc
    if not isinstance(payload, dict):
        raise SemanticRoutingError("Program Model projection returned an invalid payload")
    return manifest.capability_id, payload
