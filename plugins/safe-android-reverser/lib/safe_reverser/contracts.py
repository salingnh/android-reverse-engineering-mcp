from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from . import CAPABILITY_API_VERSION, EVIDENCE_ENVELOPE_VERSION, WORKER_ABI_VERSION

VALID_TRUST_BOUNDARIES = {
    "static",
    "framework-static",
    "native-static",
    "dynamic-opt-in",
}
VALID_PROTOCOLS = {"mcp-stdio", "cli-json"}
VALID_ACTIVATIONS = {"required", "optional", "opt-in"}
VALID_NETWORK_POLICIES = {"none", "controlled"}
VALID_STATES = {
    "declared",
    "installed",
    "ready",
    "degraded",
    "unavailable",
    "unsupported",
}
VALID_EVIDENCE_STATES = {"observed", "derived", "hypothesized"}
RESERVED_PUBLIC_OPERATIONS = frozenset({"health", "list_capabilities"})
CAPABILITY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
ADAPTER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
OPERATION_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
IMAGE_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{1,255}$")
IMAGE_ROLE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
REPRESENTATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+ -]{0,127}$")


class ContractError(ValueError):
    pass


def _strict_bool(value: Any, field: str) -> bool:
    if type(value) is not bool:
        raise ContractError(f"{field} must be a boolean")
    return value


def _strict_int(value: Any, field: str) -> int:
    if type(value) is not int:
        raise ContractError(f"{field} must be an integer")
    return value


def _strict_str(value: Any, field: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str:
        raise ContractError(f"{field} must be a string")
    normalized = value.strip()
    if not allow_empty and not normalized:
        raise ContractError(f"{field} must not be empty")
    return normalized


def _strict_string_list(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ContractError(f"{field} must be a non-empty array")
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(_strict_str(item, f"{field}[{index}]"))
    return tuple(result)


@dataclass(frozen=True)
class SandboxPolicy:
    network: str = "none"
    read_only_root: bool = True
    drop_all_capabilities: bool = True
    no_new_privileges: bool = True
    memory: str = "4g"
    cpus: str = "2"
    pids_limit: int = 256
    tmpfs_tmp: str = "1g"
    tmpfs_work: str = "1g"

    @classmethod
    def from_dict(cls, value: dict[str, Any] | None) -> "SandboxPolicy":
        if value is not None and not isinstance(value, dict):
            raise ContractError("sandbox policy must be an object")
        raw = dict(value or {})
        allowed = {
            "network",
            "read_only_root",
            "drop_all_capabilities",
            "no_new_privileges",
            "memory",
            "cpus",
            "pids_limit",
            "tmpfs_tmp",
            "tmpfs_work",
        }
        unknown = set(raw) - allowed
        if unknown:
            raise ContractError(f"unknown sandbox policy fields: {sorted(unknown)}")
        policy = cls(
            network=_strict_str(raw.get("network", "none"), "network"),
            read_only_root=_strict_bool(raw.get("read_only_root", True), "read_only_root"),
            drop_all_capabilities=_strict_bool(
                raw.get("drop_all_capabilities", True), "drop_all_capabilities"
            ),
            no_new_privileges=_strict_bool(
                raw.get("no_new_privileges", True), "no_new_privileges"
            ),
            memory=_strict_str(raw.get("memory", "4g"), "memory"),
            cpus=_strict_str(raw.get("cpus", "2"), "cpus"),
            pids_limit=_strict_int(raw.get("pids_limit", 256), "pids_limit"),
            tmpfs_tmp=_strict_str(raw.get("tmpfs_tmp", "1g"), "tmpfs_tmp"),
            tmpfs_work=_strict_str(raw.get("tmpfs_work", "1g"), "tmpfs_work"),
        )
        if policy.network not in VALID_NETWORK_POLICIES:
            raise ContractError("invalid capability network policy")
        if (
            not policy.read_only_root
            or not policy.drop_all_capabilities
            or not policy.no_new_privileges
        ):
            raise ContractError("capability must preserve locked sandbox invariants")
        if policy.pids_limit < 16 or policy.pids_limit > 4096:
            raise ContractError("invalid capability PID limit")
        return policy


@dataclass(frozen=True)
class CapabilityManifest:
    capability_id: str
    capability_api: int
    worker_abi: int
    representation: tuple[str, ...]
    trust_boundary: str
    activation: str
    adapter: str
    image_repository: str
    image_role: str
    protocol: str
    operations: tuple[str, ...]
    sandbox: SandboxPolicy

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CapabilityManifest":
        if not isinstance(value, dict):
            raise ContractError("capability manifest must be an object")
        allowed = {
            "id",
            "capability_api",
            "worker_abi",
            "representations",
            "trust_boundary",
            "activation",
            "adapter",
            "protocol",
            "image",
            "operations",
            "sandbox",
        }
        unknown = set(value) - allowed
        if unknown:
            raise ContractError(f"unknown capability manifest fields: {sorted(unknown)}")
        required = set(allowed)
        missing = required - set(value)
        if missing:
            raise ContractError(f"missing capability manifest fields: {sorted(missing)}")

        capability_id = _strict_str(value.get("id"), "id")
        if not CAPABILITY_ID_RE.fullmatch(capability_id):
            raise ContractError("invalid capability id")
        capability_api = _strict_int(value.get("capability_api"), "capability_api")
        worker_abi = _strict_int(value.get("worker_abi"), "worker_abi")
        if capability_api != CAPABILITY_API_VERSION:
            raise ContractError(
                f"unsupported capability_api={capability_api}; expected {CAPABILITY_API_VERSION}"
            )
        if worker_abi != WORKER_ABI_VERSION:
            raise ContractError(
                f"unsupported worker_abi={worker_abi}; expected {WORKER_ABI_VERSION}"
            )

        trust_boundary = _strict_str(value.get("trust_boundary"), "trust_boundary")
        if trust_boundary not in VALID_TRUST_BOUNDARIES:
            raise ContractError("invalid capability trust boundary")
        activation = _strict_str(value.get("activation"), "activation")
        if activation not in VALID_ACTIVATIONS:
            raise ContractError("invalid capability activation")
        if trust_boundary == "dynamic-opt-in" and activation != "opt-in":
            raise ContractError("dynamic capability must use opt-in activation")
        adapter = _strict_str(value.get("adapter"), "adapter")
        if not ADAPTER_RE.fullmatch(adapter):
            raise ContractError("invalid capability adapter")
        protocol = _strict_str(value.get("protocol"), "protocol")
        if protocol not in VALID_PROTOCOLS:
            raise ContractError("invalid capability worker protocol")

        image = value.get("image")
        if not isinstance(image, dict) or set(image) != {"repository", "role"}:
            raise ContractError("capability image descriptor requires repository and role only")
        repository = _strict_str(image.get("repository"), "image.repository")
        role = _strict_str(image.get("role"), "image.role")
        if not IMAGE_REPOSITORY_RE.fullmatch(repository):
            raise ContractError("invalid capability image repository")
        if not IMAGE_ROLE_RE.fullmatch(role):
            raise ContractError("invalid capability image role")

        representation = _strict_string_list(
            value.get("representations"), "representations"
        )
        operations = _strict_string_list(value.get("operations"), "operations")
        if any(not REPRESENTATION_RE.fullmatch(item) for item in representation):
            raise ContractError("invalid capability representation")
        if len(set(representation)) != len(representation):
            raise ContractError("capability representations must be unique")
        if any(not OPERATION_RE.fullmatch(item) for item in operations):
            raise ContractError("invalid capability operation name")
        if len(set(operations)) != len(operations):
            raise ContractError("capability operations must be unique")
        reserved = RESERVED_PUBLIC_OPERATIONS.intersection(operations)
        if reserved:
            raise ContractError(
                f"capability operations are reserved by control plane: {sorted(reserved)}"
            )

        sandbox = SandboxPolicy.from_dict(value.get("sandbox"))
        if trust_boundary != "dynamic-opt-in" and sandbox.network != "none":
            raise ContractError(
                "static/framework/native capability network policy must be none"
            )

        return cls(
            capability_id=capability_id,
            capability_api=capability_api,
            worker_abi=worker_abi,
            representation=representation,
            trust_boundary=trust_boundary,
            activation=activation,
            adapter=adapter,
            image_repository=repository,
            image_role=role,
            protocol=protocol,
            operations=operations,
            sandbox=sandbox,
        )


@dataclass(frozen=True)
class EvidenceEnvelope:
    analysis_id: str
    artifact_sha256: str
    producer: str
    producer_version: str
    evidence_state: str
    payload: dict[str, Any]
    limitations: tuple[str, ...] = ()
    schema_version: int = EVIDENCE_ENVELOPE_VERSION

    def to_dict(self) -> dict[str, Any]:
        if self.schema_version != EVIDENCE_ENVELOPE_VERSION:
            raise ContractError("unsupported evidence envelope version")
        if not self.analysis_id or len(self.analysis_id) > 256:
            raise ContractError("invalid evidence analysis_id")
        if len(self.artifact_sha256) != 64 or any(
            ch not in "0123456789abcdef" for ch in self.artifact_sha256
        ):
            raise ContractError("invalid evidence artifact_sha256")
        if not CAPABILITY_ID_RE.fullmatch(self.producer):
            raise ContractError("invalid evidence producer")
        if not self.producer_version or len(self.producer_version) > 128:
            raise ContractError("invalid evidence producer_version")
        if self.evidence_state not in VALID_EVIDENCE_STATES:
            raise ContractError("invalid evidence state")
        if not isinstance(self.payload, dict):
            raise ContractError("evidence payload must be an object")
        if len(self.limitations) > 100 or any(len(item) > 4096 for item in self.limitations):
            raise ContractError("evidence limitations exceed contract bounds")
        return {
            "schema_version": self.schema_version,
            "analysis_id": self.analysis_id,
            "artifact_sha256": self.artifact_sha256,
            "producer": self.producer,
            "producer_version": self.producer_version,
            "evidence_state": self.evidence_state,
            "payload": self.payload,
            "limitations": list(self.limitations),
        }
