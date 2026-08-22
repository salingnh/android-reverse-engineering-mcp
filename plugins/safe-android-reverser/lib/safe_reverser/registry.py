from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .contracts import CapabilityManifest, ContractError, VALID_STATES

MAX_MANIFEST_BYTES = 64 * 1024
RESERVED_CONTROL_PLANE_OPERATIONS = {"list_capabilities"}


@dataclass(frozen=True)
class CapabilityStatus:
    capability_id: str
    state: str
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        if self.state not in VALID_STATES:
            raise ContractError("invalid capability state")
        return {
            "capability_id": self.capability_id,
            "state": self.state,
            "detail": self.detail,
        }


class CapabilityRegistry:
    def __init__(self, manifest_dir: Path) -> None:
        raw_dir = Path(manifest_dir)
        if raw_dir.is_symlink():
            raise ContractError("capability manifest directory must not be a symlink")
        self.manifest_dir = raw_dir.resolve()
        self._manifests = self._load()
        self._operation_owner: dict[str, str] = {}
        for capability_id, manifest in self._manifests.items():
            for operation in manifest.operations:
                if operation in RESERVED_CONTROL_PLANE_OPERATIONS:
                    raise ContractError(
                        f"operation {operation!r} is reserved by the control plane"
                    )
                previous = self._operation_owner.get(operation)
                if previous is not None:
                    raise ContractError(
                        f"operation {operation!r} is declared by both {previous!r} and {capability_id!r}"
                    )
                self._operation_owner[operation] = capability_id

    def _load(self) -> dict[str, CapabilityManifest]:
        if self.manifest_dir.is_symlink() or not self.manifest_dir.is_dir():
            raise ContractError("capability manifest directory is unavailable")
        result: dict[str, CapabilityManifest] = {}
        for path in sorted(self.manifest_dir.glob("*.json")):
            if (
                path.is_symlink()
                or not path.is_file()
                or path.stat().st_size > MAX_MANIFEST_BYTES
            ):
                raise ContractError(f"unsafe capability manifest: {path.name}")
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise ContractError(f"invalid capability manifest: {path.name}") from exc
            manifest = CapabilityManifest.from_dict(raw)
            if manifest.capability_id in result:
                raise ContractError(f"duplicate capability id: {manifest.capability_id}")
            result[manifest.capability_id] = manifest
        if "static-core" not in result:
            raise ContractError("static-core capability manifest is required")
        return result

    def get(self, capability_id: str) -> CapabilityManifest:
        try:
            return self._manifests[capability_id]
        except KeyError as exc:
            raise ContractError(f"unknown capability: {capability_id}") from exc

    def owner_for_operation(self, operation: str) -> CapabilityManifest:
        owner = self._operation_owner.get(operation)
        if owner is None:
            raise ContractError(f"no capability owns operation: {operation}")
        return self._manifests[owner]

    def manifests(self) -> dict[str, CapabilityManifest]:
        return dict(self._manifests)

    def descriptor(self) -> dict[str, Any]:
        return {
            capability_id: {
                "capability_api": manifest.capability_api,
                "worker_abi": manifest.worker_abi,
                "representations": list(manifest.representation),
                "trust_boundary": manifest.trust_boundary,
                "adapter": manifest.adapter,
                "protocol": manifest.protocol,
                "operations": list(manifest.operations),
                "image_role": manifest.image_role,
            }
            for capability_id, manifest in sorted(self._manifests.items())
        }
