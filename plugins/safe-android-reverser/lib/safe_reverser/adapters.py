from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Protocol

from .contracts import CapabilityManifest, ContractError
from .flutter import FlutterCapability
from .paths import PathPolicyError, ensure_private_child
from .registry import CapabilityRegistry
from .runtime import ContainerRuntime, RuntimeErrorSafe
from .worker import McpContainerWorker, WorkerProtocolError

RESERVED_CONTROL_PLANE_OPERATIONS = {"health", "list_capabilities"}
MAX_ENABLED_CAPABILITIES = 64


class CapabilityAdapter(Protocol):
    manifest: CapabilityManifest

    def status(self) -> dict[str, Any]: ...

    def tools(self) -> list[dict[str, Any]]: ...

    def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]: ...


class McpWorkerAdapter:
    """Generic adapter for an MCP-over-stdio capability worker image."""

    def __init__(self, worker: McpContainerWorker) -> None:
        self.worker = worker
        self.manifest = worker.manifest

    def status(self) -> dict[str, Any]:
        try:
            labels = self.worker.ensure_ready()
        except (RuntimeErrorSafe, WorkerProtocolError) as exc:
            return {
                "state": "unavailable",
                "image": self.worker.image,
                "detail": str(exc),
            }
        return {
            "state": "ready",
            "image": self.worker.image,
            "worker_abi": labels.get("io.safe-reverser.worker.abi"),
            "capability_api": labels.get("io.safe-reverser.capability.api"),
            "image_version": labels.get("org.opencontainers.image.version"),
        }

    def tools(self) -> list[dict[str, Any]]:
        return self.worker.tools()

    def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        return self.worker.call(name, args)


def _env_suffix(capability_id: str) -> str:
    return capability_id.upper().replace("-", "_")


def _enabled_opt_in_capabilities() -> set[str]:
    value = str(os.environ.get("SAFE_REVERSER_ENABLE_CAPABILITIES", "")).strip()
    if not value:
        return set()
    items = [item.strip() for item in value.split(",") if item.strip()]
    if len(items) > MAX_ENABLED_CAPABILITIES:
        raise ContractError("too many explicitly enabled capabilities")
    return set(items)


def _image_override(manifest: CapabilityManifest) -> str | None:
    generic = os.environ.get(
        f"SAFE_REVERSER_CAPABILITY_IMAGE_{_env_suffix(manifest.capability_id)}"
    )
    if generic:
        return generic.strip()

    # Compatibility aliases for pre-0.3 development/installations. These are
    # configuration aliases only; image lifecycle still belongs to Runtime Driver.
    if manifest.capability_id == "static-core":
        value = os.environ.get("SAFE_REVERSER_STATIC_IMAGE")
        return value.strip() if value else None
    if manifest.capability_id == "framework-flutter":
        value = os.environ.get("SAFE_REVERSER_FLUTTER_IMAGE")
        return value.strip() if value else None
    return None


def build_capability_adapters(
    *,
    runtime: ContainerRuntime,
    registry: CapabilityRegistry,
    version: str,
    project_dir: Path,
    data_dir: Path,
) -> dict[str, CapabilityAdapter]:
    """Instantiate enabled adapters from trusted capability manifests.

    Required/optional capabilities are active when installed in the registry.
    `opt-in` capabilities are inactive until their exact capability id appears in
    SAFE_REVERSER_ENABLE_CAPABILITIES. This preserves an explicit privilege gate
    for future dynamic backends without changing the public MCP topology.
    """

    enabled_opt_in = _enabled_opt_in_capabilities()
    known_ids = set(registry.manifests())
    unknown_enabled = enabled_opt_in - known_ids
    if unknown_enabled:
        raise ContractError(
            f"unknown explicitly enabled capabilities: {sorted(unknown_enabled)}"
        )

    adapters: dict[str, CapabilityAdapter] = {}
    for capability_id, manifest in registry.manifests().items():
        if manifest.activation == "opt-in" and capability_id not in enabled_opt_in:
            continue
        override = _image_override(manifest)
        if manifest.adapter == "mcp-container":
            try:
                capability_data = ensure_private_child(data_dir, capability_id)
            except PathPolicyError as exc:
                raise ContractError(str(exc)) from exc
            image = override or f"{manifest.image_repository}:{version}"
            worker = McpContainerWorker(
                runtime,
                manifest,
                image=image,
                project_dir=project_dir,
                data_dir=capability_data,
                version=version,
            )
            adapter: CapabilityAdapter = McpWorkerAdapter(worker)
        elif manifest.adapter == "flutter-aot":
            adapter = FlutterCapability(
                runtime,
                manifest,
                version=version,
                project_dir=project_dir,
                data_dir=data_dir,
                output_tmpfs=str(
                    os.environ.get("SAFE_REVERSER_FLUTTER_OUTPUT_TMPFS", "4g")
                ).strip(),
            )
            if override:
                adapter.base_image = override
        else:
            raise ContractError(
                f"capability {capability_id!r} requests unsupported adapter {manifest.adapter!r}"
            )
        adapters[capability_id] = adapter
    return adapters
