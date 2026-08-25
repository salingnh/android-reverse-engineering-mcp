from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any, Protocol

from .controlled_build import GitHubActionsControlledBuildProvider
from .contracts import CapabilityManifest, ContractError
from .flutter import RUNTIME_CACHE_SCHEMA, FlutterCapability
from .paths import PathPolicyError, ensure_private_child
from .registry import CapabilityRegistry
from .runtime import ContainerRuntime, RuntimeErrorSafe
from .runtime_cache import RuntimeCacheResolver
from .tool_catalog import catalogs_equal, load_tool_catalog
from .worker import McpContainerWorker, WorkerProtocolError

MAX_ENABLED_CAPABILITIES = 64
CONTROLLED_BUILD_PROVIDER_ENV = "SAFE_REVERSER_CONTROLLED_BUILD_PROVIDER"


class CapabilityAdapter(Protocol):
    manifest: CapabilityManifest

    def status(self) -> dict[str, Any]: ...

    def diagnostics(self) -> dict[str, Any]: ...

    def tools(self) -> list[dict[str, Any]]: ...

    def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]: ...

    def program_model_call(
        self, name: str, args: dict[str, Any]
    ) -> dict[str, Any]: ...


class McpWorkerAdapter:
    """Generic adapter for an MCP-over-stdio capability worker image.

    Public MCP discovery must remain host-local. The trusted tool catalog is
    shipped with the plugin and returned immediately from tools/list; worker
    image verification and worker-tool drift checks remain readiness concerns
    and happen through status/health or on the first actual tool call.
    """

    def __init__(
        self, worker: McpContainerWorker, public_tools: list[dict[str, Any]]
    ) -> None:
        self.worker = worker
        self.manifest = worker.manifest
        self._public_tools = copy.deepcopy(public_tools)

    def status(self) -> dict[str, Any]:
        try:
            verified = self.worker.ensure_ready()
        except RuntimeErrorSafe as exc:
            return {
                "state": "unavailable",
                "image": self.worker.image,
                "detail": str(exc),
            }
        try:
            # `ready` means the worker image is compatible and its public/internal
            # MCP surface conforms to the Worker ABI, not merely that the image exists.
            actual_tools = self.worker.tools()
            if not catalogs_equal(self._public_tools, actual_tools):
                raise WorkerProtocolError(
                    "capability worker tool descriptors drift from the trusted host catalog"
                )
        except WorkerProtocolError as exc:
            return {
                "state": "degraded",
                "image": self.worker.image,
                "image_id": verified.immutable_ref,
                "detail": str(exc),
            }
        return {
            "state": "ready",
            "image": self.worker.image,
            "image_id": verified.immutable_ref,
            "worker_abi": verified.get("io.safe-reverser.worker.abi"),
            "capability_api": verified.get("io.safe-reverser.capability.api"),
            "image_version": verified.get("org.opencontainers.image.version"),
        }

    def diagnostics(self) -> dict[str, Any]:
        return self.worker.call_internal("health", {})

    def tools(self) -> list[dict[str, Any]]:
        # MCP initialize/tools-list must not pull, inspect or start worker images.
        return copy.deepcopy(self._public_tools)

    def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        return self.worker.call(name, args)

    def program_model_call(
        self, name: str, args: dict[str, Any]
    ) -> dict[str, Any]:
        return self.worker.call_internal(name, args, timeout=360)


class FlutterAotAdapter:
    """Control-plane adapter around the Flutter domain capability."""

    def __init__(self, capability: FlutterCapability) -> None:
        self.capability = capability
        self.manifest = capability.manifest

    def status(self) -> dict[str, Any]:
        return self.capability.status()

    def diagnostics(self) -> dict[str, Any]:
        return {
            "runtime_cache_schema": RUNTIME_CACHE_SCHEMA,
            "runtime_cache_resolver": self.capability.runtime_cache_diagnostics(),
            "job_store": "analysis-job-store-v1",
            "worker": self.capability.diagnostics(),
        }

    def tools(self) -> list[dict[str, Any]]:
        # Flutter tool descriptors are already host-local static metadata.
        return self.capability.tools()

    def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        return self.capability.call(name, args)

    def program_model_call(
        self, name: str, args: dict[str, Any]
    ) -> dict[str, Any]:
        return self.capability.program_model_call(name, args)


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


def _runtime_cache_resolver(
    runtime: ContainerRuntime, data_dir: Path
) -> RuntimeCacheResolver:
    provider_name = str(os.environ.get(CONTROLLED_BUILD_PROVIDER_ENV, "")).strip()
    provider = None
    if provider_name:
        if provider_name != "github-actions":
            raise ContractError("unsupported controlled-build provider configuration")
        try:
            provider = GitHubActionsControlledBuildProvider(
                token=str(
                    os.environ.get("SAFE_REVERSER_CONTROLLED_BUILD_TOKEN", "")
                ),
                repository=str(
                    os.environ.get(
                        "SAFE_REVERSER_CONTROLLED_BUILD_REPOSITORY",
                        "salingnh/android-reverse-engineering-mcp",
                    )
                ).strip(),
                workflow=str(
                    os.environ.get(
                        "SAFE_REVERSER_CONTROLLED_BUILD_WORKFLOW",
                        "build-flutter-runtime-cache.yml",
                    )
                ).strip(),
                ref=str(
                    os.environ.get("SAFE_REVERSER_CONTROLLED_BUILD_REF", "master")
                ).strip(),
            )
        except RuntimeError as exc:
            raise ContractError(str(exc)) from exc
    try:
        build_timeout = int(
            os.environ.get("SAFE_REVERSER_CONTROLLED_BUILD_TIMEOUT_SECONDS", "21600")
        )
        retry_delay = int(
            os.environ.get("SAFE_REVERSER_CONTROLLED_BUILD_RETRY_SECONDS", "300")
        )
    except ValueError as exc:
        raise ContractError(
            "controlled-build timing configuration must be integer"
        ) from exc
    return RuntimeCacheResolver(
        runtime,
        data_root=data_dir,
        provider=provider,
        build_timeout_seconds=build_timeout,
        retry_delay_seconds=retry_delay,
    )


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

    catalog_root = registry.manifest_dir.parent / "tool-catalogs"
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
            public_tools = load_tool_catalog(catalog_root, manifest)
            adapter: CapabilityAdapter = McpWorkerAdapter(worker, public_tools)
        elif manifest.adapter == "flutter-aot":
            capability = FlutterCapability(
                runtime,
                manifest,
                version=version,
                project_dir=project_dir,
                data_dir=data_dir,
                runtime_cache_resolver=_runtime_cache_resolver(runtime, data_dir),
                output_tmpfs=str(
                    os.environ.get("SAFE_REVERSER_FLUTTER_OUTPUT_TMPFS", "4g")
                ).strip(),
            )
            if override:
                capability.base_image = override
            adapter = FlutterAotAdapter(capability)
        else:
            raise ContractError(
                f"capability {capability_id!r} requests unsupported adapter {manifest.adapter!r}"
            )
        adapters[capability_id] = adapter
    return adapters
