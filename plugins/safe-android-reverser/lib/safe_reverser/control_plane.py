from __future__ import annotations

import copy
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Iterator

from . import CAPABILITY_API_VERSION, EVIDENCE_ENVELOPE_VERSION, WORKER_ABI_VERSION
from .adapters import CapabilityAdapter, build_capability_adapters
from .contracts import ContractError
from .evidence import normalize_capability_result
from .flutter import FlutterCapabilityError
from .paths import PathPolicyError, secure_directory_root
from .registry import CapabilityRegistry
from .runtime import ContainerRuntime, RuntimeErrorSafe
from .semantic_operations import (
    CONTROL_PLANE_CATALOG_OPERATIONS,
    CONTROL_PLANE_SEMANTIC_OPERATIONS,
    PROGRAM_MODEL_ROUTABLE_REPRESENTATIONS,
)
from .semantic_router import SemanticRoutingError, route_program_model_operation
from .tool_catalog import load_named_tool_catalog
from .worker import WorkerProtocolError

SERVER_NAME = "safe-android-reverser"
MAX_TOOL_TEXT_BYTES = 300_000
MAX_REQUEST_CHARS = 1_000_000
MAX_REQUEST_BYTES = 2 * 1024 * 1024


class ControlPlaneError(RuntimeError):
    pass


class ControlPlane:
    def __init__(self, plugin_root: Path) -> None:
        self.plugin_root = plugin_root.resolve()
        self.version = (self.plugin_root / "VERSION").read_text(encoding="utf-8").strip()
        if not self.version or len(self.version) > 64:
            raise ControlPlaneError("plugin VERSION is invalid")

        self.project_dir = Path(
            os.environ.get("SAFE_REVERSER_PROJECT_DIR", os.getcwd())
        ).resolve()
        if not self.project_dir.is_dir():
            raise ControlPlaneError("project directory does not exist")

        try:
            self.data_dir = secure_directory_root(
                Path(
                    os.environ.get(
                        "SAFE_REVERSER_DATA_DIR",
                        str(Path.home() / ".local/share/safe-android-reverser"),
                    )
                ),
                create=True,
            )
        except PathPolicyError as exc:
            raise ControlPlaneError(str(exc)) from exc
        if not os.access(self.data_dir, os.W_OK):
            raise ControlPlaneError("plugin data directory is not writable")

        runtime_name = str(os.environ.get("SAFE_REVERSER_RUNTIME", "")).strip()
        if runtime_name not in {"docker", "podman"}:
            raise ControlPlaneError(
                "SAFE_REVERSER_RUNTIME must be resolved to docker or podman by the launcher"
            )
        if shutil.which(runtime_name) is None:
            raise ControlPlaneError(f"container runtime not found: {runtime_name}")
        self.runtime = ContainerRuntime(
            runtime_name,
            host_uid=os.getuid(),
            host_gid=os.getgid(),
            auto_pull=os.environ.get("SAFE_REVERSER_AUTO_PULL", "1") == "1",
        )
        self.registry = CapabilityRegistry(self.plugin_root / "capabilities")
        self.adapters: dict[str, CapabilityAdapter] = build_capability_adapters(
            runtime=self.runtime,
            registry=self.registry,
            version=self.version,
            project_dir=self.project_dir,
            data_dir=self.data_dir,
        )
        catalog_root = self.plugin_root / "tool-catalogs"
        self._control_plane_tools = load_named_tool_catalog(
            catalog_root,
            "control-plane",
            expected_operations=CONTROL_PLANE_CATALOG_OPERATIONS,
        )
        required = {
            capability_id
            for capability_id, manifest in self.registry.manifests().items()
            if manifest.activation == "required"
        }
        missing_required = required - set(self.adapters)
        if missing_required:
            raise ControlPlaneError(
                f"required capability adapters are missing: {sorted(missing_required)}"
            )

    def _capability_states(self) -> dict[str, Any]:
        states: dict[str, Any] = {}
        for capability_id, manifest in sorted(self.registry.manifests().items()):
            adapter = self.adapters.get(capability_id)
            if adapter is None:
                states[capability_id] = {
                    "state": "declared",
                    "activation": manifest.activation,
                    "enabled": False,
                    "detail": "capability is declared but not enabled",
                }
                continue
            try:
                state = adapter.status()
            except (RuntimeErrorSafe, WorkerProtocolError, FlutterCapabilityError) as exc:
                state = {"state": "unavailable", "detail": str(exc)}
            if not isinstance(state, dict) or not isinstance(state.get("state"), str):
                state = {
                    "state": "degraded",
                    "detail": "capability adapter returned invalid readiness state",
                }
            states[capability_id] = {
                **state,
                "activation": manifest.activation,
                "enabled": True,
            }
        return states

    def _enrich_route(self, payload: dict[str, Any]) -> dict[str, Any]:
        route = payload.get("analysis_route")
        if not isinstance(route, dict):
            return payload
        states = self._capability_states()
        capability_id = str(route.get("primary_capability_id") or "")
        state = states.get(capability_id)
        route["primary_capability_state"] = (
            state.get("state") if isinstance(state, dict) else "unsupported"
        )
        route["primary_capability_runtime"] = state if isinstance(state, dict) else None
        secondaries = route.get("secondary_profiles")
        if isinstance(secondaries, list):
            for item in secondaries:
                if not isinstance(item, dict):
                    continue
                secondary_id = str(item.get("capability_id") or "")
                runtime_state = states.get(secondary_id)
                if isinstance(runtime_state, dict):
                    item["capability_state"] = runtime_state.get("state")
        return payload

    def _normalize(
        self, capability_id: str, operation: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        return normalize_capability_result(
            capability_id=capability_id,
            operation=operation,
            producer_version=self.version,
            payload=payload,
        )

    def tools(self) -> list[dict[str, Any]]:
        # All control-plane-owned descriptors are host-local and canonicalized in
        # tool-catalogs/control-plane.json. No worker is consulted during discovery.
        tools: list[dict[str, Any]] = copy.deepcopy(self._control_plane_tools)
        for _capability_id, adapter in sorted(self.adapters.items()):
            try:
                tools.extend(adapter.tools())
            except (RuntimeErrorSafe, WorkerProtocolError, FlutterCapabilityError):
                continue
        names = [str(item.get("name") or "") for item in tools]
        if len(names) != len(set(names)):
            raise ControlPlaneError("public MCP tool names collide across capability modules")
        return tools

    def health(self) -> dict[str, Any]:
        states = self._capability_states()
        manifests = self.registry.manifests()
        required_ids = {
            capability_id
            for capability_id, manifest in manifests.items()
            if manifest.activation == "required"
        }
        overall = (
            "ok"
            if required_ids
            and all(states.get(item, {}).get("state") == "ready" for item in required_ids)
            else "degraded"
        )
        diagnostics: dict[str, Any] = {}
        for capability_id, adapter in sorted(self.adapters.items()):
            if states.get(capability_id, {}).get("state") != "ready":
                continue
            try:
                detail = adapter.diagnostics()
                if not isinstance(detail, dict):
                    raise ControlPlaneError(
                        "capability adapter returned invalid diagnostics payload"
                    )
                diagnostics[capability_id] = detail
            except (
                ControlPlaneError,
                RuntimeErrorSafe,
                WorkerProtocolError,
                FlutterCapabilityError,
                ValueError,
                OSError,
            ) as exc:
                states[capability_id] = {
                    **states[capability_id],
                    "state": "degraded",
                    "detail": str(exc),
                }
                diagnostics[capability_id] = {"error": str(exc)}
                if capability_id in required_ids:
                    overall = "degraded"
        return {
            "status": overall,
            "server": SERVER_NAME,
            "version": self.version,
            "architecture": "single-host-control-plane",
            "control_plane": {
                "runs_analysis_on_host": False,
                "container_runtime": self.runtime.runtime,
                "runtime_socket_mounted_into_workers": False,
                "capability_api": CAPABILITY_API_VERSION,
                "worker_abi": WORKER_ABI_VERSION,
                "evidence_envelope": EVIDENCE_ENVELOPE_VERSION,
                "semantic_operations": sorted(CONTROL_PLANE_SEMANTIC_OPERATIONS),
                "program_model_routing": "job_id+representation",
                "program_model_representations": sorted(
                    PROGRAM_MODEL_ROUTABLE_REPRESENTATIONS
                ),
            },
            "capabilities": {
                "registry": self.registry.descriptor(),
                "states": states,
                "diagnostics": diagnostics,
            },
        }

    def list_capabilities(self) -> dict[str, Any]:
        return {
            "capability_api": CAPABILITY_API_VERSION,
            "worker_abi": WORKER_ABI_VERSION,
            "registry": self.registry.descriptor(),
            "states": self._capability_states(),
        }

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "health":
            return self.health()
        if name == "list_capabilities":
            return self.list_capabilities()
        if name in CONTROL_PLANE_SEMANTIC_OPERATIONS:
            capability_id, payload = route_program_model_operation(
                operation=name,
                arguments=arguments,
                registry=self.registry,
                adapters=self.adapters,
            )
            return self._normalize(capability_id, name, payload)
        owner = self.registry.owner_for_operation(name)
        adapter = self.adapters.get(owner.capability_id)
        if adapter is None:
            raise ControlPlaneError(f"capability is not enabled: {owner.capability_id}")
        payload = adapter.call(name, arguments)
        payload = self._enrich_route(payload)
        return self._normalize(owner.capability_id, name, payload)


def _tool_result(value: Any, *, is_error: bool = False) -> dict[str, Any]:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    size = len(text.encode("utf-8"))
    if size > MAX_TOOL_TEXT_BYTES:
        text = json.dumps(
            {
                "error": "control-plane result exceeds bounded response size",
                "result_bytes": size,
                "max_result_bytes": MAX_TOOL_TEXT_BYTES,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        is_error = True
    return {
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    }


def _bounded_request_lines() -> Iterator[str]:
    while True:
        line = sys.stdin.readline(MAX_REQUEST_CHARS + 1)
        if not line:
            return
        char_oversized = len(line) > MAX_REQUEST_CHARS
        if char_oversized and not line.endswith("\n"):
            while True:
                remainder = sys.stdin.readline(MAX_REQUEST_CHARS + 1)
                if not remainder or remainder.endswith("\n"):
                    break
        byte_oversized = len(line.encode("utf-8", "replace")) > MAX_REQUEST_BYTES
        if char_oversized or byte_oversized:
            sys.stderr.write(
                "safe-android-reverser: discarded oversized MCP request line\n"
            )
            sys.stderr.flush()
            continue
        yield line


def serve(plugin_root: Path) -> int:
    try:
        plane = ControlPlane(plugin_root)
    except (ControlPlaneError, ContractError, RuntimeErrorSafe, OSError) as exc:
        sys.stderr.write(f"safe-android-reverser: control-plane startup failed: {exc}\n")
        return 2

    def send(payload: dict[str, Any]) -> None:
        sys.stdout.write(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
        )
        sys.stdout.flush()

    for line in _bounded_request_lines():
        if not line.strip():
            continue
        request_id: Any = None
        try:
            req = json.loads(line)
            if not isinstance(req, dict):
                raise ValueError("request must be an object")
            request_id = req.get("id")
            method = req.get("method")
            params = req.get("params") or {}
            if method == "initialize":
                result: Any = {
                    "protocolVersion": params.get("protocolVersion") or "2025-06-18",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": plane.version},
                    "instructions": (
                        "Single Safe Reverser control plane. Framework routing and capability dispatch happen here; "
                        "all untrusted analysis executes inside locked capability workers."
                    ),
                }
            elif method in {"notifications/initialized", "notifications/cancelled"}:
                continue
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": plane.tools()}
            elif method == "tools/call":
                name = str(params.get("name") or "")
                arguments = params.get("arguments") or {}
                if not isinstance(arguments, dict):
                    result = _tool_result(
                        {"error": "tool arguments must be an object"}, is_error=True
                    )
                else:
                    try:
                        result = _tool_result(plane.call(name, arguments))
                    except (
                        ControlPlaneError,
                        ContractError,
                        FlutterCapabilityError,
                        SemanticRoutingError,
                        RuntimeErrorSafe,
                        WorkerProtocolError,
                        ValueError,
                        OSError,
                    ) as exc:
                        result = _tool_result({"error": str(exc)}, is_error=True)
            else:
                if request_id is None:
                    continue
                send(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {
                            "code": -32601,
                            "message": f"method not found: {method}",
                        },
                    }
                )
                continue
            if request_id is not None:
                send({"jsonrpc": "2.0", "id": request_id, "result": result})
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            if request_id is not None:
                send(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {"code": -32600, "message": str(exc)},
                    }
                )
    return 0
