from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from . import CAPABILITY_API_VERSION, EVIDENCE_ENVELOPE_VERSION, WORKER_ABI_VERSION
from .adapters import CapabilityAdapter, build_capability_adapters
from .contracts import ContractError
from .evidence import normalize_capability_result
from .flutter import FlutterCapabilityError
from .paths import PathPolicyError, secure_directory_root
from .registry import CapabilityRegistry
from .runtime import ContainerRuntime, RuntimeErrorSafe
from .worker import WorkerProtocolError

SERVER_NAME = "safe-android-reverser"
MAX_TOOL_TEXT = 300_000


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
        tools: list[dict[str, Any]] = [
            {
                "name": "health",
                "description": "Check the Safe Reverser host control plane and discover actual readiness across isolated capability workers.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            },
            {
                "name": "list_capabilities",
                "description": "Return the manifest-driven Capability SPI registry and current runtime readiness states.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            },
        ]
        for _capability_id, adapter in sorted(self.adapters.items()):
            try:
                tools.extend(adapter.tools())
            except (RuntimeErrorSafe, WorkerProtocolError, FlutterCapabilityError):
                # Control-plane diagnostics remain available even when one worker is absent.
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
        owner = self.registry.owner_for_operation(name)
        adapter = self.adapters.get(owner.capability_id)
        if adapter is None:
            raise ControlPlaneError(f"capability is not enabled: {owner.capability_id}")
        payload = adapter.call(name, arguments)
        if name in {"fingerprint", "route_analysis"}:
            payload = self._enrich_route(payload)
        return self._normalize(owner.capability_id, name, payload)


def _json_text(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)
    if len(text) > MAX_TOOL_TEXT:
        return text[:MAX_TOOL_TEXT] + "\n... [truncated]"
    return text


def _tool_result(value: Any, *, is_error: bool = False) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": _json_text(value)}],
        "isError": is_error,
    }


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

    for line in sys.stdin:
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
