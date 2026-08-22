from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from . import CAPABILITY_API_VERSION, EVIDENCE_ENVELOPE_VERSION, WORKER_ABI_VERSION
from .contracts import ContractError
from .evidence import normalize_capability_result
from .flutter import FlutterCapability, FlutterCapabilityError
from .registry import CapabilityRegistry
from .runtime import ContainerRuntime, RuntimeErrorSafe
from .worker import McpContainerWorker, WorkerProtocolError

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

        raw_project = Path(os.environ.get("SAFE_REVERSER_PROJECT_DIR", os.getcwd()))
        self.project_dir = raw_project.resolve()
        if not self.project_dir.is_dir():
            raise ControlPlaneError("project directory does not exist")

        raw_data = Path(
            os.environ.get(
                "SAFE_REVERSER_DATA_DIR",
                str(Path.home() / ".local/share/safe-android-reverser"),
            )
        )
        if raw_data.is_symlink():
            raise ControlPlaneError("plugin data directory must not be a symlink")
        raw_data.mkdir(parents=True, exist_ok=True, mode=0o700)
        if raw_data.is_symlink() or not raw_data.is_dir():
            raise ControlPlaneError("plugin data directory must be a regular directory")
        self.data_dir = raw_data.resolve()
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

        static_manifest = self.registry.get("static-core")
        static_image = str(
            os.environ.get(
                "SAFE_REVERSER_STATIC_IMAGE",
                f"{static_manifest.image_repository}:{self.version}",
            )
        ).strip()
        static_data = self.data_dir / "static-core"
        if static_data.is_symlink():
            raise ControlPlaneError("static-core data directory must not be a symlink")
        static_data.mkdir(mode=0o700, exist_ok=True)
        if static_data.resolve().parent != self.data_dir:
            raise ControlPlaneError("static-core data directory escapes plugin data root")
        self.static = McpContainerWorker(
            self.runtime,
            static_manifest,
            image=static_image,
            project_dir=self.project_dir,
            data_dir=static_data,
            version=self.version,
        )

        flutter_manifest = self.registry.get("framework-flutter")
        self.flutter = FlutterCapability(
            self.runtime,
            flutter_manifest,
            version=self.version,
            project_dir=self.project_dir,
            data_dir=self.data_dir,
            output_tmpfs=str(
                os.environ.get("SAFE_REVERSER_FLUTTER_OUTPUT_TMPFS", "4g")
            ).strip(),
        )
        override = os.environ.get("SAFE_REVERSER_FLUTTER_IMAGE")
        if override:
            self.flutter.base_image = str(override).strip()

    def _capability_states(self) -> dict[str, Any]:
        states: dict[str, Any] = {}
        try:
            labels = self.static.ensure_ready()
            states["static-core"] = {
                "state": "ready",
                "image": self.static.image,
                "worker_abi": labels.get("io.safe-reverser.worker.abi"),
                "capability_api": labels.get("io.safe-reverser.capability.api"),
            }
        except (RuntimeErrorSafe, WorkerProtocolError) as exc:
            states["static-core"] = {
                "state": "unavailable",
                "image": self.static.image,
                "detail": str(exc),
            }
        states["framework-flutter"] = self.flutter.status()
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
        try:
            tools.extend(
                item for item in self.static.tools() if item.get("name") != "health"
            )
        except (RuntimeErrorSafe, WorkerProtocolError):
            # Keep control-plane diagnostics available even when static-core is not installed.
            pass
        tools.extend(self.flutter.tools())
        names = [str(item.get("name") or "") for item in tools]
        if len(names) != len(set(names)):
            raise ControlPlaneError("public MCP tool names collide across capability modules")
        return tools

    def health(self) -> dict[str, Any]:
        states = self._capability_states()
        required_states = [
            states.get("static-core", {}),
            states.get("framework-flutter", {}),
        ]
        overall = (
            "ok"
            if all(item.get("state") == "ready" for item in required_states)
            else "degraded"
        )
        static_health: dict[str, Any] | None = None
        if states.get("static-core", {}).get("state") == "ready":
            try:
                static_health = self.static.call("health", {}, timeout=180)
            except (RuntimeErrorSafe, WorkerProtocolError) as exc:
                states["static-core"] = {
                    **states["static-core"],
                    "state": "degraded",
                    "detail": str(exc),
                }
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
            },
            "static_core": static_health,
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
        flutter_manifest = self.registry.get("framework-flutter")
        if name in flutter_manifest.operations:
            payload = self.flutter.call(name, arguments)
            return self._normalize(flutter_manifest.capability_id, name, payload)
        static_manifest = self.registry.get("static-core")
        if name in static_manifest.operations:
            payload = self.static.call(name, arguments)
            if name in {"fingerprint", "route_analysis"}:
                payload = self._enrich_route(payload)
            return self._normalize(static_manifest.capability_id, name, payload)
        raise ControlPlaneError(f"unknown tool: {name}")


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
        sys.stderr.write(
            f"safe-android-reverser: control-plane startup failed: {exc}\n"
        )
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
