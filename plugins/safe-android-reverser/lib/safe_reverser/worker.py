from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .contracts import CapabilityManifest
from .runtime import ContainerRuntime, VerifiedImage

PROTOCOL_VERSION = "2025-06-18"
MAX_MCP_RESPONSE_BYTES = 2 * 1024 * 1024
REQUIRED_INTERNAL_MCP_OPERATIONS = frozenset({"health"})
PROGRAM_MODEL_INTERNAL_OPERATIONS = frozenset(
    {
        "get_application_map",
        "expand_application_node",
        "get_function_context",
        "trace_value",
        "find_source_to_sink",
    }
)
INTERNAL_MCP_OPERATIONS = (
    REQUIRED_INTERNAL_MCP_OPERATIONS | PROGRAM_MODEL_INTERNAL_OPERATIONS
)


class WorkerProtocolError(RuntimeError):
    pass


class McpContainerWorker:
    """Bounded MCP-over-stdio adapter for an isolated capability image.

    The implementation intentionally starts a fresh worker container per request.
    Job state lives in the mounted capability data directory, so this is a valid
    isolation strategy rather than a protocol contract. A future pool may optimize
    process reuse without changing the Capability SPI or public MCP surface.
    """

    def __init__(
        self,
        runtime: ContainerRuntime,
        manifest: CapabilityManifest,
        *,
        image: str,
        project_dir: Path,
        data_dir: Path,
        version: str,
    ) -> None:
        self.runtime = runtime
        self.manifest = manifest
        self.image = image
        self.project_dir = project_dir.resolve()
        self.data_dir = data_dir.resolve()
        self.version = version
        self._tools: list[dict[str, Any]] | None = None
        self._actual_tool_names: frozenset[str] | None = None
        self._verified: VerifiedImage | None = None

    def required_labels(self) -> dict[str, str]:
        return {
            "org.opencontainers.image.version": self.version,
            "io.safe-reverser.capability.id": self.manifest.capability_id,
            "io.safe-reverser.capability.api": str(self.manifest.capability_api),
            "io.safe-reverser.worker.abi": str(self.manifest.worker_abi),
        }

    def ensure_ready(self) -> VerifiedImage:
        if self._verified is None:
            self._verified = self.runtime.ensure_image(
                self.image, required_labels=self.required_labels()
            )
        return self._verified

    def _exchange(self, request: dict[str, Any], *, timeout: int) -> dict[str, Any]:
        verified = self.ensure_ready()
        init_id = 9000001
        request_id = request.get("id")
        lines = [
            {
                "jsonrpc": "2.0",
                "id": init_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "safe-reverser-control-plane",
                        "version": self.version,
                    },
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            request,
        ]
        run = self.runtime.run_container(
            image=verified.immutable_ref,
            policy=self.manifest.sandbox,
            mounts=[
                (self.project_dir, "/workspace", "ro"),
                (self.data_dir, "/data", "rw"),
            ],
            command=[],
            timeout=timeout,
            env={
                "SAFE_REVERSER_PLUGIN_VERSION": self.version,
                "SAFE_REVERSER_IMAGE_REF": self.image,
                "SAFE_REVERSER_IMAGE_ID": verified.immutable_ref,
            },
            stdin_lines=lines,
        )
        if run.timed_out:
            raise WorkerProtocolError("capability worker timed out")
        if run.exit_code != 0:
            detail = (run.stderr or run.stdout or "worker exited non-zero")[-4000:]
            raise WorkerProtocolError(detail)
        encoded = run.stdout.encode("utf-8", "replace")
        if len(encoded) > MAX_MCP_RESPONSE_BYTES:
            raise WorkerProtocolError("capability response exceeds control-plane budget")
        responses: list[dict[str, Any]] = []
        for raw in run.stdout.splitlines():
            raw = raw.strip()
            if not raw.startswith("{"):
                continue
            try:
                value = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                responses.append(value)
        match = next((item for item in responses if item.get("id") == request_id), None)
        if match is None:
            raise WorkerProtocolError("capability returned no matching MCP response")
        if "error" in match:
            raise WorkerProtocolError(str(match["error"]))
        result = match.get("result")
        if not isinstance(result, dict):
            raise WorkerProtocolError("capability returned invalid MCP result")
        return result

    @staticmethod
    def _decode_tool_result(result: dict[str, Any]) -> dict[str, Any]:
        if result.get("isError"):
            content = result.get("content")
            detail = (
                content[0].get("text")
                if isinstance(content, list)
                and content
                and isinstance(content[0], dict)
                else "worker tool failed"
            )
            raise WorkerProtocolError(str(detail))
        content = result.get("content")
        if not isinstance(content, list) or not content or not isinstance(content[0], dict):
            raise WorkerProtocolError("capability returned invalid tool content")
        text = content[0].get("text")
        if not isinstance(text, str):
            raise WorkerProtocolError("capability tool content is not text")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise WorkerProtocolError("capability tool content is not JSON") from exc
        if not isinstance(payload, dict):
            raise WorkerProtocolError("capability tool payload must be an object")
        return payload

    def _required_internal_operations(self) -> frozenset[str]:
        required = set(REQUIRED_INTERNAL_MCP_OPERATIONS)
        if "dex" in {item.lower() for item in self.manifest.representation}:
            required.update(PROGRAM_MODEL_INTERNAL_OPERATIONS)
        return frozenset(required)

    def tools(self) -> list[dict[str, Any]]:
        if self._tools is None:
            result = self._exchange(
                {
                    "jsonrpc": "2.0",
                    "id": 9000002,
                    "method": "tools/list",
                    "params": {},
                },
                timeout=180,
            )
            tools = result.get("tools")
            if not isinstance(tools, list) or any(not isinstance(item, dict) for item in tools):
                raise WorkerProtocolError("capability returned invalid tool list")
            declared = set(self.manifest.operations)
            actual = {str(item.get("name") or "") for item in tools}
            self._actual_tool_names = frozenset(actual)
            required_internal = self._required_internal_operations()
            missing_internal = required_internal - actual
            public_actual = actual - INTERNAL_MCP_OPERATIONS
            if missing_internal or public_actual != declared:
                missing = sorted(declared - public_actual)
                extra = sorted(public_actual - declared)
                raise WorkerProtocolError(
                    "capability manifest/tool drift: "
                    f"missing={missing} extra={extra} "
                    f"missing_internal={sorted(missing_internal)}"
                )
            self._tools = [
                item
                for item in tools
                if str(item.get("name") or "") not in INTERNAL_MCP_OPERATIONS
            ]
        return list(self._tools)

    def supports_internal(self, name: str) -> bool:
        self.tools()
        return bool(self._actual_tool_names and name in self._actual_tool_names)

    def _call_tool(
        self, name: str, arguments: dict[str, Any], *, timeout: int
    ) -> dict[str, Any]:
        result = self._exchange(
            {
                "jsonrpc": "2.0",
                "id": 9000003,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            },
            timeout=timeout,
        )
        return self._decode_tool_result(result)

    def call(
        self, name: str, arguments: dict[str, Any], *, timeout: int = 3600
    ) -> dict[str, Any]:
        if name not in self.manifest.operations:
            raise WorkerProtocolError(
                f"operation is not declared by {self.manifest.capability_id}: {name}"
            )
        return self._call_tool(name, arguments, timeout=timeout)

    def call_internal(
        self, name: str, arguments: dict[str, Any], *, timeout: int = 180
    ) -> dict[str, Any]:
        if name not in INTERNAL_MCP_OPERATIONS:
            raise WorkerProtocolError(f"unsupported internal worker operation: {name}")
        if not self.supports_internal(name):
            raise WorkerProtocolError(f"worker does not support internal operation: {name}")
        return self._call_tool(name, arguments, timeout=timeout)
