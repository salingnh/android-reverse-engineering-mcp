from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .contracts import CapabilityManifest
from .runtime import ContainerRuntime, RuntimeErrorSafe

PROTOCOL_VERSION = "2025-06-18"
MAX_MCP_RESPONSE_BYTES = 2 * 1024 * 1024


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

    def required_labels(self) -> dict[str, str]:
        return {
            "org.opencontainers.image.version": self.version,
            "io.safe-reverser.capability.id": self.manifest.capability_id,
            "io.safe-reverser.capability.api": str(self.manifest.capability_api),
            "io.safe-reverser.worker.abi": str(self.manifest.worker_abi),
        }

    def ensure_ready(self) -> dict[str, str]:
        return self.runtime.ensure_image(self.image, required_labels=self.required_labels())

    def _exchange(self, request: dict[str, Any], *, timeout: int) -> dict[str, Any]:
        self.ensure_ready()
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
                    "clientInfo": {"name": "safe-reverser-control-plane", "version": self.version},
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            request,
        ]
        run = self.runtime.run_container(
            image=self.image,
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
            },
            stdin_lines=lines,
        )
        if run.timed_out:
            raise WorkerProtocolError("static capability worker timed out")
        if run.exit_code != 0:
            detail = (run.stderr or run.stdout or "worker exited non-zero")[-4000:]
            raise WorkerProtocolError(detail)
        encoded = run.stdout.encode("utf-8", "replace")
        if len(encoded) > MAX_MCP_RESPONSE_BYTES:
            raise WorkerProtocolError("static capability response exceeds control-plane budget")
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
            raise WorkerProtocolError("static capability returned no matching MCP response")
        if "error" in match:
            raise WorkerProtocolError(str(match["error"]))
        result = match.get("result")
        if not isinstance(result, dict):
            raise WorkerProtocolError("static capability returned invalid MCP result")
        return result

    def tools(self) -> list[dict[str, Any]]:
        if self._tools is None:
            result = self._exchange(
                {"jsonrpc": "2.0", "id": 9000002, "method": "tools/list", "params": {}},
                timeout=180,
            )
            tools = result.get("tools")
            if not isinstance(tools, list) or any(not isinstance(item, dict) for item in tools):
                raise WorkerProtocolError("static capability returned invalid tool list")
            declared = set(self.manifest.operations)
            actual = {str(item.get("name") or "") for item in tools}
            if actual != declared:
                missing = sorted(declared - actual)
                extra = sorted(actual - declared)
                raise WorkerProtocolError(
                    f"static capability manifest/tool drift: missing={missing} extra={extra}"
                )
            self._tools = tools
        return list(self._tools)

    def call(self, name: str, arguments: dict[str, Any], *, timeout: int = 3600) -> dict[str, Any]:
        if name not in self.manifest.operations:
            raise WorkerProtocolError(f"operation is not declared by {self.manifest.capability_id}: {name}")
        result = self._exchange(
            {
                "jsonrpc": "2.0",
                "id": 9000003,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            },
            timeout=timeout,
        )
        if result.get("isError"):
            content = result.get("content")
            detail = content[0].get("text") if isinstance(content, list) and content and isinstance(content[0], dict) else "static worker tool failed"
            raise WorkerProtocolError(str(detail))
        content = result.get("content")
        if not isinstance(content, list) or not content or not isinstance(content[0], dict):
            raise WorkerProtocolError("static capability returned invalid tool content")
        text = content[0].get("text")
        if not isinstance(text, str):
            raise WorkerProtocolError("static capability tool content is not text")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise WorkerProtocolError("static capability tool content is not JSON") from exc
        if not isinstance(payload, dict):
            raise WorkerProtocolError("static capability tool payload must be an object")
        return payload
