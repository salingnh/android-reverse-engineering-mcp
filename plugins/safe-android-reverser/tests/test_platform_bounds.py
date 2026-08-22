#!/usr/bin/env python3
from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
LIB_ROOT = PLUGIN_ROOT / "lib"
if str(LIB_ROOT) not in sys.path:
    sys.path.insert(0, str(LIB_ROOT))

from safe_reverser.control_plane import (
    MAX_REQUEST_CHARS,
    MAX_TOOL_TEXT_BYTES,
    _bounded_request_lines,
    _tool_result,
)
from safe_reverser.registry import CapabilityRegistry
from safe_reverser.runtime import (
    MAX_COMMAND_ARGS,
    MAX_ENV_VALUE,
    MAX_STDIN_BYTES,
    ContainerRuntime,
    RuntimeErrorSafe,
)


class PlatformBoundsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = CapabilityRegistry(PLUGIN_ROOT / "capabilities")
        self.runtime = ContainerRuntime(
            "docker", host_uid=os.getuid(), host_gid=os.getgid(), auto_pull=False
        )

    def test_public_tool_output_fails_closed_instead_of_returning_truncated_json(self) -> None:
        result = _tool_result({"payload": "x" * (MAX_TOOL_TEXT_BYTES + 1)})
        self.assertTrue(result["isError"])
        text = result["content"][0]["text"]
        self.assertIn("exceeds bounded response size", text)
        self.assertNotIn("... [truncated]", text)

    def test_oversized_public_request_line_is_discarded_before_json_parse(self) -> None:
        oversized = "x" * (MAX_REQUEST_CHARS + 10) + "\n"
        valid = '{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
        fake_stdin = io.StringIO(oversized + valid)
        fake_stderr = io.StringIO()
        with mock.patch("safe_reverser.control_plane.sys.stdin", fake_stdin), mock.patch(
            "safe_reverser.control_plane.sys.stderr", fake_stderr
        ):
            rows = list(_bounded_request_lines())
        self.assertEqual(rows, [valid])
        self.assertIn("discarded oversized MCP request", fake_stderr.getvalue())

    def test_mount_descriptor_rejects_noncanonical_target_and_delimiter_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            with self.assertRaises(RuntimeErrorSafe):
                self.runtime.volume(root, "/workspace/../etc", "ro")
            with self.assertRaises(RuntimeErrorSafe):
                self.runtime.volume(root, "/workspace//nested", "ro")
            colon = root / "bad:path"
            colon.mkdir()
            with self.assertRaises(RuntimeErrorSafe):
                self.runtime.volume(colon.resolve(), "/workspace", "ro")

    def test_runtime_invocation_rejects_oversized_command_env_and_stdin(self) -> None:
        policy = self.registry.get("static-core").sandbox
        with tempfile.TemporaryDirectory() as tmp:
            mount = Path(tmp).resolve()
            with self.assertRaises(RuntimeErrorSafe):
                self.runtime.run_container(
                    image="example.invalid/worker:test",
                    policy=policy,
                    mounts=[(mount, "/workspace", "ro")],
                    command=["x"] * (MAX_COMMAND_ARGS + 1),
                    timeout=1,
                )
            with self.assertRaises(RuntimeErrorSafe):
                self.runtime.run_container(
                    image="example.invalid/worker:test",
                    policy=policy,
                    mounts=[(mount, "/workspace", "ro")],
                    command=[],
                    timeout=1,
                    env={"SAFE_VALUE": "x" * (MAX_ENV_VALUE + 1)},
                )
            with self.assertRaises(RuntimeErrorSafe):
                self.runtime.run_container(
                    image="example.invalid/worker:test",
                    policy=policy,
                    mounts=[(mount, "/workspace", "ro")],
                    command=[],
                    timeout=1,
                    stdin_lines=[{"payload": "x" * (MAX_STDIN_BYTES + 1)}],
                )


if __name__ == "__main__":
    unittest.main()
