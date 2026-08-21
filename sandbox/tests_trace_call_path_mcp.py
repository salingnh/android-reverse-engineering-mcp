#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import mcp_server_v2 as server
import pu_call_path
import pu_index


class TraceCallPathMcpTests(unittest.TestCase):
    def tool(self):
        return next(tool for tool in server.core.TOOLS if tool["name"] == "trace_call_path")

    def test_schema_is_bounded_and_closed(self):
        schema = self.tool()["inputSchema"]
        self.assertEqual(schema["required"], ["job_id", "source", "target"])
        self.assertFalse(schema["additionalProperties"])
        props = schema["properties"]
        self.assertEqual(props["direction"]["enum"], ["forward", "reverse"])
        self.assertEqual((props["max_depth"]["minimum"], props["max_depth"]["maximum"]), (1, 32))
        self.assertEqual((props["max_paths"]["minimum"], props["max_paths"]["maximum"]), (1, 50))
        self.assertEqual((props["max_visited_nodes"]["minimum"], props["max_visited_nodes"]["maximum"]), (200, 200000))
        self.assertEqual((props["max_scanned_edges"]["minimum"], props["max_scanned_edges"]["maximum"]), (100, 500000))
        self.assertEqual((props["timeout_seconds"]["minimum"], props["timeout_seconds"]["maximum"]), (1, 3600))

    def test_health_advertises_call_path(self):
        health = server.health({})
        self.assertEqual(health["version"], "0.2.1")
        self.assertTrue(health["program_understanding"]["call_path"])
        self.assertTrue(health["program_understanding"]["wall_clock_deadlines"])

    def test_call_path_budget_stays_below_core_text_limit(self):
        self.assertLess(pu_call_path.MAX_RESPONSE_CHARS, server.core.MAX_TOOL_TEXT)
        sample = {"text": "x" * 1000}
        self.assertEqual(
            pu_call_path._response_chars(sample),
            len(json.dumps(sample, ensure_ascii=False, indent=2, sort_keys=True)),
        )

    def test_deadline_interrupts_bounded_work(self):
        self.assertFalse(issubclass(server.SemanticDeadlineExceeded, Exception))
        started = time.monotonic()
        with self.assertRaises(server.SemanticDeadlineExceeded):
            with server._deadline(1):
                time.sleep(2)
        self.assertLess(time.monotonic() - started, 1.8)

    def test_analyzer_exception_handler_cannot_swallow_deadline(self):
        def analyzer_like_code():
            try:
                with server._deadline(1):
                    time.sleep(2)
            except Exception:
                return "swallowed"
            return "completed"

        with self.assertRaises(server.SemanticDeadlineExceeded):
            analyzer_like_code()

    def test_pu_call_converts_semantic_deadline_to_tool_error(self):
        def fail():
            raise server.SemanticDeadlineExceeded("synthetic deadline")

        with self.assertRaises(server.core.ToolError):
            server._pu_call(fail)

    def test_program_index_does_not_swallow_wall_clock_timeout(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            root = Path(tmp.name)
            workspace = root / "workspace"
            job = root / "job"
            workspace.mkdir()
            job.mkdir()
            (workspace / "app.apk").write_bytes(b"fixture")
            (job / "job.json").write_text(
                json.dumps({"artifact": "app.apk"}), encoding="utf-8"
            )

            with mock.patch.object(
                pu_index,
                "_dex_index",
                side_effect=server.SemanticDeadlineExceeded("deadline"),
            ), mock.patch.object(pu_index, "_source_index") as fallback:
                with self.assertRaises(server.SemanticDeadlineExceeded):
                    pu_index.build_program_index(job, workspace, {}, force=True)
                fallback.assert_not_called()
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
