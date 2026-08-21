#!/usr/bin/env python3
from __future__ import annotations

import time
import unittest

import mcp_server_v2 as server


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

    def test_deadline_interrupts_bounded_work(self):
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            with server._deadline(1):
                time.sleep(2)
        self.assertLess(time.monotonic() - started, 1.8)

    def test_pu_call_converts_timeout_to_tool_error(self):
        def fail():
            raise TimeoutError("synthetic timeout")

        with self.assertRaises(server.core.ToolError):
            server._pu_call(fail)


if __name__ == "__main__":
    unittest.main()
