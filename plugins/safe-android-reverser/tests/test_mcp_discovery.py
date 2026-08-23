#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
LIB_ROOT = PLUGIN_ROOT / "lib"
if str(LIB_ROOT) not in sys.path:
    sys.path.insert(0, str(LIB_ROOT))

from safe_reverser.adapters import McpWorkerAdapter
from safe_reverser.registry import CapabilityRegistry
from safe_reverser.tool_catalog import load_tool_catalog


class NeverStartWorker:
    def __init__(self, manifest):
        self.manifest = manifest
        self.image = "example.invalid/static-core:test"

    def ensure_ready(self):
        raise AssertionError("tools/list must not inspect or pull a worker image")

    def tools(self):
        raise AssertionError("tools/list must not start a worker container")

    def call(self, *_args, **_kwargs):
        raise AssertionError("tools/list must not call a worker")

    def call_internal(self, *_args, **_kwargs):
        raise AssertionError("tools/list must not call worker diagnostics")


class McpDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.registry = CapabilityRegistry(PLUGIN_ROOT / "capabilities")
        self.static = self.registry.get("static-core")
        self.catalog = load_tool_catalog(PLUGIN_ROOT / "tool-catalogs", self.static)

    def test_static_catalog_exactly_matches_manifest_operations(self):
        self.assertEqual(
            {item["name"] for item in self.catalog}, set(self.static.operations)
        )
        self.assertTrue(all(item["inputSchema"]["type"] == "object" for item in self.catalog))

    def test_tools_list_does_not_touch_container_runtime(self):
        adapter = McpWorkerAdapter(NeverStartWorker(self.static), self.catalog)
        tools = adapter.tools()
        self.assertEqual({item["name"] for item in tools}, set(self.static.operations))

    def test_tools_result_is_defensive_copy(self):
        adapter = McpWorkerAdapter(NeverStartWorker(self.static), self.catalog)
        first = adapter.tools()
        first[0]["name"] = "mutated"
        second = adapter.tools()
        self.assertNotEqual(second[0]["name"], "mutated")


if __name__ == "__main__":
    unittest.main()
