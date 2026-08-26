#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
LIB_ROOT = PLUGIN_ROOT / "lib"
if str(LIB_ROOT) not in sys.path:
    sys.path.insert(0, str(LIB_ROOT))

from safe_reverser.adapters import FlutterAotAdapter
from safe_reverser.registry import CapabilityRegistry
from safe_reverser.semantic_operations import CONTROL_PLANE_SEMANTIC_OPERATIONS
from safe_reverser.semantic_router import SemanticRoutingError, route_program_model_operation
from safe_reverser.tool_catalog import load_named_tool_catalog


class FakeAdapter:
    def __init__(self):
        self.calls = []

    def program_model_call(self, name, args):
        self.calls.append((name, dict(args)))
        return {
            "status": "ok",
            "context_retrieval_version": 1,
            "program_model_version": 1,
            "snapshot_id": "pms:test",
            "root": {"entity_id": args.get("entity_id")},
        }


class FakeFlutterCapability:
    def __init__(self, manifest):
        self.manifest = manifest
        self.calls = []

    def _semantic(self, job_id, command, argv, timeout):
        self.calls.append((job_id, command, list(argv), timeout))
        return {"status": "ok", "argv": list(argv)}


class ContextRetrievalRoutingTests(unittest.TestCase):
    def setUp(self):
        self.registry = CapabilityRegistry(PLUGIN_ROOT / "capabilities")

    def test_context_operation_is_control_plane_owned_and_catalogued_once(self):
        self.assertIn("get_function_context", CONTROL_PLANE_SEMANTIC_OPERATIONS)
        catalog = load_named_tool_catalog(
            PLUGIN_ROOT / "tool-catalogs",
            "control-plane",
        )
        names = [item["name"] for item in catalog]
        self.assertEqual(names.count("get_function_context"), 1)
        for manifest in self.registry.manifests().values():
            self.assertNotIn("get_function_context", manifest.operations)

    def test_context_routes_by_representation_without_fallback_probe(self):
        static = FakeAdapter()
        flutter = FakeAdapter()
        adapters = {"static-core": static, "framework-flutter": flutter}
        capability_id, payload = route_program_model_operation(
            operation="get_function_context",
            arguments={
                "job_id": "012345abcdef",
                "representation": "dex",
                "entity_id": "pm:v1:function:test",
                "relationship_limit": 12,
            },
            registry=self.registry,
            adapters=adapters,
        )
        self.assertEqual(capability_id, "static-core")
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(len(static.calls), 1)
        self.assertEqual(flutter.calls, [])
        self.assertNotIn("representation", static.calls[0][1])
        self.assertEqual(static.calls[0][1]["job_id"], "012345abcdef")

        capability_id, _ = route_program_model_operation(
            operation="get_function_context",
            arguments={
                "job_id": "fedcba654321",
                "representation": "flutter-dart-aot",
                "entity_id": "pm:v1:function:flutter",
            },
            registry=self.registry,
            adapters=adapters,
        )
        self.assertEqual(capability_id, "framework-flutter")
        self.assertEqual(len(flutter.calls), 1)

    def test_unknown_representation_fails_before_adapter_call(self):
        static = FakeAdapter()
        flutter = FakeAdapter()
        with self.assertRaises(SemanticRoutingError):
            route_program_model_operation(
                operation="get_function_context",
                arguments={
                    "job_id": "012345abcdef",
                    "representation": "native-unknown",
                    "entity_id": "pm:v1:function:test",
                },
                registry=self.registry,
                adapters={"static-core": static, "framework-flutter": flutter},
            )
        self.assertEqual(static.calls, [])
        self.assertEqual(flutter.calls, [])

    def test_flutter_adapter_builds_bounded_private_context_command(self):
        capability = FakeFlutterCapability(self.registry.get("framework-flutter"))
        adapter = FlutterAotAdapter(capability)
        payload = adapter.program_model_call(
            "get_function_context",
            {
                "job_id": "012345abcdef",
                "entity_id": "pm:v1:function:flutter",
                "ownership_scope": "application",
                "direction": "both",
                "relationship_kinds": ["XREF", "CALLS"],
                "relationship_limit": 20,
                "evidence_limit": 10,
                "source_line_limit": 80,
                "source_byte_limit": 8192,
                "response_budget_bytes": 65536,
                "cursor": "cursor-token",
            },
        )
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(len(capability.calls), 1)
        job_id, command, argv, timeout = capability.calls[0]
        self.assertEqual(job_id, "012345abcdef")
        self.assertEqual(command, "get_function_context")
        self.assertEqual(timeout, 300)
        self.assertEqual(argv[0], "pm:v1:function:flutter")
        self.assertIn("--relationship-limit", argv)
        self.assertIn("--source-byte-limit", argv)
        self.assertIn("--response-budget-bytes", argv)
        self.assertEqual(argv.count("--relationship-kind"), 2)
        self.assertIn("--cursor", argv)

    def test_flutter_adapter_rejects_unbounded_context_arguments_before_worker(self):
        capability = FakeFlutterCapability(self.registry.get("framework-flutter"))
        adapter = FlutterAotAdapter(capability)
        with self.assertRaises(Exception):
            adapter.program_model_call(
                "get_function_context",
                {
                    "job_id": "012345abcdef",
                    "entity_id": "pm:v1:function:flutter",
                    "response_budget_bytes": 9999999,
                },
            )
        self.assertEqual(capability.calls, [])


if __name__ == "__main__":
    unittest.main()
