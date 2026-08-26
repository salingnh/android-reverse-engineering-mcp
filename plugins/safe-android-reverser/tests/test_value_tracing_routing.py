#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
LIB_ROOT = PLUGIN_ROOT / "lib"
if str(LIB_ROOT) not in sys.path:
    sys.path.insert(0, str(LIB_ROOT))

from safe_reverser.registry import CapabilityRegistry
from safe_reverser.semantic_operations import (
    CONTROL_PLANE_SEMANTIC_OPERATIONS,
    VALUE_FLOW_ROUTABLE_REPRESENTATIONS,
    VALUE_FLOW_SEMANTIC_OPERATIONS,
)
from safe_reverser.semantic_router import SemanticRoutingError, route_program_model_operation
from safe_reverser.tool_catalog import load_named_tool_catalog


class FakeAdapter:
    def __init__(self):
        self.calls = []

    def program_model_call(self, name, args):
        self.calls.append((name, dict(args)))
        return {
            "status": "ok",
            "value_tracing_version": 1,
            "operation": name,
            "flow": {"flow_ir_version": 1},
        }


class ValueTracingRoutingTests(unittest.TestCase):
    def setUp(self):
        self.registry = CapabilityRegistry(PLUGIN_ROOT / "capabilities")

    def test_flow_operations_are_control_plane_owned_and_catalogued_once(self):
        self.assertEqual(
            VALUE_FLOW_SEMANTIC_OPERATIONS,
            {"trace_value", "find_source_to_sink"},
        )
        self.assertTrue(VALUE_FLOW_SEMANTIC_OPERATIONS.issubset(CONTROL_PLANE_SEMANTIC_OPERATIONS))
        self.assertEqual(VALUE_FLOW_ROUTABLE_REPRESENTATIONS, {"dex"})
        catalog = load_named_tool_catalog(
            PLUGIN_ROOT / "tool-catalogs",
            "control-plane",
        )
        names = [item["name"] for item in catalog]
        for operation in VALUE_FLOW_SEMANTIC_OPERATIONS:
            self.assertEqual(names.count(operation), 1)
            for manifest in self.registry.manifests().values():
                self.assertNotIn(operation, manifest.operations)

    def test_trace_value_routes_directly_to_static_core(self):
        static = FakeAdapter()
        flutter = FakeAdapter()
        capability_id, payload = route_program_model_operation(
            operation="trace_value",
            arguments={
                "job_id": "012345abcdef",
                "representation": "dex",
                "entity_id": "pm:v1:function:test",
                "seed": {"kind": "parameter", "index": 0},
            },
            registry=self.registry,
            adapters={"static-core": static, "framework-flutter": flutter},
        )
        self.assertEqual(capability_id, "static-core")
        self.assertEqual(payload["operation"], "trace_value")
        self.assertEqual(len(static.calls), 1)
        self.assertEqual(flutter.calls, [])
        self.assertNotIn("representation", static.calls[0][1])
        self.assertEqual(static.calls[0][1]["job_id"], "012345abcdef")

    def test_source_to_sink_routes_directly_to_static_core(self):
        static = FakeAdapter()
        capability_id, payload = route_program_model_operation(
            operation="find_source_to_sink",
            arguments={
                "job_id": "fedcba654321",
                "representation": "dex",
                "entity_id": "pm:v1:function:test",
                "source": {"kind": "parameter", "index": 0},
                "sink": {"kind": "return"},
            },
            registry=self.registry,
            adapters={"static-core": static},
        )
        self.assertEqual(capability_id, "static-core")
        self.assertEqual(payload["operation"], "find_source_to_sink")
        self.assertEqual(len(static.calls), 1)

    def test_flutter_flow_request_fails_before_adapter_call(self):
        static = FakeAdapter()
        flutter = FakeAdapter()
        with self.assertRaisesRegex(SemanticRoutingError, "not available"):
            route_program_model_operation(
                operation="trace_value",
                arguments={
                    "job_id": "012345abcdef",
                    "representation": "flutter-dart-aot",
                    "entity_id": "pm:v1:function:flutter",
                    "seed": {"kind": "return"},
                },
                registry=self.registry,
                adapters={"static-core": static, "framework-flutter": flutter},
            )
        self.assertEqual(static.calls, [])
        self.assertEqual(flutter.calls, [])

    def test_unknown_representation_fails_before_adapter_call(self):
        static = FakeAdapter()
        with self.assertRaises(SemanticRoutingError):
            route_program_model_operation(
                operation="find_source_to_sink",
                arguments={
                    "job_id": "012345abcdef",
                    "representation": "native-unknown",
                    "entity_id": "pm:v1:function:test",
                    "source": {"kind": "parameter", "index": 0},
                    "sink": {"kind": "return"},
                },
                registry=self.registry,
                adapters={"static-core": static},
            )
        self.assertEqual(static.calls, [])


if __name__ == "__main__":
    unittest.main()
