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
    SECURITY_ROUTABLE_REPRESENTATIONS,
    SECURITY_SEMANTIC_OPERATIONS,
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
            "security_semantics_version": 1,
            "operation": name,
        }


class SecuritySemanticRoutingTests(unittest.TestCase):
    def setUp(self):
        self.registry = CapabilityRegistry(PLUGIN_ROOT / "capabilities")

    def test_security_operations_are_control_plane_owned_once(self):
        self.assertEqual(SECURITY_SEMANTIC_OPERATIONS, {"find_auth_flow", "trace_crypto"})
        self.assertEqual(SECURITY_ROUTABLE_REPRESENTATIONS, {"dex"})
        self.assertTrue(
            SECURITY_SEMANTIC_OPERATIONS.issubset(CONTROL_PLANE_SEMANTIC_OPERATIONS)
        )
        catalog = load_named_tool_catalog(PLUGIN_ROOT / "tool-catalogs", "control-plane")
        names = [item["name"] for item in catalog]
        for operation in SECURITY_SEMANTIC_OPERATIONS:
            self.assertEqual(names.count(operation), 1)
            for manifest in self.registry.manifests().values():
                self.assertNotIn(operation, manifest.operations)

    def test_auth_flow_routes_to_static_core(self):
        static = FakeAdapter()
        flutter = FakeAdapter()
        capability_id, payload = route_program_model_operation(
            operation="find_auth_flow",
            arguments={
                "job_id": "012345abcdef",
                "representation": "dex",
                "entity_id": "pm:v1:function:test",
                "focus": "bearer",
            },
            registry=self.registry,
            adapters={"static-core": static, "framework-flutter": flutter},
        )
        self.assertEqual(capability_id, "static-core")
        self.assertEqual(payload["operation"], "find_auth_flow")
        self.assertEqual(len(static.calls), 1)
        self.assertEqual(flutter.calls, [])
        self.assertNotIn("representation", static.calls[0][1])

    def test_crypto_routes_to_static_core(self):
        static = FakeAdapter()
        capability_id, payload = route_program_model_operation(
            operation="trace_crypto",
            arguments={
                "job_id": "fedcba654321",
                "representation": "dex",
                "entity_id": "pm:v1:function:test",
                "family": "hmac",
            },
            registry=self.registry,
            adapters={"static-core": static},
        )
        self.assertEqual(capability_id, "static-core")
        self.assertEqual(payload["operation"], "trace_crypto")

    def test_flutter_security_request_fails_before_adapter_call(self):
        static = FakeAdapter()
        flutter = FakeAdapter()
        with self.assertRaisesRegex(SemanticRoutingError, "not available"):
            route_program_model_operation(
                operation="find_auth_flow",
                arguments={
                    "job_id": "012345abcdef",
                    "representation": "flutter-dart-aot",
                    "entity_id": "pm:v1:function:flutter",
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
                operation="trace_crypto",
                arguments={
                    "job_id": "012345abcdef",
                    "representation": "native-unknown",
                    "entity_id": "pm:v1:function:test",
                },
                registry=self.registry,
                adapters={"static-core": static},
            )
        self.assertEqual(static.calls, [])


if __name__ == "__main__":
    unittest.main()
