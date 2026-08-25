#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
LIB_ROOT = PLUGIN_ROOT / "lib"
if str(LIB_ROOT) not in sys.path:
    sys.path.insert(0, str(LIB_ROOT))

from safe_reverser.control_plane import ControlPlane
from safe_reverser.registry import CapabilityRegistry
from safe_reverser.semantic_operations import (
    CONTROL_PLANE_CATALOG_OPERATIONS,
    CONTROL_PLANE_SEMANTIC_OPERATIONS,
)
from safe_reverser.semantic_router import (
    SemanticRoutingError,
    route_program_model_operation,
)
from safe_reverser.tool_catalog import load_named_tool_catalog


class FakeAdapter:
    def __init__(self, manifest, *, fail=False):
        self.manifest = manifest
        self.fail = fail
        self.calls = []

    def tools(self):
        raise AssertionError("semantic routing test must not need public worker discovery")

    def program_model_call(self, name, args):
        self.calls.append((name, dict(args)))
        if self.fail:
            raise RuntimeError("job not found in selected capability")
        return {
            "status": "ok",
            "application_map_version": 1,
            "program_model_version": 1,
            "snapshot_id": "pms:test",
            "nodes": [],
            "edges": [],
        }


class NeverStartPublicAdapter:
    def __init__(self, public_tools):
        self.public_tools = public_tools

    def tools(self):
        return [dict(item) for item in self.public_tools]


class ApplicationMapRoutingTests(unittest.TestCase):
    def setUp(self):
        self.registry = CapabilityRegistry(PLUGIN_ROOT / "capabilities")
        self.control_catalog = load_named_tool_catalog(
            PLUGIN_ROOT / "tool-catalogs",
            "control-plane",
            expected_operations=CONTROL_PLANE_CATALOG_OPERATIONS,
        )

    def test_map_operations_are_control_plane_owned_only(self):
        names = {item["name"] for item in self.control_catalog}
        self.assertEqual(names, set(CONTROL_PLANE_CATALOG_OPERATIONS))
        self.assertTrue(CONTROL_PLANE_SEMANTIC_OPERATIONS.issubset(names))
        for manifest in self.registry.manifests().values():
            self.assertFalse(
                CONTROL_PLANE_SEMANTIC_OPERATIONS.intersection(manifest.operations)
            )

    def test_control_plane_tools_contains_each_semantic_operation_once_without_runtime(self):
        plane = ControlPlane.__new__(ControlPlane)
        plane._control_plane_tools = self.control_catalog
        plane.adapters = {
            "fake": NeverStartPublicAdapter(
                [
                    {
                        "name": "fake_public_tool",
                        "description": "fake",
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "additionalProperties": False,
                        },
                    }
                ]
            )
        }
        names = [item["name"] for item in plane.tools()]
        for operation in CONTROL_PLANE_SEMANTIC_OPERATIONS:
            self.assertEqual(names.count(operation), 1)
        self.assertEqual(names.count("health"), 1)
        self.assertEqual(names.count("list_capabilities"), 1)

    def test_representation_routes_to_exact_capability_and_is_removed_from_worker_args(self):
        static = FakeAdapter(self.registry.get("static-core"))
        flutter = FakeAdapter(self.registry.get("framework-flutter"))
        adapters = {"static-core": static, "framework-flutter": flutter}
        capability_id, payload = route_program_model_operation(
            operation="get_application_map",
            arguments={"job_id": "012345abcdef", "representation": "dex"},
            registry=self.registry,
            adapters=adapters,
        )
        self.assertEqual(capability_id, "static-core")
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(len(static.calls), 1)
        self.assertEqual(flutter.calls, [])
        self.assertNotIn("representation", static.calls[0][1])

        capability_id, _ = route_program_model_operation(
            operation="get_application_map",
            arguments={
                "job_id": "fedcba654321",
                "representation": "flutter-dart-aot",
            },
            registry=self.registry,
            adapters=adapters,
        )
        self.assertEqual(capability_id, "framework-flutter")
        self.assertEqual(len(flutter.calls), 1)

    def test_unknown_representation_fails_before_any_capability_call(self):
        static = FakeAdapter(self.registry.get("static-core"))
        flutter = FakeAdapter(self.registry.get("framework-flutter"))
        with self.assertRaises(SemanticRoutingError):
            route_program_model_operation(
                operation="get_application_map",
                arguments={"job_id": "012345abcdef", "representation": "unknown-vm"},
                registry=self.registry,
                adapters={"static-core": static, "framework-flutter": flutter},
            )
        self.assertEqual(static.calls, [])
        self.assertEqual(flutter.calls, [])

    def test_selected_capability_failure_does_not_probe_other_job_stores(self):
        static = FakeAdapter(self.registry.get("static-core"), fail=True)
        flutter = FakeAdapter(self.registry.get("framework-flutter"))
        with self.assertRaises(RuntimeError):
            route_program_model_operation(
                operation="expand_application_node",
                arguments={
                    "job_id": "012345abcdef",
                    "representation": "dex",
                    "entity_id": "pm:v1:function:test",
                },
                registry=self.registry,
                adapters={"static-core": static, "framework-flutter": flutter},
            )
        self.assertEqual(len(static.calls), 1)
        self.assertEqual(flutter.calls, [])

    def test_ambiguous_representation_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("static-core", "framework-flutter"):
                raw = json.loads(
                    (PLUGIN_ROOT / "capabilities" / f"{name}.json").read_text(
                        encoding="utf-8"
                    )
                )
                if name == "framework-flutter":
                    raw["representations"].append("dex")
                (root / f"{name}.json").write_text(
                    json.dumps(raw), encoding="utf-8"
                )
            ambiguous = CapabilityRegistry(root)
            with self.assertRaisesRegex(Exception, "ambiguous"):
                ambiguous.owner_for_representation("dex")


if __name__ == "__main__":
    unittest.main()
