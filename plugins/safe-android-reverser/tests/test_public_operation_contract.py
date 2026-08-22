#!/usr/bin/env python3
from __future__ import annotations

import copy
import os
import sys
import unittest
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
LIB_ROOT = PLUGIN_ROOT / "lib"
if str(LIB_ROOT) not in sys.path:
    sys.path.insert(0, str(LIB_ROOT))

from safe_reverser.contracts import (
    RESERVED_PUBLIC_OPERATIONS,
    CapabilityManifest,
    ContractError,
)
from safe_reverser.registry import CapabilityRegistry
from safe_reverser.runtime import ContainerRuntime, RuntimeErrorSafe


class PublicOperationContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = CapabilityRegistry(PLUGIN_ROOT / "capabilities")

    def test_reserved_control_plane_operations_have_no_capability_owner(self) -> None:
        self.assertEqual(RESERVED_PUBLIC_OPERATIONS, {"health", "list_capabilities"})
        for manifest in self.registry.manifests().values():
            self.assertFalse(RESERVED_PUBLIC_OPERATIONS.intersection(manifest.operations))
        with self.assertRaises(ContractError):
            self.registry.owner_for_operation("health")
        with self.assertRaises(ContractError):
            self.registry.owner_for_operation("list_capabilities")

    def test_static_worker_health_is_internal_not_public_capability_operation(self) -> None:
        self.assertNotIn("health", self.registry.get("static-core").operations)

    def test_manifest_requires_explicit_activation_adapter_and_strict_contract_types(self) -> None:
        manifest = self.registry.get("static-core")
        base = {
            "id": manifest.capability_id,
            "capability_api": manifest.capability_api,
            "worker_abi": manifest.worker_abi,
            "representations": list(manifest.representation),
            "trust_boundary": manifest.trust_boundary,
            "activation": manifest.activation,
            "adapter": manifest.adapter,
            "protocol": manifest.protocol,
            "image": {
                "repository": manifest.image_repository,
                "role": manifest.image_role,
            },
            "operations": list(manifest.operations),
            "sandbox": {
                "network": manifest.sandbox.network,
                "read_only_root": manifest.sandbox.read_only_root,
                "drop_all_capabilities": manifest.sandbox.drop_all_capabilities,
                "no_new_privileges": manifest.sandbox.no_new_privileges,
                "memory": manifest.sandbox.memory,
                "cpus": manifest.sandbox.cpus,
                "pids_limit": manifest.sandbox.pids_limit,
                "tmpfs_tmp": manifest.sandbox.tmpfs_tmp,
                "tmpfs_work": manifest.sandbox.tmpfs_work,
            },
        }
        missing_activation = copy.deepcopy(base)
        missing_activation.pop("activation")
        with self.assertRaises(ContractError):
            CapabilityManifest.from_dict(missing_activation)

        bad_api_type = copy.deepcopy(base)
        bad_api_type["capability_api"] = True
        with self.assertRaises(ContractError):
            CapabilityManifest.from_dict(bad_api_type)

        bad_boolean_type = copy.deepcopy(base)
        bad_boolean_type["sandbox"]["read_only_root"] = "true"
        with self.assertRaises(ContractError):
            CapabilityManifest.from_dict(bad_boolean_type)

    def test_dynamic_controlled_network_is_schema_ready_but_static_runtime_rejects_it(self) -> None:
        static = self.registry.get("static-core")
        raw = {
            "id": "dynamic-test",
            "capability_api": static.capability_api,
            "worker_abi": static.worker_abi,
            "representations": ["runtime-events"],
            "trust_boundary": "dynamic-opt-in",
            "activation": "opt-in",
            "adapter": "mcp-container",
            "protocol": "mcp-stdio",
            "image": {
                "repository": "ghcr.io/example/dynamic-test",
                "role": "dynamic-test",
            },
            "operations": ["observe_runtime"],
            "sandbox": {
                "network": "controlled",
                "read_only_root": True,
                "drop_all_capabilities": True,
                "no_new_privileges": True,
                "memory": "4g",
                "cpus": "2",
                "pids_limit": 256,
                "tmpfs_tmp": "1g",
                "tmpfs_work": "1g",
            },
        }
        dynamic = CapabilityManifest.from_dict(raw)
        self.assertEqual(dynamic.activation, "opt-in")
        self.assertEqual(dynamic.sandbox.network, "controlled")
        runtime = ContainerRuntime(
            "docker", host_uid=os.getuid(), host_gid=os.getgid(), auto_pull=False
        )
        with self.assertRaises(RuntimeErrorSafe):
            runtime.locked_args(dynamic.sandbox)


if __name__ == "__main__":
    unittest.main()
