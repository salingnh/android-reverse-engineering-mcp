#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PLUGIN_ROOT.parents[1]
LIB_ROOT = PLUGIN_ROOT / "lib"
if str(LIB_ROOT) not in sys.path:
    sys.path.insert(0, str(LIB_ROOT))

from safe_reverser import CAPABILITY_API_VERSION, WORKER_ABI_VERSION
from safe_reverser.contracts import ContractError, EvidenceEnvelope
from safe_reverser.control_plane import ControlPlane
from safe_reverser.flutter import FlutterCapability
from safe_reverser.paths import PathPolicyError, secure_child
from safe_reverser.registry import CapabilityRegistry
from safe_reverser.runtime import ContainerRuntime, RunResult


class FakeRuntime:
    def __init__(self):
        self.required_labels = None
        self.image = None

    def ensure_image(self, image, *, required_labels):
        self.image = image
        self.required_labels = dict(required_labels)
        return dict(required_labels)


class PlatformArchitectureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.project = self.root / "project"
        self.data = self.root / "data"
        self.project.mkdir()
        self.data.mkdir()
        self.artifact = self.project / "app.apk"
        self.artifact.write_bytes(b"fixture")
        self.registry = CapabilityRegistry(PLUGIN_ROOT / "capabilities")

    def tearDown(self):
        self.tmp.cleanup()

    def test_single_public_mcp_server(self):
        manifest = json.loads((PLUGIN_ROOT / ".mcp.json").read_text(encoding="utf-8"))
        self.assertEqual(set(manifest["mcpServers"]), {"safe-android-reverser"})

    def test_capability_spi_is_manifest_driven_and_operations_do_not_collide(self):
        static = self.registry.get("static-core")
        flutter = self.registry.get("framework-flutter")
        self.assertEqual(static.capability_api, CAPABILITY_API_VERSION)
        self.assertEqual(static.worker_abi, WORKER_ABI_VERSION)
        self.assertEqual(flutter.capability_api, CAPABILITY_API_VERSION)
        self.assertEqual(flutter.worker_abi, WORKER_ABI_VERSION)
        self.assertEqual(flutter.protocol, "cli-json")
        self.assertNotIn("health", flutter.operations)
        self.assertEqual(
            self.registry.owner_for_operation("find_dart_symbols").capability_id,
            "framework-flutter",
        )

    def test_locked_runtime_policy_never_mounts_a_runtime_socket(self):
        runtime = ContainerRuntime("docker", host_uid=os.getuid(), host_gid=os.getgid(), auto_pull=False)
        args = runtime.locked_args(self.registry.get("framework-flutter").sandbox)
        joined = " ".join(args)
        self.assertIn("--network=none", args)
        self.assertIn("--read-only", args)
        self.assertIn("--cap-drop=ALL", args)
        self.assertIn("--security-opt=no-new-privileges", args)
        self.assertNotIn("docker.sock", joined)
        self.assertNotIn("podman.sock", joined)

    def test_shared_path_policy_rejects_escape_and_symlink(self):
        with self.assertRaises(PathPolicyError):
            secure_child(self.project, "../outside.apk")
        link = self.project / "linked.apk"
        try:
            link.symlink_to(self.artifact.name)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(PathPolicyError):
            secure_child(self.project, "linked.apk")

    def test_evidence_envelope_has_stable_common_contract(self):
        envelope = EvidenceEnvelope(
            analysis_id="analysis:fixture",
            artifact_sha256="a" * 64,
            producer="fixture-worker",
            producer_version="1",
            evidence_state="observed",
            payload={"node": "example"},
        ).to_dict()
        self.assertEqual(envelope["schema_version"], 1)
        self.assertEqual(envelope["evidence_state"], "observed")
        with self.assertRaises(ContractError):
            EvidenceEnvelope(
                analysis_id="analysis:fixture",
                artifact_sha256="a" * 64,
                producer="fixture-worker",
                producer_version="1",
                evidence_state="confidence-0.9",
                payload={},
            ).to_dict()

    def test_worker_images_publish_capability_api_and_worker_abi_labels(self):
        static = (REPO_ROOT / "sandbox" / "Dockerfile").read_text(encoding="utf-8")
        flutter = (REPO_ROOT / "frameworks" / "flutter" / "Dockerfile").read_text(encoding="utf-8")
        runtime = (REPO_ROOT / "frameworks" / "flutter" / "Dockerfile.runtime").read_text(encoding="utf-8")
        for text, capability_id in (
            (static, "static-core"),
            (flutter, "framework-flutter"),
            (runtime, "framework-flutter"),
        ):
            self.assertIn(f'io.safe-reverser.capability.id="{capability_id}"', text)
            self.assertIn('io.safe-reverser.capability.api="1"', text)
            self.assertIn('io.safe-reverser.worker.abi="1"', text)
        self.assertIn('io.safe-reverser.runtime-cache.schema="2"', runtime)

    def test_flutter_worker_does_not_own_registry_selection(self):
        adapter = (REPO_ROOT / "frameworks" / "flutter" / "safe_blutter_adapter.py").read_text(encoding="utf-8")
        self.assertNotIn("SAFE_FLUTTER_IMAGE_REPOSITORY", adapter)
        self.assertNotIn("ghcr.io/salingnh/safe-android-reverser-flutter", adapter)
        self.assertNotIn('"recommended_image"', adapter)

    def test_flutter_runtime_image_is_selected_by_control_plane(self):
        runtime = FakeRuntime()
        capability = FlutterCapability(
            runtime,
            self.registry.get("framework-flutter"),
            version="0.3.0",
            project_dir=self.project,
            data_dir=self.data,
        )
        prepared = {
            "blutter_commit": "c" * 40,
            "runtime": {
                "identity_status": "identified",
                "dart_version": "3.5.4",
                "os": "android",
                "arch": "arm64",
                "snapshot_hash": "b" * 32,
                "compressed_pointers": True,
                "cache_tag": "dart-3.5.4-arm64-cp-" + "d" * 64,
            },
        }
        image, dart_runtime, commit = capability._runtime_image(prepared)
        self.assertTrue(image.startswith("ghcr.io/salingnh/safe-android-reverser-flutter:"))
        self.assertEqual(commit, "c" * 40)
        ready, _ = capability._ensure_runtime_ready(image, dart_runtime, commit)
        self.assertTrue(ready)
        self.assertEqual(runtime.required_labels["io.safe-reverser.worker.abi"], "1")
        self.assertEqual(runtime.required_labels["io.safe-reverser.runtime-cache.schema"], "2")

    def test_flutter_analysis_uses_shared_job_store_and_cleans_prepared_input(self):
        runtime = FakeRuntime()
        capability = FlutterCapability(
            runtime,
            self.registry.get("framework-flutter"),
            version="0.3.0",
            project_dir=self.project,
            data_dir=self.data,
        )
        prepared = {
            "status": "runtime_cache_miss",
            "profile": "framework-flutter",
            "blutter_commit": "c" * 40,
            "runtime": {
                "identity_status": "identified",
                "dart_version": "3.5.4",
                "os": "android",
                "arch": "arm64",
                "snapshot_hash": "b" * 32,
                "compressed_pointers": True,
                "cache_tag": "dart-3.5.4-arm64-cp-" + "d" * 64,
            },
        }

        def fake_prepare(job, _artifact):
            (job / "input").mkdir()
            (job / "input" / "libapp.so").write_bytes(b"app")
            return prepared

        with mock.patch.object(capability, "ensure_base_ready", return_value={}), mock.patch.object(
            capability, "_prepare", side_effect=fake_prepare
        ), mock.patch.object(
            capability, "_ensure_runtime_ready", return_value=(True, "ready")
        ), mock.patch.object(
            capability, "_execute", return_value={"status": "ok", "analysis_id": "flutter-aot:" + "e" * 64}
        ):
            result = capability.analyze({"artifact": "app.apk", "timeout_seconds": 60})
        self.assertEqual(result["status"], "ok")
        job = capability.jobs.get(result["job_id"])
        self.assertFalse((job / "input").exists())
        self.assertEqual(capability.jobs.read(job)["status"], "ok")

    def test_control_plane_enriches_static_route_with_discovered_state(self):
        env = {
            "SAFE_REVERSER_PROJECT_DIR": str(self.project),
            "SAFE_REVERSER_DATA_DIR": str(self.data),
            "SAFE_REVERSER_RUNTIME": "docker",
            "SAFE_REVERSER_AUTO_PULL": "0",
        }
        with mock.patch.dict(os.environ, env, clear=False), mock.patch(
            "safe_reverser.control_plane.shutil.which", return_value="/usr/bin/docker"
        ):
            plane = ControlPlane(PLUGIN_ROOT)
        with mock.patch.object(
            plane,
            "_capability_states",
            return_value={
                "static-core": {"state": "ready"},
                "framework-flutter": {"state": "ready", "image": "fixture"},
            },
        ):
            payload = plane._enrich_route(
                {
                    "analysis_route": {
                        "primary_capability_id": "framework-flutter",
                        "primary_profile_status": "declared",
                        "secondary_profiles": [],
                    }
                }
            )
        route = payload["analysis_route"]
        self.assertEqual(route["primary_profile_status"], "declared")
        self.assertEqual(route["primary_capability_state"], "ready")


if __name__ == "__main__":
    unittest.main()
