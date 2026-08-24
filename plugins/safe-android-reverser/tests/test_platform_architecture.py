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
from safe_reverser.adapters import _image_override
from safe_reverser.contracts import CapabilityManifest, ContractError, EvidenceEnvelope
from safe_reverser.control_plane import ControlPlane
from safe_reverser.evidence import normalize_capability_result
from safe_reverser.flutter import FlutterCapability
from safe_reverser.jobs import AnalysisJobStore, JobStoreError
import safe_reverser.jobs as jobs_module
from safe_reverser.paths import PathPolicyError, secure_child, secure_directory_root
from safe_reverser.registry import CapabilityRegistry
from safe_reverser.runtime import (
    ContainerRuntime,
    RunResult,
    RuntimeErrorSafe,
    VerifiedImage,
)
from safe_reverser.runtime_cache import (
    RuntimeCacheResolution,
    RuntimeCacheState,
    RuntimeIdentity,
)


class FakeRuntime:
    def __init__(self):
        self.required_labels = None
        self.image = None

    def ensure_image(self, image, *, required_labels):
        self.image = image
        self.required_labels = dict(required_labels)
        labels = dict(required_labels)
        labels.setdefault("org.opencontainers.image.revision", "f" * 40)
        return VerifiedImage(
            requested_ref=image,
            immutable_ref="sha256:" + "a" * 64,
            labels=labels,
        )

    def validate_tmpfs_spec(self, spec):
        ContainerRuntime.validate_tmpfs_spec(spec)

    def run_container(self, *, command, **_kwargs):
        if command != ["health"]:
            raise AssertionError(f"unexpected fake runtime command: {command}")
        payload = {
            "status": "ok",
            "network_required_at_runtime": False,
            "build_on_demand_allowed": False,
            "registry_selection_owned_by_worker": False,
            "required_runtime_constraints": {"network": "none"},
            "orchestration": {
                "runtime_download_inside_sandbox": False,
                "runtime_build_inside_sandbox": False,
            },
        }
        return RunResult(
            exit_code=0,
            timed_out=False,
            stdout=json.dumps(payload) + "\n",
            stderr="",
        )

    def parse_json_tail(self, run):
        return json.loads(run.stdout)


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

    def test_single_public_mcp_server_and_legacy_dual_controller_is_gone(self):
        manifest = json.loads((PLUGIN_ROOT / ".mcp.json").read_text(encoding="utf-8"))
        self.assertEqual(set(manifest["mcpServers"]), {"safe-android-reverser"})
        self.assertFalse((PLUGIN_ROOT / "bin" / "safe-flutter-mcp").exists())
        self.assertFalse((PLUGIN_ROOT / "bin" / "flutter-mcp-host.py").exists())

    def test_capability_spi_is_manifest_driven_and_operations_do_not_collide(self):
        static = self.registry.get("static-core")
        flutter = self.registry.get("framework-flutter")
        self.assertEqual(static.capability_api, CAPABILITY_API_VERSION)
        self.assertEqual(static.worker_abi, WORKER_ABI_VERSION)
        self.assertEqual(static.activation, "required")
        self.assertEqual(static.adapter, "mcp-container")
        self.assertEqual(flutter.capability_api, CAPABILITY_API_VERSION)
        self.assertEqual(flutter.worker_abi, WORKER_ABI_VERSION)
        self.assertEqual(flutter.activation, "required")
        self.assertEqual(flutter.adapter, "flutter-aot")
        self.assertEqual(flutter.protocol, "cli-json")
        self.assertNotIn("health", flutter.operations)
        self.assertEqual(
            self.registry.owner_for_operation("find_dart_symbols").capability_id,
            "framework-flutter",
        )

    def test_dynamic_contract_is_predeclared_but_static_driver_stays_offline(self):
        dynamic = CapabilityManifest.from_dict(
            {
                "id": "dynamic",
                "capability_api": 1,
                "worker_abi": 1,
                "representations": ["runtime-observation"],
                "trust_boundary": "dynamic-opt-in",
                "activation": "opt-in",
                "adapter": "mcp-container",
                "protocol": "mcp-stdio",
                "image": {"repository": "example.invalid/dynamic", "role": "dynamic"},
                "operations": ["observe_runtime"],
                "sandbox": {
                    "network": "controlled",
                    "read_only_root": True,
                    "drop_all_capabilities": True,
                    "no_new_privileges": True,
                },
            }
        )
        self.assertEqual(dynamic.activation, "opt-in")
        self.assertEqual(dynamic.sandbox.network, "controlled")
        runtime = ContainerRuntime(
            "docker", host_uid=os.getuid(), host_gid=os.getgid(), auto_pull=False
        )
        with self.assertRaises(RuntimeErrorSafe):
            runtime.locked_args(dynamic.sandbox)

        invalid_static = {
            "id": "native-test",
            "capability_api": 1,
            "worker_abi": 1,
            "representations": ["elf"],
            "trust_boundary": "native-static",
            "activation": "optional",
            "adapter": "mcp-container",
            "protocol": "mcp-stdio",
            "image": {"repository": "example.invalid/native", "role": "native-test"},
            "operations": ["inspect_elf"],
            "sandbox": {"network": "controlled"},
        }
        with self.assertRaises(ContractError):
            CapabilityManifest.from_dict(invalid_static)

    def test_locked_runtime_policy_never_mounts_a_runtime_socket(self):
        runtime = ContainerRuntime(
            "docker", host_uid=os.getuid(), host_gid=os.getgid(), auto_pull=False
        )
        args = runtime.locked_args(self.registry.get("framework-flutter").sandbox)
        joined = " ".join(args)
        self.assertIn("--network=none", args)
        self.assertIn("--read-only", args)
        self.assertIn("--cap-drop=ALL", args)
        self.assertIn("--security-opt=no-new-privileges", args)
        self.assertNotIn("docker.sock", joined)
        self.assertNotIn("podman.sock", joined)

    def test_runtime_driver_requires_interactive_for_stdio_workers(self):
        runtime = ContainerRuntime(
            "docker", host_uid=os.getuid(), host_gid=os.getgid(), auto_pull=False
        )
        with mock.patch.object(runtime, "_validate_image"), mock.patch(
            "safe_reverser.runtime.subprocess.run"
        ) as run:
            run.return_value.returncode = 0
            runtime.run_container(
                image="fixture:ci",
                policy=self.registry.get("static-core").sandbox,
                mounts=[(self.project, "/workspace", "ro")],
                command=[],
                timeout=10,
                stdin_lines=[{"jsonrpc": "2.0", "id": 1, "method": "ping"}],
            )
        argv = run.call_args.args[0]
        self.assertIn("--interactive", argv)

    def test_runtime_driver_rejects_untyped_tmpfs_options(self):
        runtime = ContainerRuntime(
            "docker", host_uid=os.getuid(), host_gid=os.getgid(), auto_pull=False
        )
        runtime.validate_tmpfs_spec("/output:rw,nosuid,nodev,size=4g")
        with self.assertRaises(RuntimeErrorSafe):
            runtime.validate_tmpfs_spec("/output:rw,exec,size=4g")
        with self.assertRaises(RuntimeErrorSafe):
            runtime.validate_tmpfs_spec("/output:rw,nosuid,nodev,size=4g,exec")

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

    def test_data_root_rejects_symlinked_parent_component(self):
        real = self.root / "real-data"
        real.mkdir()
        link = self.root / "data-link"
        try:
            link.symlink_to(real, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(PathPolicyError):
            secure_directory_root(link / "nested", create=True)
        self.assertFalse((real / "nested").exists())

    def test_job_store_has_hard_directory_scan_budget(self):
        store = AnalysisJobStore(self.data, "scan-test")
        old = jobs_module.MAX_JOB_SCAN
        jobs_module.MAX_JOB_SCAN = 2
        try:
            for name in ("a", "b", "c"):
                (store.root / name).mkdir()
            with self.assertRaises(JobStoreError):
                store.list()
        finally:
            jobs_module.MAX_JOB_SCAN = old

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

    def test_result_normalization_preserves_private_schema_and_adds_shared_evidence(self):
        native = {
            "status": "ok",
            "provenance": {
                "analysis_id": "flutter-aot:" + "b" * 64,
                "artifact_sha256": "b" * 64,
                "evidence_state": "derived",
                "analyzer": "safe-flutter-semantic",
            },
            "results": [{"name": "ApiClient.request"}],
        }
        result = normalize_capability_result(
            capability_id="framework-flutter",
            operation="find_dart_symbols",
            producer_version="0.3.0",
            payload=native,
        )
        self.assertEqual(result["results"], native["results"])
        contract = result["safe_reverser_contract"]
        self.assertEqual(contract["capability_api"], 1)
        self.assertEqual(contract["worker_abi"], 1)
        evidence = result["evidence_envelope"]
        self.assertEqual(evidence["producer"], "framework-flutter")
        self.assertEqual(evidence["evidence_state"], "derived")
        self.assertEqual(evidence["artifact_sha256"], "b" * 64)

    def test_result_normalizer_does_not_invent_evidence_state(self):
        result = normalize_capability_result(
            capability_id="static-core",
            operation="fingerprint",
            producer_version="0.3.0",
            payload={
                "status": "ok",
                "provenance": {
                    "analysis_id": "x",
                    "artifact_sha256": "a" * 64,
                },
            },
        )
        self.assertIn("safe_reverser_contract", result)
        self.assertNotIn("evidence_envelope", result)

    def test_worker_images_publish_capability_api_and_worker_abi_labels(self):
        static = (REPO_ROOT / "sandbox" / "Dockerfile").read_text(encoding="utf-8")
        flutter = (REPO_ROOT / "frameworks" / "flutter" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        runtime = (
            REPO_ROOT / "frameworks" / "flutter" / "Dockerfile.runtime"
        ).read_text(encoding="utf-8")
        for text, capability_id in (
            (static, "static-core"),
            (flutter, "framework-flutter"),
            (runtime, "framework-flutter"),
        ):
            self.assertIn(
                f'io.safe-reverser.capability.id="{capability_id}"', text
            )
            self.assertIn('io.safe-reverser.capability.api="1"', text)
            self.assertIn('io.safe-reverser.worker.abi="1"', text)
        self.assertIn('io.safe-reverser.runtime-cache.schema="3"', runtime)
        self.assertIn('io.safe-reverser.dart.os="${TARGET_OS}"', runtime)

    def test_flutter_worker_does_not_own_registry_selection(self):
        adapter = (
            REPO_ROOT / "frameworks" / "flutter" / "safe_blutter_adapter.py"
        ).read_text(encoding="utf-8")
        host_adapter = (
            PLUGIN_ROOT / "lib" / "safe_reverser" / "flutter.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("SAFE_FLUTTER_IMAGE_REPOSITORY", adapter)
        self.assertNotIn("ghcr.io/salingnh/safe-android-reverser-flutter", adapter)
        self.assertNotIn('"recommended_image"', adapter)
        self.assertNotIn("SAFE_FLUTTER_IMAGE_REPOSITORY", host_adapter)

    def test_controlled_builder_is_deduplicated_outside_worker_boundary(self):
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "build-flutter-runtime-cache.yml"
        ).read_text(encoding="utf-8")
        flutter_host = (
            PLUGIN_ROOT / "lib" / "safe_reverser" / "flutter.py"
        ).read_text(encoding="utf-8")
        provider = (
            PLUGIN_ROOT / "lib" / "safe_reverser" / "controlled_build.py"
        ).read_text(encoding="utf-8")
        self.assertIn("run-name: Runtime cache ${{ inputs.request_identity }}", workflow)
        self.assertIn(
            "group: flutter-runtime-cache-${{ inputs.request_identity }}", workflow
        )
        for field in (
            "request_identity",
            "dart_version",
            "snapshot_hash",
            "arch",
            "os",
            "compressed_pointers",
            "blutter_commit",
            "runtime_cache_schema",
            "capability_api",
            "worker_abi",
        ):
            self.assertIn(f"      {field}:", workflow)
        self.assertNotIn("GitHub", flutter_host)
        self.assertNotIn("workflow_run_id", flutter_host)
        self.assertIn("class GitHubActionsControlledBuildProvider", provider)
        self.assertNotIn("run_container", provider)

    def test_generic_capability_image_override_precedes_compat_alias(self):
        manifest = self.registry.get("framework-flutter")
        with mock.patch.dict(
            os.environ,
            {
                "SAFE_REVERSER_CAPABILITY_IMAGE_FRAMEWORK_FLUTTER": "example.invalid/flutter:generic",
                "SAFE_REVERSER_FLUTTER_IMAGE": "example.invalid/flutter:legacy",
            },
            clear=False,
        ):
            self.assertEqual(
                _image_override(manifest), "example.invalid/flutter:generic"
            )

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
        prepared["runtime"]["cache_tag"] = RuntimeIdentity(
            dart_version="3.5.4",
            snapshot_hash="b" * 32,
            arch="arm64",
            os="android",
            compressed_pointers=True,
            blutter_commit="c" * 40,
            runtime_cache_schema=3,
            capability_api=1,
            worker_abi=1,
        ).cache_tag
        image, dart_runtime, commit = capability._runtime_image(prepared)
        self.assertTrue(
            image.startswith("ghcr.io/salingnh/safe-android-reverser-flutter:")
        )
        self.assertEqual(commit, "c" * 40)
        resolution = capability._resolve_runtime_cache(image, dart_runtime, commit)
        self.assertEqual(resolution.state, RuntimeCacheState.READY)
        self.assertEqual(runtime.required_labels["io.safe-reverser.worker.abi"], "1")
        self.assertEqual(
            runtime.required_labels["io.safe-reverser.runtime-cache.schema"], "3"
        )
        self.assertEqual(runtime.required_labels["io.safe-reverser.dart.os"], "android")

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

        with mock.patch.object(
            capability, "ensure_base_ready", return_value={}
        ), mock.patch.object(
            capability, "_prepare", side_effect=fake_prepare
        ), mock.patch.object(
            capability,
            "_resolve_runtime_cache",
            return_value=RuntimeCacheResolution(
                RuntimeCacheState.READY,
                "f" * 64,
                "example.invalid/flutter:fixture",
                image=VerifiedImage(
                    "example.invalid/flutter:fixture",
                    "sha256:" + "f" * 64,
                    {"org.opencontainers.image.revision": "e" * 40},
                ),
            ),
        ), mock.patch.object(
            capability,
            "_execute",
            return_value={
                "status": "ok",
                "analysis_id": "flutter-aot:" + "e" * 64,
            },
        ):
            result = capability.analyze(
                {"artifact": "app.apk", "timeout_seconds": 60}
            )
        self.assertEqual(result["status"], "ok")
        job = capability.jobs.get(result["job_id"])
        self.assertFalse((job / "input").exists())
        self.assertEqual(capability.jobs.read(job)["status"], "ok")

    def test_flutter_cache_build_state_is_semantic_and_credential_free(self):
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
                "dart_version": "3.11.1",
                "os": "android",
                "arch": "arm64",
                "snapshot_hash": "b" * 32,
                "compressed_pointers": True,
                "cache_tag": "dart-3.11.1-arm64-cp-" + "d" * 64,
            },
        }

        def fake_prepare(job, _artifact):
            (job / "input").mkdir()
            return prepared

        secret = "stage-a-builder-secret"
        with mock.patch.dict(
            os.environ,
            {"SAFE_REVERSER_CONTROLLED_BUILD_TOKEN": secret},
            clear=False,
        ), mock.patch.object(
            capability, "_prepare", side_effect=fake_prepare
        ), mock.patch.object(
            capability,
            "_resolve_runtime_cache",
            return_value=RuntimeCacheResolution(
                RuntimeCacheState.BUILDING,
                "e" * 64,
                "example.invalid/flutter:fixture",
            ),
        ):
            result = capability.analyze(
                {"artifact": "app.apk", "timeout_seconds": 60}
            )
        self.assertEqual(result["status"], "runtime_cache_building")
        self.assertEqual(result["runtime_cache"]["state"], "BUILDING")
        serialized = json.dumps(result)
        self.assertNotIn(secret, serialized)
        self.assertNotIn("GitHub", serialized)
        job = capability.jobs.get(result["job_id"])
        self.assertNotIn(secret, (job / "job.json").read_text(encoding="utf-8"))

    def test_control_plane_is_adapter_registry_driven(self):
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
        self.assertEqual(set(plane.adapters), {"static-core", "framework-flutter"})
        self.assertFalse(hasattr(plane, "static"))
        self.assertFalse(hasattr(plane, "flutter"))
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
