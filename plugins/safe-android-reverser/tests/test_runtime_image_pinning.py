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
LIB_ROOT = PLUGIN_ROOT / "lib"
if str(LIB_ROOT) not in sys.path:
    sys.path.insert(0, str(LIB_ROOT))

from safe_reverser.flutter import FlutterCapability
from safe_reverser.registry import CapabilityRegistry
from safe_reverser.runtime import ContainerRuntime, RunResult, VerifiedImage
from safe_reverser.worker import INTERNAL_MCP_OPERATIONS, McpContainerWorker


class InspectRuntime(ContainerRuntime):
    def __init__(self) -> None:
        super().__init__("docker", host_uid=1000, host_gid=1000, auto_pull=False)

    def image_info(self, image: str):
        return {
            "Id": "a" * 64,
            "Config": {"Labels": {"contract": "ok"}},
        }


class FakeWorkerRuntime:
    def __init__(self, manifest) -> None:
        self.manifest = manifest
        self.images: list[str] = []
        self.verified = VerifiedImage(
            requested_ref="example.invalid/static:test",
            immutable_ref="sha256:" + "b" * 64,
            labels={
                "org.opencontainers.image.version": "0.3.0",
                "io.safe-reverser.capability.id": manifest.capability_id,
                "io.safe-reverser.capability.api": str(manifest.capability_api),
                "io.safe-reverser.worker.abi": str(manifest.worker_abi),
            },
        )

    def ensure_image(self, image, *, required_labels):
        self.requested = image
        self.required_labels = required_labels
        return self.verified

    def run_container(self, *, image, stdin_lines, **_kwargs):
        self.images.append(image)
        self.last_worker_env = dict(_kwargs.get("env") or {})
        request = stdin_lines[-1]
        request_id = request["id"]
        if request["method"] == "tools/list":
            names = sorted(set(self.manifest.operations) | set(INTERNAL_MCP_OPERATIONS))
            result = {"tools": [{"name": name} for name in names]}
        else:
            result = {
                "content": [{"type": "text", "text": json.dumps({"status": "ok"})}],
                "isError": False,
            }
        return RunResult(
            exit_code=0,
            timed_out=False,
            stdout=json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}) + "\n",
            stderr="",
        )


class FakeFlutterRuntime:
    def __init__(self, manifest) -> None:
        self.images: list[str] = []
        self.verified = VerifiedImage(
            requested_ref="example.invalid/flutter:test",
            immutable_ref="sha256:" + "c" * 64,
            labels={
                "org.opencontainers.image.version": "0.3.0",
                "io.safe-reverser.capability.id": manifest.capability_id,
                "io.safe-reverser.capability.api": str(manifest.capability_api),
                "io.safe-reverser.worker.abi": str(manifest.worker_abi),
            },
        )

    def validate_tmpfs_spec(self, spec):
        ContainerRuntime.validate_tmpfs_spec(spec)

    def ensure_image(self, image, *, required_labels):
        self.requested = image
        self.required_labels = required_labels
        return self.verified

    def run_container(self, *, image, **_kwargs):
        self.images.append(image)
        self.last_worker_env = _kwargs.get("env")
        return RunResult(
            exit_code=0,
            timed_out=False,
            stdout=json.dumps({"status": "unsupported"}) + "\n",
            stderr="",
        )

    def parse_json_tail(self, run):
        return json.loads(run.stdout)


class RuntimeImagePinningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = CapabilityRegistry(PLUGIN_ROOT / "capabilities")

    def test_runtime_normalizes_docker_or_podman_image_id(self) -> None:
        runtime = InspectRuntime()
        verified = runtime.ensure_image(
            "example.invalid/image:test", required_labels={"contract": "ok"}
        )
        self.assertEqual(verified.requested_ref, "example.invalid/image:test")
        self.assertEqual(verified.immutable_ref, "sha256:" + "a" * 64)
        self.assertEqual(verified.get("contract"), "ok")
        self.assertEqual(
            ContainerRuntime.immutable_image_ref({"Id": "sha256:" + "d" * 64}),
            "sha256:" + "d" * 64,
        )

    def test_mcp_worker_executes_verified_image_id_not_mutable_tag(self) -> None:
        manifest = self.registry.get("static-core")
        runtime = FakeWorkerRuntime(manifest)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            data = root / "data"
            project.mkdir()
            data.mkdir()
            worker = McpContainerWorker(
                runtime,
                manifest,
                image="example.invalid/static:test",
                project_dir=project,
                data_dir=data,
                version="0.3.0",
            )
            worker.tools()
        self.assertTrue(runtime.images)
        self.assertEqual(set(runtime.images), {"sha256:" + "b" * 64})

    def test_flutter_base_worker_executes_verified_image_id(self) -> None:
        manifest = self.registry.get("framework-flutter")
        runtime = FakeFlutterRuntime(manifest)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            data = root / "data"
            job = root / "job"
            project.mkdir()
            data.mkdir()
            job.mkdir()
            capability = FlutterCapability(
                runtime,
                manifest,
                version="0.3.0",
                project_dir=project,
                data_dir=data,
            )
            capability.base_image = "example.invalid/flutter:test"
            result = capability._prepare(job, "app.apk")
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(runtime.images, ["sha256:" + "c" * 64])

    def test_builder_credentials_are_absent_from_worker_environments(self) -> None:
        secret = "stage-a-builder-secret"
        private_attempt = "8" * 32
        static_manifest = self.registry.get("static-core")
        static_runtime = FakeWorkerRuntime(static_manifest)
        flutter_manifest = self.registry.get("framework-flutter")
        flutter_runtime = FakeFlutterRuntime(flutter_manifest)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ,
            {
                "SAFE_REVERSER_CONTROLLED_BUILD_TOKEN": secret,
                "GITHUB_TOKEN": secret,
                "GH_TOKEN": secret,
                "SAFE_REVERSER_PRIVATE_BUILD_ATTEMPT": private_attempt,
            },
            clear=False,
        ):
            root = Path(tmp)
            project = root / "project"
            data = root / "data"
            job = root / "job"
            project.mkdir()
            data.mkdir()
            job.mkdir()
            worker = McpContainerWorker(
                static_runtime,
                static_manifest,
                image="example.invalid/static:test",
                project_dir=project,
                data_dir=data,
                version="0.3.0",
            )
            worker.tools()
            flutter = FlutterCapability(
                flutter_runtime,
                flutter_manifest,
                version="0.3.0",
                project_dir=project,
                data_dir=data,
            )
            flutter.base_image = "example.invalid/flutter:test"
            flutter._prepare(job, "fixture.apk")

        serialized = json.dumps(static_runtime.last_worker_env)
        self.assertNotIn(secret, serialized)
        self.assertNotIn(private_attempt, serialized)
        self.assertNotIn("TOKEN", serialized)
        self.assertIsNone(flutter_runtime.last_worker_env)


if __name__ == "__main__":
    unittest.main()
