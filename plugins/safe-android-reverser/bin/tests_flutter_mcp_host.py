#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


class FlutterMcpHostTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.root = root
        self.project = root / "project"
        self.data = root / "data"
        self.project.mkdir()
        self.data.mkdir()
        self.artifact = self.project / "app.apk"
        self.artifact.write_bytes(b"untrusted-apk-placeholder")
        env = {
            "SAFE_REVERSER_PLUGIN_VERSION": "0.3.0",
            "SAFE_REVERSER_RUNTIME": "docker",
            "SAFE_REVERSER_PROJECT_DIR": str(self.project),
            "SAFE_REVERSER_DATA_DIR": str(self.data),
            "SAFE_REVERSER_HOST_UID": str(os.getuid()),
            "SAFE_REVERSER_HOST_GID": str(os.getgid()),
            "SAFE_REVERSER_FLUTTER_REPOSITORY": "ghcr.io/salingnh/safe-android-reverser-flutter",
            "SAFE_REVERSER_FLUTTER_IMAGE": "ghcr.io/salingnh/safe-android-reverser-flutter:0.3.0",
            "SAFE_REVERSER_AUTO_PULL": "0",
        }
        self.env_patch = mock.patch.dict(os.environ, env, clear=False)
        self.env_patch.start()
        path = Path(__file__).with_name("flutter-mcp-host.py")
        spec = importlib.util.spec_from_file_location(
            f"flutter_mcp_host_tested_{id(self)}", path
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.host = module
        self.host._validate_config()

    def tearDown(self):
        self.env_patch.stop()
        self.tmp.cleanup()

    def prepared(self):
        tag = "dart-3.5.4-arm64-cp-" + "a" * 64
        image = self.host.FLUTTER_REPOSITORY + ":" + tag
        runtime = {
            "identity_status": "identified",
            "dart_version": "3.5.4",
            "os": "android",
            "arch": "arm64",
            "snapshot_hash": "b" * 32,
            "compressed_pointers": True,
            "cache_tag": tag,
            "recommended_image": image,
        }
        return {
            "status": "runtime_cache_miss",
            "profile": "framework-flutter",
            "runtime": runtime,
            "recommended_image": image,
            "blutter_commit": "c" * 40,
        }

    def test_container_boundary_never_mounts_runtime_socket_or_network(self):
        args = self.host._common_container_args()
        joined = " ".join(args)
        self.assertIn("--network=none", args)
        self.assertIn("--read-only", args)
        self.assertIn("--cap-drop=ALL", args)
        self.assertIn("--security-opt=no-new-privileges", args)
        self.assertNotIn("docker.sock", joined)
        self.assertNotIn("podman.sock", joined)

    def test_resource_limits_are_typed_not_generic_suffixes(self):
        with mock.patch.object(self.host, "CPUS", "2g"), self.assertRaises(
            self.host.ControllerError
        ):
            self.host._validate_config()
        with mock.patch.object(self.host, "MEMORY", "0"), self.assertRaises(
            self.host.ControllerError
        ):
            self.host._validate_config()
        with mock.patch.object(
            self.host, "OUTPUT_TMPFS_SIZE", "-1g"
        ), self.assertRaises(self.host.ControllerError):
            self.host._validate_config()

    def test_flutter_data_symlink_cannot_escape_plugin_data_root(self):
        outside = self.root / "outside"
        outside.mkdir()
        link = self.data / "flutter"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(self.host.ControllerError):
            self.host._flutter_data_root()

    def test_runtime_image_reference_is_derived_not_caller_controlled(self):
        prepared = self.prepared()
        image, runtime = self.host._runtime_image_reference(prepared)
        self.assertEqual(image, prepared["recommended_image"])
        self.assertEqual(runtime["arch"], "arm64")
        malicious = self.prepared()
        malicious["recommended_image"] = "evil.example/image:latest"
        with self.assertRaises(self.host.ControllerError):
            self.host._runtime_image_reference(malicious)

    def test_runtime_image_requires_cache_schema_and_exact_dart_provenance(self):
        prepared = self.prepared()
        image, runtime = self.host._runtime_image_reference(prepared)
        labels = {
            "io.safe-reverser.runtime-cache.schema": "2",
            "io.safe-reverser.blutter.commit": "c" * 40,
            "io.safe-reverser.dart.version": "3.5.4",
            "io.safe-reverser.dart.snapshot": "b" * 32,
            "io.safe-reverser.dart.arch": "arm64",
            "io.safe-reverser.dart.compressed-pointers": "true",
        }
        info = {"Config": {"Labels": labels}}
        with mock.patch.object(self.host, "_inspect_image", return_value=info):
            ready, _ = self.host._ensure_runtime_image(image, runtime, "c" * 40)
        self.assertTrue(ready)
        bad = {
            "Config": {
                "Labels": {
                    **labels,
                    "io.safe-reverser.runtime-cache.schema": "1",
                }
            }
        }
        with mock.patch.object(
            self.host, "_inspect_image", return_value=bad
        ), self.assertRaises(self.host.ControllerError):
            self.host._ensure_runtime_image(image, runtime, "c" * 40)

    def test_analyze_orchestrates_prepare_verify_execute_and_cleanup(self):
        prepared = self.prepared()
        image = prepared["recommended_image"]
        analysis = {
            "status": "ok",
            "analysis_id": "flutter-aot:" + "d" * 64,
            "semantic_index": {"status": "ok"},
        }

        def fake_prepare(job, _artifact):
            (job / "input").mkdir()
            (job / "input" / "libapp.so").write_bytes(b"app")
            return prepared

        with mock.patch.object(
            self.host, "_ensure_base_image", return_value={}
        ), mock.patch.object(
            self.host, "_prepare", side_effect=fake_prepare
        ) as prepare_call, mock.patch.object(
            self.host, "_ensure_runtime_image", return_value=(True, "ready")
        ), mock.patch.object(
            self.host, "_execute_analysis", return_value=analysis
        ) as execute_call:
            result = self.host.analyze_flutter_aot(
                {"artifact": "app.apk", "timeout_seconds": 120}
            )
        self.assertEqual(result["status"], "ok")
        self.assertRegex(result["job_id"], r"^[0-9a-f]{12}$")
        prepare_call.assert_called_once()
        execute_call.assert_called_once()
        self.assertEqual(execute_call.call_args.args[1], image)
        job = self.host._job(result["job_id"])
        self.assertFalse((job / "input").exists())
        meta = self.host._read_job(job)
        self.assertEqual(meta["status"], "ok")
        self.assertEqual(meta["runtime_image"], image)

    def test_missing_runtime_cache_is_explicit_never_executes_and_cleans_input(self):
        prepared = self.prepared()

        def fake_prepare(job, _artifact):
            (job / "input").mkdir()
            (job / "input" / "libapp.so").write_bytes(b"app")
            return prepared

        with mock.patch.object(
            self.host, "_ensure_base_image", return_value={}
        ), mock.patch.object(
            self.host, "_prepare", side_effect=fake_prepare
        ), mock.patch.object(
            self.host,
            "_ensure_runtime_image",
            return_value=(False, "manifest unknown"),
        ), mock.patch.object(self.host, "_execute_analysis") as execute_call:
            result = self.host.analyze_flutter_aot({"artifact": "app.apk"})
        self.assertEqual(result["status"], "runtime_cache_unavailable")
        self.assertFalse(result["executed"])
        execute_call.assert_not_called()
        job = self.host._job(result["job_id"])
        self.assertFalse((job / "input").exists())

    def test_query_and_symbol_bounds_match_semantic_surface(self):
        with self.assertRaises(self.host.ControllerError):
            self.host._query_text("q" * 513, "query", self.host.MAX_QUERY_TEXT)
        self.assertEqual(
            self.host._query_text(
                "s" * 1024, "symbol", self.host.MAX_SYMBOL_TEXT
            ),
            "s" * 1024,
        )
        with self.assertRaises(self.host.ControllerError):
            self.host._query_text(
                "s" * 1025, "symbol", self.host.MAX_SYMBOL_TEXT
            )

    def test_project_symlinks_and_path_escape_are_rejected(self):
        with self.assertRaises(self.host.ControllerError):
            self.host._artifact("../outside.apk")
        link = self.project / "linked.apk"
        try:
            link.symlink_to(self.artifact.name)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(self.host.ControllerError):
            self.host._artifact("linked.apk")

    def test_flutter_tool_surface_is_allow_listed(self):
        names = {tool["name"] for tool in self.host.TOOLS}
        self.assertEqual(
            names,
            {
                "health",
                "analyze_flutter_aot",
                "find_dart_symbols",
                "find_dart_strings",
                "find_dart_xrefs",
                "map_dart_to_native",
                "extract_flutter_network_model",
                "list_flutter_jobs",
            },
        )
        self.assertNotIn("shell", names)
        self.assertNotIn("exec", names)


if __name__ == "__main__":
    unittest.main()
