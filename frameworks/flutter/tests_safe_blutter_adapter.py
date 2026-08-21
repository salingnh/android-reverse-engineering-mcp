#!/usr/bin/env python3
import importlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


class SafeBlutterAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.input_root = root / "input"
        cls.output_root = root / "output"
        cls.blutter_root = root / "blutter"
        (cls.input_root / "libs").mkdir(parents=True)
        cls.output_root.mkdir()
        (cls.blutter_root / "bin").mkdir(parents=True)
        (cls.input_root / "libs" / "libapp.so").write_bytes(b"app")
        (cls.input_root / "libs" / "libflutter.so").write_bytes(b"flutter")
        os.environ["SAFE_FLUTTER_INPUT"] = str(cls.input_root)
        os.environ["SAFE_FLUTTER_OUTPUT"] = str(cls.output_root)
        os.environ["SAFE_BLUTTER_ROOT"] = str(cls.blutter_root)
        os.environ["SAFE_BLUTTER_COMMIT"] = "test-commit"
        cls.adapter = importlib.import_module("safe_blutter_adapter")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def helpers(self, version="3.5.4"):
        adapter = self.adapter

        class FakeInfo:
            def __init__(self, version, os_name, arch, compressed, snapshot_hash):
                self.version = version
                self.os_name = os_name
                self.arch = arch
                self.has_compressed_ptrs = compressed
                self.snapshot_hash = snapshot_hash
                self.lib_name = f"dartvm{version}_{os_name}_{arch}"

        class FakeInput:
            def __init__(self, libapp, info, outdir, rebuild, vs, no_analysis):
                self.blutter_file = str(
                    adapter.BLUTTER_ROOT / "bin" / f"blutter_{info.lib_name}"
                )

        def snapshot(_path):
            return "a" * 32, ["compressed-pointers", "product"]

        def engine(_path):
            return ["b" * 40, "c" * 40], version, "arm64", "android"

        return FakeInput, FakeInfo, snapshot, engine

    def test_health_declares_no_runtime_build_or_network(self):
        result = self.adapter.health()
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["network_required_at_runtime"])
        self.assertFalse(result["network_capable_upstream_path_used"])
        self.assertFalse(result["build_on_demand_allowed"])

    def test_inspect_returns_cache_miss_without_executing_builder(self):
        with mock.patch.object(
            self.adapter, "_import_runtime_helpers", return_value=self.helpers()
        ):
            result = self.adapter.inspect("libs")
        self.assertEqual(result["status"], "runtime_cache_miss")
        self.assertEqual(result["runtime"]["dart_version"], "3.5.4")
        self.assertFalse(result["runtime"]["binary_cached"])

    def test_cached_binary_makes_runtime_ready(self):
        binary = self.blutter_root / "bin" / "blutter_dartvm3.5.4_android_arm64"
        binary.write_bytes(b"binary")
        try:
            with mock.patch.object(
                self.adapter, "_import_runtime_helpers", return_value=self.helpers()
            ):
                result = self.adapter.inspect("libs")
            self.assertEqual(result["status"], "ready")
            self.assertTrue(result["runtime"]["binary_cached"])
        finally:
            binary.unlink()

    def test_incomplete_runtime_identity_never_uses_network_fallback(self):
        helpers = list(self.helpers(version=None))
        with mock.patch.object(
            self.adapter, "_import_runtime_helpers", return_value=tuple(helpers)
        ):
            result = self.adapter.inspect("libs")
        self.assertEqual(result["status"], "runtime_identity_incomplete")
        self.assertIsNone(result["runtime"]["dart_version"])

    def test_analyze_cache_miss_does_not_spawn_process(self):
        with mock.patch.object(
            self.adapter, "_import_runtime_helpers", return_value=self.helpers()
        ), mock.patch.object(
            self.adapter.subprocess,
            "run",
            side_effect=AssertionError("subprocess must not execute on cache miss"),
        ):
            result = self.adapter.analyze("libs", "job-1", 10)
        self.assertEqual(result["status"], "runtime_cache_miss")
        self.assertFalse(result["executed"])

    def test_paths_cannot_escape_capability_roots(self):
        with self.assertRaises(self.adapter.AdapterError):
            self.adapter._safe_under(self.adapter.INPUT_ROOT, "../escape")
        with self.assertRaises(self.adapter.AdapterError):
            self.adapter._safe_under(self.adapter.OUTPUT_ROOT, "../../escape", must_exist=False)


if __name__ == "__main__":
    unittest.main()
