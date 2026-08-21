#!/usr/bin/env python3
import importlib
import os
import tempfile
import types
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
        os.environ["SAFE_BLUTTER_COMMIT"] = "d" * 40
        cls.adapter = importlib.import_module("safe_blutter_adapter")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def helpers(self, version="3.5.4", arch="arm64", os_name="android"):
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
            return ["b" * 40, "c" * 40], version, arch, os_name

        return FakeInput, FakeInfo, snapshot, engine

    def test_health_declares_no_runtime_build_or_network(self):
        result = self.adapter.health()
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["network_required_at_runtime"])
        self.assertFalse(result["network_capable_upstream_path_used"])
        self.assertFalse(result["build_on_demand_allowed"])
        constraints = result["required_runtime_constraints"]
        self.assertEqual(constraints["network"], "none")
        self.assertEqual(constraints["output_mount"], "writable-bounded")
        self.assertGreater(constraints["max_generated_file_bytes"], 0)

    def test_inspect_returns_exact_cache_miss_without_executing_builder(self):
        with mock.patch.object(
            self.adapter, "_import_runtime_helpers", return_value=self.helpers()
        ):
            result = self.adapter.inspect("libs")
        self.assertEqual(result["status"], "runtime_cache_miss")
        self.assertEqual(result["runtime"]["dart_version"], "3.5.4")
        self.assertEqual(result["runtime"]["snapshot_hash"], "a" * 32)
        self.assertFalse(result["runtime"]["binary_cached"])
        self.assertRegex(
            result["runtime"]["cache_tag"],
            r"^dart-3\.5\.4-arm64-cp-[0-9a-f]{64}$",
        )
        self.assertTrue(
            result["runtime"]["recommended_image"].endswith(
                ":" + result["runtime"]["cache_tag"]
            )
        )

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
        self.assertIsNone(result["runtime"]["cache_tag"])

    def test_invalid_local_runtime_identity_is_rejected(self):
        with mock.patch.object(
            self.adapter,
            "_import_runtime_helpers",
            return_value=self.helpers(version="3.5.4/../../escape"),
        ), self.assertRaises(self.adapter.AdapterError):
            self.adapter.inspect("libs")
        with mock.patch.object(
            self.adapter,
            "_import_runtime_helpers",
            return_value=self.helpers(arch="x64"),
        ), self.assertRaises(self.adapter.AdapterError):
            self.adapter.inspect("libs")

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

    def test_analyze_keeps_only_bounded_process_log_tail(self):
        binary = self.blutter_root / "bin" / "blutter_dartvm3.5.4_android_arm64"
        binary.write_bytes(b"binary")

        def fake_run(*_args, **kwargs):
            kwargs["stdout"].write(b"z" * (self.adapter.MAX_PROCESS_OUTPUT + 1000))
            return types.SimpleNamespace(returncode=0)

        try:
            with mock.patch.object(
                self.adapter, "_import_runtime_helpers", return_value=self.helpers()
            ), mock.patch.object(self.adapter.subprocess, "run", side_effect=fake_run):
                result = self.adapter.analyze("libs", "job-2", 10)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(
                len(result["output"].encode("utf-8")), self.adapter.MAX_PROCESS_OUTPUT
            )
            self.assertTrue(result["limits"]["required_bounded_output_volume"])
        finally:
            binary.unlink()

    def test_paths_cannot_escape_capability_roots(self):
        with self.assertRaises(self.adapter.AdapterError):
            self.adapter._safe_under(self.adapter.INPUT_ROOT, "../escape")
        with self.assertRaises(self.adapter.AdapterError):
            self.adapter._safe_under(
                self.adapter.OUTPUT_ROOT, "../../escape", must_exist=False
            )


if __name__ == "__main__":
    unittest.main()
