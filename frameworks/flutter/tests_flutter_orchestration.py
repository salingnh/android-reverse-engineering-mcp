#!/usr/bin/env python3
from __future__ import annotations

import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import flutter_artifact as artifact
import flutter_export as exporter
import flutter_entrypoint as entry


class FlutterArtifactPreparationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.workspace = root / "workspace"
        self.output = root / "output"
        self.export = root / "export"
        self.workspace.mkdir()
        self.output.mkdir()
        self.export.mkdir()
        self.old_workspace = artifact.WORKSPACE
        self.old_output = artifact.adapter.OUTPUT_ROOT
        self.old_export = exporter.EXPORT_ROOT
        artifact.WORKSPACE = self.workspace.resolve()
        artifact.adapter.OUTPUT_ROOT = self.output.resolve()
        exporter.EXPORT_ROOT = self.export.resolve()

    def tearDown(self):
        artifact.WORKSPACE = self.old_workspace
        artifact.adapter.OUTPUT_ROOT = self.old_output
        exporter.EXPORT_ROOT = self.old_export
        self.tmp.cleanup()

    def runtime(self):
        tag = "dart-3.5.4-arm64-cp-" + "a" * 64
        image = "ghcr.io/salingnh/safe-android-reverser-flutter:" + tag
        return {
            "identity_status": "identified",
            "dart_version": "3.5.4",
            "os": "android",
            "arch": "arm64",
            "snapshot_hash": "b" * 32,
            "compressed_pointers": True,
            "cache_tag": tag,
            "recommended_image": image,
            "binary_cached": False,
        }

    def make_apk(self, name: str, members: dict[str, bytes]) -> Path:
        path = self.workspace / name
        with zipfile.ZipFile(path, "w") as zf:
            for member, content in members.items():
                zf.writestr(member, content)
        return path

    def apk_bytes(self, members: dict[str, bytes]) -> bytes:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as zf:
            for member, content in members.items():
                zf.writestr(member, content)
        return stream.getvalue()

    def test_prepare_extracts_only_supported_runtime_pair(self):
        self.make_apk(
            "app.apk",
            {
                "lib/arm64-v8a/libapp.so": b"app-aot",
                "lib/arm64-v8a/libflutter.so": b"flutter-engine",
                "lib/x86_64/libapp.so": b"ignored",
                "assets/flutter_assets/AssetManifest.json": b"{}",
            },
        )
        with mock.patch.object(
            artifact.adapter, "_runtime_info", return_value=self.runtime()
        ):
            result = artifact.prepare_artifact("app.apk", "input")
        self.assertEqual(result["status"], "runtime_cache_miss")
        self.assertEqual(result["abi"], "arm64-v8a")
        self.assertEqual((self.output / "input" / "libapp.so").read_bytes(), b"app-aot")
        self.assertEqual(
            (self.output / "input" / "libflutter.so").read_bytes(),
            b"flutter-engine",
        )
        self.assertEqual(result["recommended_image"], self.runtime()["recommended_image"])

    def test_bundle_duplicate_runtime_library_must_be_identical(self):
        first = self.apk_bytes(
            {
                "lib/arm64-v8a/libapp.so": b"app-one",
                "lib/arm64-v8a/libflutter.so": b"flutter",
            }
        )
        second = self.apk_bytes(
            {
                "lib/arm64-v8a/libapp.so": b"app-two",
                "lib/arm64-v8a/libflutter.so": b"flutter",
            }
        )
        bundle = self.workspace / "app.xapk"
        with zipfile.ZipFile(bundle, "w") as zf:
            zf.writestr("splits/a.apk", first)
            zf.writestr("splits/b.apk", second)
        with self.assertRaises(artifact.FlutterArtifactError):
            artifact.prepare_artifact("app.xapk", "input")
        self.assertFalse((self.output / "input").exists())

    def test_unsupported_abi_is_structured_and_leaves_no_partial_input(self):
        self.make_apk(
            "x86.apk",
            {
                "lib/x86_64/libapp.so": b"app",
                "lib/x86_64/libflutter.so": b"flutter",
            },
        )
        result = artifact.prepare_artifact("x86.apk", "input")
        self.assertEqual(result["status"], "unsupported")
        self.assertIn("x86_64", result["available_abis"])
        self.assertFalse((self.output / "input").exists())

    def test_artifact_symlink_and_output_escape_are_rejected(self):
        real = self.make_apk(
            "real.apk",
            {
                "lib/arm64-v8a/libapp.so": b"app",
                "lib/arm64-v8a/libflutter.so": b"flutter",
            },
        )
        link = self.workspace / "link.apk"
        try:
            link.symlink_to(real.name)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(artifact.FlutterArtifactError):
            artifact.prepare_artifact("link.apk", "input")
        with self.assertRaises(artifact.FlutterArtifactError):
            artifact.prepare_artifact("real.apk", "../escape")
        with self.assertRaises(artifact.FlutterArtifactError):
            artifact.prepare_artifact("real.apk", "nested/input")


class FlutterExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.output = root / "output"
        self.export = root / "export"
        self.output.mkdir()
        self.export.mkdir()
        self.old_output = exporter.adapter.OUTPUT_ROOT
        self.old_export = exporter.EXPORT_ROOT
        exporter.adapter.OUTPUT_ROOT = self.output.resolve()
        exporter.EXPORT_ROOT = self.export.resolve()
        self.source = self.output / "analysis"
        (self.source / "asm" / "app").mkdir(parents=True)
        (self.source / "flutter-index.sqlite").write_bytes(b"sqlite")
        (self.source / "asm" / "app" / "api.dart").write_text(
            "void ping() {}\n", encoding="utf-8"
        )

    def tearDown(self):
        exporter.adapter.OUTPUT_ROOT = self.old_output
        exporter.EXPORT_ROOT = self.old_export
        self.tmp.cleanup()

    def test_export_is_bounded_and_atomic(self):
        result = exporter.export_analysis(self.source, "analysis")
        self.assertEqual(result["status"], "ok")
        self.assertGreaterEqual(result["files"], 2)
        self.assertEqual(
            (self.export / "analysis" / "asm" / "app" / "api.dart").read_text(
                encoding="utf-8"
            ),
            "void ping() {}\n",
        )
        self.assertFalse(any(p.name.startswith(".safe-flutter-export-") for p in self.export.iterdir()))

    def test_export_rejects_symlinked_analyzer_output(self):
        outside = self.output / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        link = self.source / "asm" / "linked.txt"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(exporter.FlutterExportError):
            exporter.export_analysis(self.source, "analysis")
        self.assertFalse((self.export / "analysis").exists())

    def test_export_total_bytes_budget_is_hard(self):
        old = exporter.MAX_EXPORT_BYTES
        exporter.MAX_EXPORT_BYTES = 3
        try:
            with self.assertRaises(exporter.FlutterExportError):
                exporter.export_analysis(self.source, "analysis")
        finally:
            exporter.MAX_EXPORT_BYTES = old
        self.assertFalse((self.export / "analysis").exists())


class FlutterEntrypointOrchestrationTests(unittest.TestCase):
    def test_analyze_export_only_exports_success_or_partial_output(self):
        args = mock.Mock(output="analysis")
        fake_source = Path("/tmp/fake-analysis")
        with mock.patch.object(entry, "_analyze_command", return_value={"status": "ok"}), mock.patch.object(
            entry, "_output_dir", return_value=fake_source
        ), mock.patch.object(
            entry.exporter,
            "export_analysis",
            return_value={"status": "ok", "destination": "analysis"},
        ) as export_call:
            result = entry._analyze_export_command(args)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["exported_output"], "analysis")
        export_call.assert_called_once_with(fake_source, "analysis")

    def test_analyze_export_does_not_export_cache_miss(self):
        args = mock.Mock(output="analysis")
        with mock.patch.object(
            entry,
            "_analyze_command",
            return_value={"status": "runtime_cache_miss", "executed": False},
        ), mock.patch.object(entry.exporter, "export_analysis") as export_call:
            result = entry._analyze_export_command(args)
        self.assertEqual(result["status"], "runtime_cache_miss")
        export_call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
