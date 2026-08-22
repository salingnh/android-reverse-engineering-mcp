#!/usr/bin/env python3
import io
import importlib
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


class FlutterAnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.workspace = Path(cls.tmp.name) / "workspace"
        cls.data = Path(cls.tmp.name) / "data"
        cls.workspace.mkdir()
        cls.data.mkdir()
        os.environ["SAFE_REVERSER_WORKSPACE"] = str(cls.workspace)
        os.environ["SAFE_REVERSER_DATA_ROOT"] = str(cls.data)
        os.environ["SAFE_REVERSER_IMAGE_VERSION"] = "0.2.1"
        os.environ["SAFE_REVERSER_BUILD_COMMIT"] = "test-build"
        cls.flutter = importlib.import_module("flutter_analysis")
        cls.server = importlib.import_module("static_semantic_worker")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def make_flutter_apk(
        self,
        name="flutter.apk",
        *,
        runtime_marker=True,
        assets=3,
        large_preview=False,
    ):
        apk = self.workspace / name
        marker = b""
        if runtime_marker:
            marker = (
                b"prefix Dart VM version: 3.5.4 suffix "
                b"SnapshotHash: aabbccddeeff00112233445566778899 end"
            )
        with zipfile.ZipFile(
            apk, "w", compression=zipfile.ZIP_DEFLATED
        ) as archive:
            archive.writestr(
                "classes.dex", b"Lio/flutter/embedding/android/FlutterActivity;"
            )
            archive.writestr("lib/arm64-v8a/libapp.so", b"dart-aot-code")
            archive.writestr("lib/arm64-v8a/libflutter.so", b"engine" + marker)
            archive.writestr(
                "assets/flutter_assets/AssetManifest.json",
                b'{"assets/config.json":[]}',
            )
            archive.writestr("assets/flutter_assets/FontManifest.json", b"[]")
            config = b'{"baseUrl":"https://api.example.test"}'
            if large_preview:
                config += b"x" * (self.flutter.MAX_ASSET_PREVIEW_BYTES * 2)
            archive.writestr("assets/flutter_assets/config.json", config)
            for index in range(max(0, assets - 3)):
                archive.writestr(f"assets/flutter_assets/images/{index}.bin", b"x")
        return apk

    def make_xapk(self):
        base = io.BytesIO()
        with zipfile.ZipFile(
            base, "w", compression=zipfile.ZIP_DEFLATED
        ) as archive:
            archive.writestr(
                "classes.dex", b"Lio/flutter/embedding/android/FlutterActivity;"
            )
            archive.writestr("lib/arm64-v8a/libapp.so", b"dart-aot-code")
            archive.writestr(
                "lib/arm64-v8a/libflutter.so",
                b"Dart VM version: 3.6.0 SnapshotHash: 00112233445566778899aabbccddeeff",
            )
        assets = io.BytesIO()
        with zipfile.ZipFile(
            assets, "w", compression=zipfile.ZIP_DEFLATED
        ) as archive:
            archive.writestr("assets/flutter_assets/AssetManifest.json", b"{}")
            archive.writestr(
                "assets/flutter_assets/env/config.json", b'{"env":"test"}'
            )
        xapk = self.workspace / "flutter.xapk"
        with zipfile.ZipFile(
            xapk, "w", compression=zipfile.ZIP_DEFLATED
        ) as outer:
            outer.writestr("base.apk", base.getvalue())
            outer.writestr("config.assets.apk", assets.getvalue())
        return xapk

    def test_inspect_flutter_recovers_structure_runtime_and_evidence(self):
        self.make_flutter_apk()
        result = self.server.inspect_flutter({"artifact": "flutter.apk"})
        self.assertEqual(result["artifact"], "flutter.apk")
        self.assertEqual(result["framework"], "flutter")
        self.assertEqual(result["abis"], ["arm64-v8a"])
        self.assertEqual(len(result["libraries"]["libapp"]), 1)
        self.assertEqual(len(result["libraries"]["libflutter"]), 1)
        self.assertEqual(result["dart_runtime"]["status"], "identified")
        self.assertIn("3.5.4", result["dart_runtime"]["versions"])
        self.assertEqual(result["dart_runtime"]["snapshot_hashes"], [])
        self.assertEqual(result["capability"]["status"], "partial")
        self.assertTrue(
            any("Snapshot hash extraction" in item for item in result["limitations"])
        )
        evidence = result["libraries"]["libapp"][0]["evidence"]
        self.assertEqual(evidence["state"], "observed")
        self.assertEqual(len(evidence["artifact_sha256"]), 64)
        self.assertEqual(evidence["image_version"], "0.2.1")
        self.assertEqual(evidence["build_commit"], "test-build")
        self.assertIn(result["artifact_sha256"], result["analysis_id"])

    def test_unknown_runtime_is_explicit_not_guessed(self):
        self.make_flutter_apk(name="unknown.apk", runtime_marker=False)
        result = self.server.identify_dart_runtime({"artifact": "unknown.apk"})
        self.assertEqual(result["dart_runtime"]["status"], "unknown")
        self.assertEqual(result["dart_runtime"]["versions"], [])
        self.assertTrue(
            any("No bounded Dart VM" in item for item in result["limitations"])
        )

    def test_assets_are_bounded_and_text_previews_have_provenance(self):
        self.make_flutter_apk(name="assets.apk", assets=8, large_preview=True)
        result = self.server.extract_flutter_assets(
            {"artifact": "assets.apk", "max_items": 2, "max_previews": 3}
        )
        self.assertEqual(result["count"], 8)
        self.assertEqual(len(result["items"]), 2)
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["previews"]), 3)
        self.assertTrue(result["previews"])
        self.assertEqual(result["previews"][0]["evidence"]["state"], "observed")
        preview = next(
            item for item in result["previews"] if item["path"].endswith("config.json")
        )
        self.assertLessEqual(
            len(preview["text"].encode("utf-8")),
            self.flutter.MAX_ASSET_PREVIEW_BYTES,
        )
        self.assertTrue(preview["truncated"])

    def test_xapk_scans_flutter_members_across_splits(self):
        self.make_xapk()
        result = self.server.inspect_flutter({"artifact": "flutter.xapk"})
        self.assertIn("base.apk", result["apk_members"])
        self.assertIn("config.assets.apk", result["apk_members"])
        self.assertEqual(result["assets"]["count"], 2)
        self.assertEqual(result["dart_runtime"]["status"], "identified")

    def test_bundle_budget_is_enforced_before_nested_apk_extraction(self):
        self.make_xapk()
        with mock.patch.object(
            self.flutter, "MAX_BUNDLE_TOTAL_APK_BYTES", 1
        ), self.assertRaises(self.server.core.ToolError) as ctx:
            self.server.inspect_flutter({"artifact": "flutter.xapk"})
        self.assertIn("total safe extraction budget", str(ctx.exception))

    def test_flutter_tools_do_not_repeat_full_fingerprint(self):
        self.make_flutter_apk(name="no-refingerprint.apk")
        with mock.patch.object(
            self.server,
            "_baseline_fingerprint",
            side_effect=AssertionError("full fingerprint must not run"),
        ):
            result = self.server.inspect_flutter({"artifact": "no-refingerprint.apk"})
        self.assertEqual(result["framework"], "flutter")

    def test_flutter_tools_reject_non_flutter_artifact(self):
        apk = self.workspace / "native.apk"
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("classes.dex", b"Lcom/example/MainActivity;")
        with self.assertRaises(self.server.core.ToolError):
            self.server.inspect_flutter({"artifact": "native.apk"})

    def test_flutter_tools_are_registered_and_health_is_partial(self):
        names = {tool["name"] for tool in self.server.core.TOOLS}
        self.assertTrue(
            {
                "inspect_flutter",
                "identify_dart_runtime",
                "extract_flutter_assets",
            }.issubset(names)
        )
        health = self.server.health({})
        self.assertEqual(
            health["analysis_routing"]["profiles"]["framework-flutter"]["status"],
            "partial",
        )
        self.assertTrue(
            health["framework_analysis"]["flutter"]["artifact_inspection"]
        )
        self.assertFalse(
            health["framework_analysis"]["flutter"]["dart_aot_index"]
        )


if __name__ == "__main__":
    unittest.main()
