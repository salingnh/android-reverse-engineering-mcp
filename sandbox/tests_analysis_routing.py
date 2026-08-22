#!/usr/bin/env python3
import importlib
import os
import tempfile
import unittest
import zipfile
from pathlib import Path


class AnalysisRoutingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.workspace = Path(cls.tmp.name) / "workspace"
        cls.data = Path(cls.tmp.name) / "data"
        cls.workspace.mkdir()
        cls.data.mkdir()
        os.environ["SAFE_REVERSER_WORKSPACE"] = str(cls.workspace)
        os.environ["SAFE_REVERSER_DATA_ROOT"] = str(cls.data)
        cls.routing = importlib.import_module("analysis_routing")
        cls.server = importlib.import_module("static_semantic_worker")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def make_apk(self, name: str, members: dict[str, bytes]) -> Path:
        apk = self.workspace / name
        with zipfile.ZipFile(apk, "w") as archive:
            for path, content in members.items():
                archive.writestr(path, content)
        return apk

    def test_native_android_routes_to_static_core(self):
        route = self.routing.route_fingerprint(
            {
                "framework": {"type": "Native Android (Kotlin)"},
                "native_libraries": [],
            }
        )
        self.assertEqual(route["framework_id"], "native-android")
        self.assertEqual(route["primary_profile"], "static-core")
        self.assertEqual(route["primary_capability_id"], "static-core")
        self.assertEqual(route["primary_profile_status"], "available")
        self.assertTrue(route["allow_java_decompile_as_primary"])

    def test_flutter_route_declares_capability_without_claiming_runtime_readiness(self):
        route = self.routing.route_fingerprint(
            {
                "framework": {"type": "Flutter"},
                "native_libraries": [
                    "lib/arm64-v8a/libapp.so",
                    "lib/arm64-v8a/libflutter.so",
                ],
            }
        )
        self.assertEqual(route["framework_id"], "flutter")
        self.assertEqual(route["primary_profile"], "framework-flutter")
        self.assertEqual(route["primary_capability_id"], "framework-flutter")
        self.assertEqual(route["primary_profile_status"], "declared")
        self.assertFalse(route["allow_java_decompile_as_primary"])
        self.assertTrue(
            any("Runtime readiness" in item for item in route["limitations"])
        )
        secondary = {
            item["profile"]: item["purpose"] for item in route["secondary_profiles"]
        }
        self.assertIn("static-core", secondary)
        self.assertIn("host shell", secondary["static-core"])

    def test_react_native_without_hermes_stays_runtime_agnostic(self):
        route = self.routing.route_fingerprint(
            {
                "framework": {"type": "React Native"},
                "native_libraries": ["lib/arm64-v8a/libreactnativejni.so"],
            }
        )
        self.assertEqual(route["framework_id"], "react-native")
        self.assertEqual(route["primary_profile"], "framework-react-native")
        self.assertFalse(route["allow_java_decompile_as_primary"])
        self.assertTrue(any("Hermes was not proven" in x for x in route["limitations"]))

    def test_react_native_with_libhermes_routes_to_hermes(self):
        route = self.routing.route_fingerprint(
            {
                "framework": {"type": "React Native"},
                "native_libraries": [
                    "lib/arm64-v8a/libreactnativejni.so",
                    "lib/arm64-v8a/libhermes.so",
                ],
            }
        )
        self.assertEqual(route["framework_id"], "react-native-hermes")
        self.assertEqual(route["primary_profile"], "framework-hermes")

    def test_il2cpp_native_marker_overrides_generic_android_route(self):
        route = self.routing.route_fingerprint(
            {
                "framework": {"type": "Native Android (Java/Kotlin)"},
                "native_libraries": ["lib/arm64-v8a/libil2cpp.so"],
            }
        )
        self.assertEqual(route["framework_id"], "unity-il2cpp")
        self.assertEqual(route["primary_profile"], "framework-il2cpp")
        self.assertFalse(route["allow_java_decompile_as_primary"])

    def test_unknown_framework_does_not_authorize_jadx_as_primary(self):
        route = self.routing.route_fingerprint(
            {
                "framework": {"type": "Unknown custom runtime"},
                "native_libraries": [],
            }
        )
        self.assertEqual(route["framework_id"], "unknown")
        self.assertFalse(route["allow_java_decompile_as_primary"])

    def test_wrapped_fingerprint_returns_declared_flutter_route(self):
        self.make_apk(
            "flutter.apk",
            {
                "classes.dex": b"Lio/flutter/embedding/android/FlutterActivity;",
                "lib/arm64-v8a/libflutter.so": b"flutter",
                "lib/arm64-v8a/libapp.so": b"dart-aot",
                "assets/flutter_assets/AssetManifest.json": b"{}",
            },
        )
        result = self.server.fingerprint({"artifact": "flutter.apk"})
        self.assertEqual(result["framework"]["type"], "Flutter")
        route = result["analysis_route"]
        self.assertEqual(route["primary_profile"], "framework-flutter")
        self.assertEqual(route["primary_capability_id"], "framework-flutter")
        self.assertEqual(route["primary_profile_status"], "declared")
        self.assertFalse(route["allow_java_decompile_as_primary"])

    def test_route_analysis_tool_is_registered(self):
        names = {tool["name"] for tool in self.server.core.TOOLS}
        self.assertIn("route_analysis", names)
        self.assertIs(
            self.server.core.TOOL_HANDLERS["route_analysis"], self.server.route_analysis
        )

    def test_health_exposes_topology_not_host_runtime_state(self):
        result = self.server.health({})
        self.assertTrue(result["analysis_routing"]["enabled"])
        self.assertEqual(result["analysis_routing"]["schema_version"], 2)
        self.assertEqual(
            result["analysis_routing"]["profiles"]["static-core"]["status"],
            "available",
        )
        flutter = result["analysis_routing"]["profiles"]["framework-flutter"]
        self.assertEqual(flutter["status"], "declared")
        self.assertEqual(flutter["capability_id"], "framework-flutter")
        self.assertIn("dart-aot-index", flutter["available_capabilities"])
        self.assertNotIn("capability_server", flutter)
        self.assertEqual(
            result["analysis_routing"]["profiles"]["framework-react-native"][
                "status"
            ],
            "planned",
        )


if __name__ == "__main__":
    unittest.main()
