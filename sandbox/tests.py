#!/usr/bin/env python3
import importlib.util
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

MODULE = Path(__file__).with_name("mcp_server.py")


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.workspace = Path(cls.tmp.name) / "workspace"
        cls.data = Path(cls.tmp.name) / "data"
        cls.workspace.mkdir()
        cls.data.mkdir()
        os.environ["SAFE_REVERSER_WORKSPACE"] = str(cls.workspace)
        os.environ["SAFE_REVERSER_DATA_ROOT"] = str(cls.data)
        spec = importlib.util.spec_from_file_location("safe_server_test", MODULE)
        cls.server = importlib.util.module_from_spec(spec)
        assert spec.loader
        spec.loader.exec_module(cls.server)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def make_apk(self):
        apk = self.workspace / "sample.apk"
        descriptors = [
            b"Lcom/example/BuildConfig;",
            b"Lretrofit2/Retrofit;",
            b"Lokhttp3/OkHttpClient;",
            b"Landroidx/compose/ui/Modifier;",
        ]
        for a in "abcdef":
            for b in "abcdef":
                descriptors.append(f"L{a}/{b}/C{a}{b};".encode())
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("classes.dex", b"\0".join(descriptors))
            zf.writestr("lib/arm64-v8a/libnative.so", b"x")
        return apk

    def test_fingerprint_uses_dex_names_and_detects_buildconfig(self):
        self.make_apk()
        result = self.server.fingerprint({"artifact": "sample.apk"})
        self.assertEqual(result["obfuscation"]["level"], "high")
        self.assertTrue(result["build_config_detected"])
        self.assertIn("Retrofit", result["http_stacks"])
        self.assertIn("OkHttp", result["http_stacks"])

    def test_third_party_apex_and_subdomain(self):
        self.assertTrue(self.server._is_third_party("stripe.com"))
        self.assertTrue(self.server._is_third_party("api.stripe.com"))
        self.assertFalse(self.server._is_third_party("api.example.org"))

    def test_path_escape_is_rejected(self):
        with self.assertRaises(self.server.ToolError):
            self.server._safe_relative(self.workspace, "../escape.apk", must_exist=False)
        with self.assertRaises(self.server.ToolError):
            self.server._safe_relative(self.workspace, "/etc/passwd")


if __name__ == "__main__":
    unittest.main()
