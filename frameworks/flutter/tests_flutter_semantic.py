#!/usr/bin/env python3
import importlib
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import flutter_semantic as semantic


class FlutterSemanticIndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "job"
        (self.root / "asm" / "app").mkdir(parents=True)
        (self.root / "asm" / "app" / "api.dart").write_text(
            """// lib: , url: package:app/api.dart

// class id: 101, size: 0x20, field offset: 0x10
class ApiClient extends Object {
  Future login(String user) {
    // ** addr: 0x1234, size: 0x50
    0x1234: bl 0x2000 ; [package:app/auth.dart] Auth::verify -> bool
    0x1238: bl 0x2100 ; [package:app/auth.dart] Auth::sign -> String
    // \"https://api.example.com/login\"
  }
}
""",
            encoding="utf-8",
        )
        (self.root / "asm" / "app" / "auth.dart").write_text(
            """// lib: , url: package:app/auth.dart

// class id: 102, size: 0x20
class Auth extends Object {
  bool verify(String body) {
    // ** addr: 0x2000, size: 0x30
  }
  String sign(String body) {
    // ** addr: 0x2100, size: 0x30
  }
  String sign(String body, String key) {
    // ** addr: 0x2200, size: 0x20
  }
}
""",
            encoding="utf-8",
        )
        (self.root / "pp.txt").write_text(
            '0x10: "Authorization"\n0x18: "Bearer "\n0x20: "literal%marker"\n',
            encoding="utf-8",
        )
        (self.root / "objs.txt").write_text(
            'Object: "refresh_token"\n', encoding="utf-8"
        )
        self.index = self.root / "flutter-index.sqlite"

    def tearDown(self):
        self.tmp.cleanup()

    def build(self):
        return semantic.build_flutter_index(
            self.root,
            self.index,
            analysis_id="flutter-aot:" + "b" * 64,
            artifact_sha256="a" * 64,
            blutter_commit="c" * 40,
            runtime={"dart_version": "3.5.4", "arch": "arm64"},
        )

    def test_builds_bounded_sqlite_index_with_provenance(self):
        result = self.build()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["counts"]["libraries"], 2)
        self.assertEqual(result["counts"]["classes"], 2)
        self.assertEqual(result["counts"]["functions"], 4)
        self.assertEqual(result["counts"]["xrefs"], 2)
        self.assertGreaterEqual(result["counts"]["strings"], 4)
        self.assertTrue(self.index.is_file())
        with sqlite3.connect(self.index) as conn:
            meta = dict(conn.execute("SELECT key,value FROM metadata"))
        self.assertEqual(meta["artifact_sha256"], "a" * 64)
        self.assertEqual(meta["artifact_kind"], "libapp.so")
        self.assertEqual(meta["blutter_commit"], "c" * 40)

    def test_symbol_search_returns_native_offset_without_raw_body(self):
        self.build()
        result = semantic.find_dart_symbols(self.index, "login")
        self.assertEqual(len(result["results"]), 1)
        row = result["results"][0]
        self.assertEqual(row["name"], "login")
        self.assertEqual(row["native_offset"], 0x1234)
        self.assertNotIn("body", row)
        self.assertEqual(result["provenance"]["evidence_state"], "derived")

    def test_object_pool_strings_are_indexed(self):
        self.build()
        result = semantic.find_dart_strings(self.index, "Authorization")
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["source_kind"], "object-pool")

    def test_string_occurrences_preserve_multiple_locations(self):
        path = self.root / "asm" / "app" / "api.dart"
        with path.open("a", encoding="utf-8") as handle:
            handle.write('// duplicate evidence: "Authorization"\n')
        self.build()
        result = semantic.find_dart_strings(self.index, "Authorization")
        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(
            {row["source_kind"] for row in result["results"]}, {"asm", "object-pool"}
        )

    def test_query_text_is_literal_and_case_sensitive(self):
        self.build()
        literal = semantic.find_dart_strings(self.index, "%")
        self.assertEqual([x["value"] for x in literal["results"]], ["literal%marker"])
        case_miss = semantic.find_dart_strings(self.index, "authorization")
        self.assertEqual(case_miss["results"], [])

    def test_xrefs_resolve_only_unique_targets(self):
        self.build()
        login = semantic.find_dart_symbols(self.index, "login")["results"][0]
        result = semantic.find_dart_xrefs(
            self.index, login["id"], direction="outgoing"
        )
        self.assertEqual(len(result["outgoing"]), 2)
        by_name = {edge["target_name"]: edge for edge in result["outgoing"]}
        self.assertEqual(by_name["verify"]["target_native_offset"], 0x2000)
        self.assertIsNotNone(by_name["verify"]["target_id"])
        self.assertIsNone(by_name["sign"]["target_id"])
        self.assertIsNone(by_name["sign"]["target_native_offset"])
        self.assertIn("not proof of value flow", result["limitations"][0])

    def test_ambiguous_symbol_requires_function_id(self):
        self.build()
        with self.assertRaises(semantic.FlutterIndexError):
            semantic.map_dart_to_native(self.index, "sign")

    def test_map_dart_to_native_preserves_offset_provenance(self):
        self.build()
        login = semantic.find_dart_symbols(self.index, "login")["results"][0]
        result = semantic.map_dart_to_native(self.index, login["id"])
        self.assertEqual(result["function"]["native_offset_hex"], "0x1234")
        self.assertEqual(result["function"]["size_hex"], "0x50")
        self.assertEqual(result["provenance"]["artifact_sha256"], "a" * 64)
        self.assertEqual(result["provenance"]["artifact_kind"], "libapp.so")

    def test_rejects_oversized_untrusted_line_and_removes_partial_index(self):
        bad = self.root / "asm" / "app" / "bad.dart"
        bad.write_bytes(
            b"// lib: , url: package:app/bad.dart\n"
            + b"A" * (semantic.MAX_LINE_BYTES + 10)
        )
        with self.assertRaises(semantic.FlutterIndexError):
            self.build()
        self.assertFalse(self.index.exists())

    def test_query_limit_is_hard_bounded(self):
        self.build()
        result = semantic.find_dart_symbols(self.index, "package:app", limit=999999)
        self.assertEqual(result["limit"], semantic.MAX_QUERY_LIMIT)


class FlutterSemanticEntrypointTests(unittest.TestCase):
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
        (cls.input_root / "libs" / "libapp.so").write_bytes(b"app-aot")
        (cls.input_root / "libs" / "libflutter.so").write_bytes(b"flutter")
        os.environ["SAFE_FLUTTER_INPUT"] = str(cls.input_root)
        os.environ["SAFE_FLUTTER_OUTPUT"] = str(cls.output_root)
        os.environ["SAFE_BLUTTER_ROOT"] = str(cls.blutter_root)
        os.environ["SAFE_BLUTTER_COMMIT"] = "d" * 40
        cls.adapter = importlib.import_module("safe_blutter_adapter")
        cls.entry = importlib.import_module("flutter_entrypoint")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.job_name = self._testMethodName
        self.job = self.output_root / self.job_name
        self.job.mkdir()

    def runtime(self):
        return {
            "identity_status": "identified",
            "dart_version": "3.5.4",
            "arch": "arm64",
            "os": "android",
            "snapshot_hash": "a" * 32,
        }

    def write_fixture(self):
        (self.job / "asm" / "app").mkdir(parents=True, exist_ok=True)
        (self.job / "asm" / "app" / "api.dart").write_text(
            """// lib: , url: package:app/api.dart
// class id: 1, size: 0x20
class Api extends Object {
  void ping() {
    // ** addr: 0x100, size: 0x20
  }
}
""",
            encoding="utf-8",
        )

    def test_build_index_requires_profile_generated_manifest(self):
        self.write_fixture()
        with self.assertRaises(self.adapter.AdapterError):
            self.entry._build_index_from_manifest(self.job)

    def test_manifest_binds_index_to_local_libapp_hash(self):
        self.write_fixture()
        manifest = self.entry._write_manifest(
            self.job, self.input_root / "libs", self.runtime()
        )
        result = self.entry._build_index_from_manifest(self.job)
        self.assertEqual(result["status"], "ok")
        self.assertTrue((self.job / self.entry.INDEX_NAME).is_file())
        self.assertEqual(result["artifact_sha256"], manifest["artifact_sha256"])
        self.assertEqual(result["analysis_id"], manifest["analysis_id"])

    def test_successful_analyze_automatically_builds_semantic_index(self):
        args = mock.Mock(libdir="libs", output=self.job_name, timeout=10)

        def fake_analyze(_libdir, _output, _timeout):
            self.write_fixture()
            return {
                "status": "ok",
                "profile": "framework-flutter",
                "runtime": self.runtime(),
                "executed": True,
            }

        with mock.patch.object(self.adapter, "analyze", side_effect=fake_analyze):
            result = self.entry._analyze_command(args)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["semantic_index"]["status"], "ok")
        self.assertTrue((self.job / self.entry.MANIFEST_NAME).is_file())
        self.assertTrue((self.job / self.entry.INDEX_NAME).is_file())

    def test_analyze_rejects_nonempty_output_before_adapter_execution(self):
        (self.job / "stale.txt").write_text("old evidence", encoding="utf-8")
        args = mock.Mock(libdir="libs", output=self.job_name, timeout=10)
        with mock.patch.object(
            self.adapter,
            "analyze",
            side_effect=AssertionError("analyzer must not run on stale output"),
        ):
            with self.assertRaises(self.adapter.AdapterError):
                self.entry._analyze_command(args)

    def test_manifest_rejects_different_blutter_revision(self):
        manifest = self.entry._write_manifest(
            self.job, self.input_root / "libs", self.runtime()
        )
        path = self.job / self.entry.MANIFEST_NAME
        os.chmod(path, 0o644)
        manifest["blutter_commit"] = "e" * 40
        path.write_text(__import__("json").dumps(manifest), encoding="utf-8")
        with self.assertRaises(self.adapter.AdapterError):
            self.entry._read_manifest(self.job)

    def test_manifest_symlink_is_rejected(self):
        real = self.job / "other.json"
        real.write_text("{}", encoding="utf-8")
        link = self.job / self.entry.MANIFEST_NAME
        try:
            link.symlink_to(real.name)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable")
        with self.assertRaises(self.adapter.AdapterError):
            self.entry._read_manifest(self.job)

    def test_index_symlink_inside_output_is_rejected(self):
        real = self.job / "other.sqlite"
        real.write_bytes(b"not-an-index")
        link = self.job / self.entry.INDEX_NAME
        try:
            link.symlink_to(real.name)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable")
        with self.assertRaises(self.adapter.AdapterError):
            self.entry._index_path(self.job_name)

    def test_output_symlink_component_is_rejected(self):
        real = self.output_root / f"{self.job_name}-real"
        real.mkdir()
        link = self.output_root / f"{self.job_name}-link"
        try:
            link.symlink_to(real.name, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable")
        with self.assertRaises(self.adapter.AdapterError):
            self.entry._output_dir(link.name)

    def test_index_path_cannot_escape_output_root(self):
        with self.assertRaises(self.adapter.AdapterError):
            self.entry._index_path("../escape")


if __name__ == "__main__":
    unittest.main()
