#!/usr/bin/env python3
import base64
import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

MODULE = Path(__file__).with_name("program_understanding_v2.py")
ANALYSIS_TEST_DEX_B64 = '''ZGV4CjAzNQBahmsi20g2ZLTHScOGjxUeP9oKbLiV36H8AwAAcAAAAHhWNBIA
AAAAAAAAAFwDAAAVAAAAcAAAAAoAAADEAAAABQAAAOwAAAABAAAAKAEAAAgA
AAAwAQAAAQAAAHABAABsAgAAkAEAABoCAAAiAgAANQIAADgCAABFAgAASAIA
AFgCAABvAgAAgwIAAJcCAACrAgAAwwIAANsCAADeAgAA4gIAAOYCAADzAgAA
+AIAAAEDAAALAwAAHAMAAAIAAAAEAAAABQAAAAYAAAAHAAAACAAAAAkAAAAK
AAAACwAAAAwAAAACAAAAAAAAAAAAAAAMAAAACQAAAAAAAAANAAAACQAAAAQC
AAAOAAAACQAAAAwCAAAOAAAACQAAABQCAAAGAAMAEAAAAAIAAQAAAAAAAgAD
ABIAAAACAAEAEwAAAAIAAQAUAAAAAwAEABEAAAAEAAEAAAAAAAcAAgAAAAAA
CAAAAA8AAAACAAAAAAAAAAQAAAAAAAAAAQAAAAAAAABFAwAAAAAAAAEAAQAB
AAAALQMAAAQAAABwEAUAAAAOAAIAAgABAAAAMgMAAAYAAAAfAQgAbhAHAAEA
DgADAAEAAgAAADkDAAAIAAAAIgAHABMBFwBwIAYAEAAOAAMAAQACAAAAPwMA
AAgAAABiAAAAGgEDAG4gBAAQAA4AAQAAAAEAAAABAAAABAAAAAEAAAAFAAY8
aW5pdD4AEUFuYWx5c2lzVGVzdC5qYXZhAAFEAAtIZWxsbyB3b3JsZAABSQAO
TEFuYWx5c2lzVGVzdDsAFUxqYXZhL2lvL1ByaW50U3RyZWFtOwASTGphdmEv
bGFuZy9PYmplY3Q7ABJMamF2YS9sYW5nL1N0cmluZzsAEkxqYXZhL2xhbmcv
U3lzdGVtOwAWTGphdmEvbWF0aC9CaWdEZWNpbWFsOwAWTGphdmEvbWF0aC9C
aWdJbnRlZ2VyOwABVgACVkkAAlZMAAtkb3VibGVWYWx1ZQADb3V0AAdwcmlu
dGxuAAh0ZXN0Q2FzdAAPdGVzdE9iamVjdENhbGxzAA90ZXN0U3RhdGljQ2Fs
bHMABAAHDgASAQAHDloADQAHDngACAAHDngAAAABAwCAgASQAwEBqAMBAcQD
AQHkAwANAAAAAAAAAAEAAAAAAAAAAQAAABUAAABwAAAAAgAAAAoAAADEAAAA
AwAAAAUAAADsAAAABAAAAAEAAAAoAQAABQAAAAgAAAAwAQAABgAAAAEAAABw
AQAAASAAAAQAAACQAQAAARAAAAMAAAAEAgAAAiAAABUAAAAaAgAAAyAAAAQA
AAAtAwAAACAAAAEAAABFAwAAABAAAAEAAABcAwAA'''


class ProgramUnderstandingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("safe_program_understanding_test", MODULE)
        cls.pu = importlib.util.module_from_spec(spec)
        assert spec.loader
        spec.loader.exec_module(cls.pu)
        import pu_index
        import pu_source
        cls.index = pu_index
        cls.source = pu_source

    def make_job(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        workspace = root / "workspace"
        job = root / "job"
        source = job / "jadx" / "sources" / "com" / "example"
        workspace.mkdir()
        source.mkdir(parents=True)
        (workspace / "app.apk").write_bytes(b"not-a-real-apk")
        (job / "job.json").write_text(json.dumps({"artifact": "app.apk"}), encoding="utf-8")
        (source / "Api.java").write_text(
            '''package com.example;
public interface Api {
  @POST("/v1/login")
  Call<LoginResponse> login(LoginRequest request);
  void refresh();
}
class AuthHeaders {
  public String authorization(String access_token) {
    refresh();
    return "Bearer " + access_token;
  }
}
''',
            encoding="utf-8",
        )
        return tmp, workspace, job

    def seed_dex_index(self, job):
        with self.index.connect(job) as conn:
            self.index.init_db(conn)
            methods = [
                ("LApi; login (LLoginRequest;)V", "com.example.Api", "login", "(LLoginRequest;)V", 1, 0),
                ("LAdminApi; login (LLoginRequest;)V", "com.example.AdminApi", "login", "(LLoginRequest;)V", 1, 0),
                ("LApi; login (LLoginRequest;Ljava/lang/String;)V", "com.example.Api", "login", "(LLoginRequest;Ljava/lang/String;)V", 2, 0),
                ("LRepo; submit ()V", "com.example.Repo", "submit", "()V", 0, 0),
                ("LAdminRepo; submit ()V", "com.example.AdminRepo", "submit", "()V", 0, 0),
            ]
            for method in methods:
                conn.execute(
                    "INSERT INTO methods(id,class,name,descriptor,parameter_count,external,source_json) VALUES (?,?,?,?,?,?,?)",
                    (*method, "{}"),
                )
            conn.execute(
                "INSERT INTO call_edges(caller,callee,offset,confidence,kind) VALUES (?,?,?,?,?)",
                ("LRepo; submit ()V", "LApi; login (LLoginRequest;)V", 4, 0.98, "dex-xref"),
            )
            conn.execute(
                "INSERT INTO call_edges(caller,callee,offset,confidence,kind) VALUES (?,?,?,?,?)",
                ("LAdminRepo; submit ()V", "LAdminApi; login (LLoginRequest;)V", 4, 0.98, "dex-xref"),
            )
            workspace_artifact = job.parent / "workspace" / "app.apk"
            metadata = {
                "schema_version": 2,
                "builder_version": 2,
                "analysis_kind": "dex-xref",
                "analyzer": {"name": "test"},
                "truncated": {"methods": False, "edges": False},
                "artifact_stat": self.index.artifact_stat(workspace_artifact),
            }
            for key, value in metadata.items():
                self.index.meta_set(conn, key, value)
            conn.commit()

    def test_parser_rejects_annotations_and_invocations(self):
        tmp, _, job = self.make_job()
        try:
            value = (job / "jadx" / "sources" / "com" / "example" / "Api.java").read_text()
            names = [item["name"] for item in self.source.declarations(value, "Api")]
            self.assertIn("login", names)
            self.assertIn("refresh", names)
            self.assertIn("authorization", names)
            self.assertNotIn("POST", names)
            self.assertNotIn("T", names)
            self.assertEqual(names.count("refresh"), 1)
        finally:
            tmp.cleanup()

    def test_source_fallback_uses_sqlite_index(self):
        tmp, workspace, job = self.make_job()
        try:
            result = self.pu.build_program_index(job, workspace)
            self.assertEqual(result["analysis_kind"], "source-fallback")
            self.assertEqual(result["storage"], "sqlite")
            self.assertTrue((job / "program-index.sqlite3").is_file())
            symbols = self.pu.find_symbols(job, workspace, "login")
            self.assertEqual(symbols["matches"][0]["name"], "login")
        finally:
            tmp.cleanup()

    def test_network_model_resolves_class_and_arity_without_union(self):
        tmp, workspace, job = self.make_job()
        try:
            self.seed_dex_index(job)
            endpoint = self.pu.extract_network_model(job, workspace)["endpoints"][0]
            self.assertEqual(endpoint["declaring_method"], "login")
            self.assertEqual(endpoint["symbol_resolution"]["status"], "resolved")
            self.assertEqual(endpoint["symbol_resolution"]["resolved_symbol_id"], "LApi; login (LLoginRequest;)V")
            self.assertEqual(endpoint["callers"], ["LRepo; submit ()V"])
            self.assertNotIn("LAdminRepo; submit ()V", endpoint["callers"])
        finally:
            tmp.cleanup()

    def test_find_xrefs_queries_sqlite_edges(self):
        tmp, workspace, job = self.make_job()
        try:
            self.seed_dex_index(job)
            result = self.pu.find_xrefs(job, workspace, "com.example.Api login", direction="incoming")
            self.assertEqual(len(result["xrefs"]), 1)
            self.assertTrue(all(edge["from"] != "LAdminRepo; submit ()V" for edge in result["xrefs"]))
        finally:
            tmp.cleanup()

    def test_cache_reuses_unchanged_artifact(self):
        tmp, workspace, job = self.make_job()
        try:
            first = self.pu.build_program_index(job, workspace)
            second = self.pu.build_program_index(job, workspace)
            self.assertFalse(first["cached"])
            self.assertTrue(second["cached"])
        finally:
            tmp.cleanup()

    def test_real_dex_semantics_when_androguard_is_available(self):
        if not self.pu.capabilities()["androguard"]:
            self.skipTest("Androguard is not installed in the host unit-test environment")
        tmp = tempfile.TemporaryDirectory()
        try:
            root = Path(tmp.name)
            workspace = root / "workspace"
            job = root / "job"
            workspace.mkdir()
            job.mkdir()
            apk = workspace / "analysis.apk"
            with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("classes.dex", base64.b64decode(ANALYSIS_TEST_DEX_B64))
            (job / "job.json").write_text(json.dumps({"artifact": "analysis.apk"}), encoding="utf-8")
            result = self.pu.build_program_index(job, workspace, force=True)
            self.assertEqual(result["analysis_kind"], "dex-xref", result.get("fallback_reason"))
            self.assertGreaterEqual(result["method_count"], 4)
            symbols = self.pu.find_symbols(job, workspace, "testObjectCalls")
            self.assertTrue(symbols["matches"])
            xrefs = self.pu.find_xrefs(job, workspace, "testObjectCalls", direction="outgoing")
            self.assertTrue(xrefs["xrefs"])
            cfg = self.pu.get_cfg(job, workspace, "testObjectCalls", max_blocks=50)
            self.assertTrue(cfg["matches"])
            self.assertTrue(cfg["matches"][0]["blocks"])
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
