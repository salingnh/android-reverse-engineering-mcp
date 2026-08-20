#!/usr/bin/env python3
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).with_name("program_understanding.py")


class ProgramUnderstandingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("safe_program_understanding_test", MODULE)
        cls.pu = importlib.util.module_from_spec(spec)
        assert spec.loader
        spec.loader.exec_module(cls.pu)

    def make_job(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        workspace = root / "workspace"
        job = root / "job"
        src = job / "jadx" / "sources" / "com" / "example"
        workspace.mkdir()
        src.mkdir(parents=True)
        (workspace / "app.apk").write_bytes(b"not-a-real-apk")
        (job / "job.json").write_text(json.dumps({"artifact": "app.apk"}), encoding="utf-8")
        (src / "Api.java").write_text(
            """package com.example;
public interface Api {
  @POST(\"/v1/login\")
  Call<LoginResponse> login(LoginRequest request);
}
class AuthHeaders {
  public String authorization(String access_token) {
    return \"Bearer \" + access_token;
  }
}
""",
            encoding="utf-8",
        )
        return tmp, workspace, job

    def test_source_fallback_builds_symbol_index(self):
        tmp, workspace, job = self.make_job()
        try:
            result = self.pu.build_program_index(job, workspace)
            self.assertEqual(result["analysis_kind"], "source-fallback")
            symbols = self.pu.find_symbols(job, workspace, "login")
            self.assertTrue(symbols["matches"])
            self.assertEqual(symbols["matches"][0]["name"], "login")
        finally:
            tmp.cleanup()

    def test_find_xrefs_reads_normalized_edges(self):
        tmp, workspace, job = self.make_job()
        try:
            index = {
                "analysis_kind": "dex-xref",
                "methods": [
                    {"id": "LApi; login ()V", "class": "Api", "name": "login", "descriptor": "()V"},
                    {"id": "LRepo; submit ()V", "class": "Repo", "name": "submit", "descriptor": "()V"},
                ],
                "call_edges": [{"from": "LRepo; submit ()V", "to": "LApi; login ()V", "kind": "dex-xref", "confidence": 0.98}],
            }
            (job / "program-index.json").write_text(json.dumps(index), encoding="utf-8")
            result = self.pu.find_xrefs(job, workspace, "login", direction="incoming")
            self.assertEqual(len(result["xrefs"]), 1)
            self.assertEqual(result["xrefs"][0]["from"], "LRepo; submit ()V")
        finally:
            tmp.cleanup()

    def test_network_model_returns_endpoint_and_auth_evidence(self):
        tmp, workspace, job = self.make_job()
        try:
            index = {
                "analysis_kind": "dex-xref",
                "methods": [
                    {"id": "LApi; login (LLoginRequest;)V", "class": "com.example.Api", "name": "login", "descriptor": "(LLoginRequest;)V"},
                    {"id": "LRepo; submit ()V", "class": "com.example.Repo", "name": "submit", "descriptor": "()V"},
                ],
                "call_edges": [{"from": "LRepo; submit ()V", "to": "LApi; login (LLoginRequest;)V", "kind": "dex-xref", "confidence": 0.98}],
            }
            (job / "program-index.json").write_text(json.dumps(index), encoding="utf-8")
            result = self.pu.extract_network_model(job, workspace)
            self.assertEqual(result["endpoints"][0]["path"], "/v1/login")
            self.assertIn("LRepo; submit ()V", result["endpoints"][0]["callers"])
            self.assertTrue(any(x["signal"].lower() in {"authorization", "bearer", "access_token"} for x in result["auth_evidence"]))
        finally:
            tmp.cleanup()

    def test_apkid_is_optional(self):
        tmp, workspace, job = self.make_job()
        try:
            result = self.pu.identify_protector(workspace / "app.apk")
            if not self.pu.capabilities()["apkid"]:
                self.assertFalse(result["available"])
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
