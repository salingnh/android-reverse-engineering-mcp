#!/usr/bin/env python3
import json
import os
import tempfile
import unittest
from pathlib import Path

import program_understanding_v2 as pu
import pu_index
import pu_source


SOURCE = '''package com.example;
public interface Api {
  @POST("/v1/login")
  Call<LoginResponse> login(LoginRequest request);
}
class AuthHeaders {
  public String authorization(String access_token) {
    return "Authorization: Bearer " + access_token;
  }
  class InnerApi {
    @GET("/v1/inner")
    Call<InnerResponse> inner();
  }
}
class SecondaryApi {
  @GET("/v1/secondary")
  Call<SecondaryResponse> secondary();
}
'''


class ProgramUnderstandingScopeTests(unittest.TestCase):
    def make_job(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        workspace = root / "workspace"
        job = root / "job"
        source = job / "jadx" / "sources" / "com" / "example"
        workspace.mkdir()
        source.mkdir(parents=True)
        artifact = workspace / "app.apk"
        artifact.write_bytes(b"invalid-apk-A")
        (job / "job.json").write_text(
            json.dumps({"artifact": "app.apk"}), encoding="utf-8"
        )
        (source / "Api.java").write_text(SOURCE, encoding="utf-8")
        return tmp, workspace, job, artifact

    def test_declarations_preserve_top_level_and_nested_owners(self):
        items = pu_source.declarations(SOURCE, "Api")
        owners = {(item["name"], item["class_name"]) for item in items}
        self.assertIn(("login", "Api"), owners)
        self.assertIn(("authorization", "AuthHeaders"), owners)
        self.assertIn(("inner", "AuthHeaders$InnerApi"), owners)
        self.assertIn(("secondary", "SecondaryApi"), owners)

    def test_source_fallback_symbol_index_uses_lexical_owner(self):
        tmp, workspace, job, _ = self.make_job()
        try:
            result = pu.build_program_index(job, workspace, force=True)
            self.assertEqual(result["analysis_kind"], "source-fallback")
            self.assertEqual(result["builder_version"], pu_index.BUILDER_VERSION)
            auth = pu.find_symbols(job, workspace, "authorization")["matches"]
            self.assertEqual(auth[0]["class"], "com.example.AuthHeaders")
            nested = pu.find_symbols(job, workspace, "inner")["matches"]
            self.assertTrue(
                any(item["class"] == "com.example.AuthHeaders$InnerApi" for item in nested)
            )
            secondary = pu.find_symbols(job, workspace, "secondary")["matches"]
            self.assertTrue(
                any(item["class"] == "com.example.SecondaryApi" for item in secondary)
            )
        finally:
            tmp.cleanup()

    def test_network_evidence_uses_owning_class(self):
        tmp, workspace, job, _ = self.make_job()
        try:
            pu.build_program_index(job, workspace, force=True)
            model = pu.extract_network_model(job, workspace)
            endpoints = {item["path"]: item for item in model["endpoints"]}
            self.assertEqual(
                endpoints["/v1/login"]["declaring_class"], "com.example.Api"
            )
            self.assertEqual(
                endpoints["/v1/inner"]["declaring_class"],
                "com.example.AuthHeaders$InnerApi",
            )
            self.assertEqual(
                endpoints["/v1/secondary"]["declaring_class"],
                "com.example.SecondaryApi",
            )
            auth = [item for item in model["auth_evidence"] if item["signal"] == "Authorization"]
            self.assertTrue(auth)
            self.assertEqual(auth[0]["declaring_class"], "com.example.AuthHeaders")
            self.assertEqual(auth[0]["declaring_method"], "authorization")
        finally:
            tmp.cleanup()

    def test_cache_detects_same_size_same_mtime_artifact_replacement(self):
        tmp, workspace, job, artifact = self.make_job()
        try:
            pu.build_program_index(job, workspace, force=True)
            before = artifact.stat()
            old_hash = pu_index.sha256(artifact)
            replacement = b"invalid-apk-B"
            self.assertEqual(len(replacement), artifact.stat().st_size)
            artifact.write_bytes(replacement)
            os.utime(artifact, ns=(before.st_atime_ns, before.st_mtime_ns))
            self.assertEqual(artifact.stat().st_size, before.st_size)
            self.assertEqual(artifact.stat().st_mtime_ns, before.st_mtime_ns)
            self.assertNotEqual(pu_index.sha256(artifact), old_hash)

            pu.find_symbols(job, workspace, "login")
            with pu_index.connect(job) as conn:
                self.assertEqual(
                    pu_index.meta_get(conn, "artifact_sha256"),
                    pu_index.sha256(artifact),
                )
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
