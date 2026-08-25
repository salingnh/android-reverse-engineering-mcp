#!/usr/bin/env python3
import json
import os
import tempfile
import unittest
from pathlib import Path

import program_understanding_v2 as pu
import pu_index
import pu_source
from tests_code_ownership import CodeOwnershipTests  # imported for unittest discovery


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

VENDOR_SOURCE = '''package com.google.firebase.auth;
public class FirebaseApi {
  @POST("/firebase/internal")
  public void login() {}
}
'''

GENERATED_SOURCE = '''package com.example;
public class Hilt_MainActivity {
  public void login() {}
}
'''

MANIFEST = '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
  <application android:name=".App">
    <activity android:name=".MainActivity" />
    <provider android:name="com.google.firebase.provider.FirebaseInitProvider" />
  </application>
</manifest>
'''


class ProgramUnderstandingScopeTests(unittest.TestCase):
    def make_job(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        workspace = root / "workspace"
        job = root / "job"
        source = job / "jadx" / "sources" / "com" / "example"
        vendor = job / "jadx" / "sources" / "com" / "google" / "firebase" / "auth"
        resources = job / "jadx" / "resources"
        workspace.mkdir()
        source.mkdir(parents=True)
        vendor.mkdir(parents=True)
        resources.mkdir(parents=True)
        artifact = workspace / "app.apk"
        artifact.write_bytes(b"invalid-apk-A")
        (job / "job.json").write_text(
            json.dumps({"artifact": "app.apk"}), encoding="utf-8"
        )
        (source / "Api.java").write_text(SOURCE, encoding="utf-8")
        (source / "Hilt_MainActivity.java").write_text(GENERATED_SOURCE, encoding="utf-8")
        (vendor / "FirebaseApi.java").write_text(VENDOR_SOURCE, encoding="utf-8")
        (resources / "AndroidManifest.xml").write_text(MANIFEST, encoding="utf-8")
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
            self.assertEqual(result["ownership_model"]["context"]["application_package"], "com.example")
            auth = pu.find_symbols(job, workspace, "authorization")["matches"]
            self.assertEqual(auth[0]["class"], "com.example.AuthHeaders")
            self.assertEqual(auth[0]["ownership"]["scope"], "FIRST_PARTY")
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

    def test_default_symbol_scope_suppresses_sdk_and_generated_internals(self):
        tmp, workspace, job, _ = self.make_job()
        try:
            pu.build_program_index(job, workspace, force=True)
            application = pu.find_symbols(job, workspace, "login")
            self.assertEqual(application["scope"], "application")
            self.assertEqual(
                {item["class"] for item in application["matches"]},
                {"com.example.Api"},
            )
            third_party = pu.find_symbols(job, workspace, "login", scope="third_party")
            self.assertEqual(
                {item["class"] for item in third_party["matches"]},
                {"com.google.firebase.auth.FirebaseApi"},
            )
            generated = pu.find_symbols(job, workspace, "login", scope="generated")
            self.assertEqual(
                {item["class"] for item in generated["matches"]},
                {"com.example.Hilt_MainActivity"},
            )
            all_results = pu.find_symbols(job, workspace, "login", scope="all")
            self.assertEqual(len(all_results["matches"]), 3)
        finally:
            tmp.cleanup()

    def test_default_network_scope_does_not_scan_vendor_source(self):
        tmp, workspace, job, _ = self.make_job()
        try:
            pu.build_program_index(job, workspace, force=True)
            application = pu.extract_network_model(job, workspace)
            paths = {item["path"] for item in application["endpoints"]}
            self.assertIn("/v1/login", paths)
            self.assertNotIn("/firebase/internal", paths)
            self.assertGreaterEqual(application["source_files_skipped_by_scope"], 2)
            self.assertTrue(
                all(item["ownership"]["scope"] == "FIRST_PARTY" for item in application["endpoints"])
            )

            vendor = pu.extract_network_model(job, workspace, scope="third_party")
            vendor_paths = {item["path"] for item in vendor["endpoints"]}
            self.assertEqual(vendor_paths, {"/firebase/internal"})
            self.assertTrue(
                all(item["ownership"]["scope"] == "THIRD_PARTY" for item in vendor["endpoints"])
            )
        finally:
            tmp.cleanup()

    def test_application_xref_retains_direct_sdk_boundary(self):
        tmp, workspace, job, _ = self.make_job()
        try:
            pu.build_program_index(job, workspace, force=True)
            with pu_index.connect(job) as conn:
                app_id = conn.execute(
                    "SELECT id FROM methods WHERE class=? AND name=?",
                    ("com.example.Api", "login"),
                ).fetchone()["id"]
                vendor_id = conn.execute(
                    "SELECT id FROM methods WHERE class=? AND name=?",
                    ("com.google.firebase.auth.FirebaseApi", "login"),
                ).fetchone()["id"]
                conn.execute(
                    "INSERT INTO call_edges(caller,callee,offset,confidence,kind) VALUES (?,?,?,?,?)",
                    (app_id, vendor_id, 8, 0.98, "fixture-xref"),
                )
                conn.commit()
            result = pu.find_xrefs(
                job,
                workspace,
                "com.example.Api login",
                direction="outgoing",
            )
            self.assertEqual(len(result["xrefs"]), 1)
            edge = result["xrefs"][0]
            self.assertTrue(edge["boundary"])
            self.assertEqual(edge["from_ownership"]["scope"], "FIRST_PARTY")
            self.assertEqual(edge["to_ownership"]["scope"], "THIRD_PARTY")
            self.assertEqual(result["boundary_edge_count"], 1)
        finally:
            tmp.cleanup()

    def test_vendor_noise_cannot_starve_application_symbol_results(self):
        tmp, workspace, job, _ = self.make_job()
        try:
            pu.build_program_index(job, workspace, force=True)
            with pu_index.connect(job) as conn:
                conn.execute(
                    "INSERT INTO methods(id,class,name,descriptor,parameter_count,external,source_json) VALUES (?,?,?,?,?,?,?)",
                    ("app-noise", "com.example.Noise", "noise", "()V", 0, 0, "{}"),
                )
                for index in range(250):
                    conn.execute(
                        "INSERT INTO methods(id,class,name,descriptor,parameter_count,external,source_json) VALUES (?,?,?,?,?,?,?)",
                        (
                            f"vendor-noise-{index:04d}",
                            f"com.facebook.internal.Noise{index:04d}",
                            "noise",
                            "()V",
                            0,
                            0,
                            "{}",
                        ),
                    )
                conn.commit()
            result = pu.find_symbols(job, workspace, "noise", limit=1)
            self.assertEqual([item["id"] for item in result["matches"]], ["app-noise"])
            self.assertEqual(result["matched_count"], 1)
            self.assertGreater(result["scanned_count"], 200)
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
