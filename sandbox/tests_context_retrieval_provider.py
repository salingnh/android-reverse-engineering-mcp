from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import context_retrieval as context
import program_model as pm
import pu_index
import pu_program_model
import static_context_retrieval as static_context


class DexContextRetrievalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.job = root / "jobs" / "job-1"
        self.job.mkdir(parents=True)
        self.workspace = root / "workspace"
        self.workspace.mkdir()
        self.artifact = self.workspace / "app.apk"
        self.artifact.write_bytes(b"fixture")
        manifest = self.job / "jadx" / "resources" / "AndroidManifest.xml"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example"><application android:name="com.example.App"/></manifest>',
            encoding="utf-8",
        )
        self.source = self.job / "jadx" / "sources" / "com" / "example" / "AuthService.java"
        self.source.parent.mkdir(parents=True)
        self.source.write_text(
            "package com.example;\n"
            "public class AuthService {\n"
            "  public void helper() { }\n"
            "  public void login() {\n"
            "    String token = \"token\";\n"
            "    helper();\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )
        with pu_index.connect(self.job) as conn:
            pu_index.init_db(conn)
            pu_index.meta_set(conn, "artifact_sha256", "a" * 64)
            pu_index.meta_set(conn, "analysis_kind", "dex-xref")
            pu_index.meta_set(conn, "analyzer", {"name": "androguard", "version": "4.1.4"})
            login_id = "Lcom/example/AuthService; login ()V"
            helper_id = "Lcom/example/AuthService; helper ()V"
            sdk_id = "Lcom/google/firebase/auth/Auth; signIn ()V"
            conn.executemany(
                "INSERT INTO methods VALUES (?,?,?,?,?,?,?)",
                [
                    (
                        login_id,
                        "com.example.AuthService",
                        "login",
                        "()V",
                        0,
                        0,
                        json.dumps({"file": "jadx/sources/com/example/AuthService.java", "line": 4}),
                    ),
                    (
                        helper_id,
                        "com.example.AuthService",
                        "helper",
                        "()V",
                        0,
                        0,
                        json.dumps({"file": "jadx/sources/com/example/AuthService.java", "line": 3}),
                    ),
                    (
                        sdk_id,
                        "com.google.firebase.auth.Auth",
                        "signIn",
                        "()V",
                        0,
                        1,
                        json.dumps({"apk_member": "external"}),
                    ),
                ],
            )
            conn.executemany(
                "INSERT INTO call_edges VALUES (?,?,?,?,?)",
                [
                    (login_id, helper_id, 24, 0.99, "dex-xref"),
                    (login_id, sdk_id, 32, 0.99, "dex-xref"),
                ],
            )
            conn.commit()
        self.ensure_patch = mock.patch.object(pu_index, "ensure_index", lambda *args, **kwargs: None)
        self.artifact_patch = mock.patch.object(
            pu_index, "artifact", lambda *args, **kwargs: self.artifact
        )
        self.ensure_patch.start()
        self.artifact_patch.start()

    def tearDown(self):
        self.ensure_patch.stop()
        self.artifact_patch.stop()
        self.tmp.cleanup()

    def repository(self):
        provider = pu_program_model.DexProgramProvider(
            self.job,
            self.workspace,
            {"androguard": True},
        )
        return pm.ProgramRepository((provider,))

    def login_entity(self, repo):
        page = repo.find_entities(
            kind="FUNCTION",
            text="AuthService.login",
            ownership_scope="application",
            limit=10,
        )
        return next(item for item in page.items if item.display_name.endswith(".login"))

    def test_function_context_localizes_bounded_jadx_source_and_boundary(self):
        repo = self.repository()
        login = self.login_entity(repo)
        result = context.ContextRetriever(
            repo,
            static_context.DexContextSourceProvider(self.job),
        ).get_function_context(entity_id=login.entity_id)
        self.assertEqual(result["root"]["entity_id"], login.entity_id)
        self.assertEqual(len(result["source_slices"]), 1)
        source = result["source_slices"][0]
        self.assertEqual(source["canonical_truth"], False)
        self.assertFalse(Path(source["source_file"]).is_absolute())
        self.assertIn("login", source["text"])
        kinds = {item["kind"] for item in result["relationships"]}
        self.assertIn("CALLS", kinds)
        self.assertIn("CALLS_EXTERNAL", kinds)
        self.assertTrue(all(item["data_flow_claim"] is False for item in result["relationships"]))

    def test_source_provider_rejects_escape_and_symlinked_source(self):
        repo = self.repository()
        login = self.login_entity(repo)
        source_provider = static_context.DexContextSourceProvider(self.job)
        self.assertIsNone(source_provider._from_locator("../../outside.java"))

        outside = Path(self.tmp.name) / "outside.java"
        outside.write_text("public class AuthService { public void login() {} }", encoding="utf-8")
        self.source.unlink()
        self.source.symlink_to(outside)
        self.assertIsNone(
            source_provider.source_slice(
                entity=login,
                evidence=(),
                line_limit=20,
                byte_limit=4096,
            )
        )


if __name__ == "__main__":
    unittest.main()
