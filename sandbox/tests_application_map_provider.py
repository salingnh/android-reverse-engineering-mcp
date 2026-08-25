from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import application_map as amap
import program_model as pm
import pu_index
import pu_program_model


class DexApplicationMapTests(unittest.TestCase):
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
        with pu_index.connect(self.job) as conn:
            pu_index.init_db(conn)
            pu_index.meta_set(conn, "artifact_sha256", "a" * 64)
            pu_index.meta_set(conn, "analysis_kind", "dex-xref")
            pu_index.meta_set(
                conn,
                "analyzer",
                {"name": "androguard", "version": "4.1.4"},
            )
            app_id = "Lcom/example/AuthService; login ()V"
            sdk_id = "Lcom/google/firebase/auth/Auth; signIn ()V"
            conn.executemany(
                "INSERT INTO methods VALUES (?,?,?,?,?,?,?)",
                [
                    (
                        app_id,
                        "com.example.AuthService",
                        "login",
                        "()V",
                        0,
                        0,
                        json.dumps({"apk_member": "base.apk"}),
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
            conn.execute(
                "INSERT INTO call_edges VALUES (?,?,?,?,?)",
                (app_id, sdk_id, 24, 0.99, "dex-xref"),
            )
            conn.commit()
        self.ensure_patch = mock.patch.object(
            pu_index,
            "ensure_index",
            lambda *args, **kwargs: None,
        )
        self.artifact_patch = mock.patch.object(
            pu_index,
            "artifact",
            lambda *args, **kwargs: self.artifact,
        )
        self.ensure_patch.start()
        self.artifact_patch.start()

    def tearDown(self):
        self.ensure_patch.stop()
        self.artifact_patch.stop()
        self.tmp.cleanup()

    def provider(self):
        return pu_program_model.DexProgramProvider(
            self.job,
            self.workspace,
            {"androguard": True},
        )

    def test_map_retains_app_to_sdk_boundary(self):
        result = amap.ApplicationMapProjector(
            pm.ProgramRepository((self.provider(),))
        ).get_application_map(node_limit=20, edge_limit=20)
        self.assertIn(
            "com.example.AuthService.login",
            [item["display_name"] for item in result["nodes"]],
        )
        boundaries = [
            item for item in result["nodes"] if item["kind"] == "EXTERNAL_BOUNDARY"
        ]
        self.assertEqual(len(boundaries), 1)
        self.assertEqual(boundaries[0]["ownership"], "THIRD_PARTY")
        self.assertEqual(
            [item["kind"] for item in result["edges"] if item["kind"] == "CALLS_EXTERNAL"],
            ["CALLS_EXTERNAL"],
        )

    def test_expand_boundary_after_provider_reconstruction(self):
        first = amap.ApplicationMapProjector(
            pm.ProgramRepository((self.provider(),))
        ).get_application_map(node_limit=20, edge_limit=20)
        boundary_id = next(
            item["entity_id"]
            for item in first["nodes"]
            if item["kind"] == "EXTERNAL_BOUNDARY"
        )
        # New provider and repository instance proves no map/process cache is required.
        second = amap.ApplicationMapProjector(
            pm.ProgramRepository((self.provider(),))
        ).expand_application_node(
            entity_id=boundary_id,
            direction="both",
            node_limit=20,
            edge_limit=20,
        )
        self.assertEqual(second["root_entity_id"], boundary_id)
        self.assertIn("CALLS_EXTERNAL", [item["kind"] for item in second["edges"]])


if __name__ == "__main__":
    unittest.main()
