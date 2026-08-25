from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import program_model as pm
import pu_index
import pu_program_model


class DexProgramProviderTests(unittest.TestCase):
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
            rows = [
                (
                    "Lcom/example/App; login ()V",
                    "com.example.App",
                    "login",
                    "()V",
                    0,
                    0,
                    json.dumps({"apk_member": "base.apk"}),
                ),
                (
                    "Lcom/google/firebase/auth/Auth; sign ()V",
                    "com.google.firebase.auth.Auth",
                    "sign",
                    "()V",
                    0,
                    1,
                    json.dumps({"apk_member": "external-or-unknown"}),
                ),
            ]
            conn.executemany("INSERT INTO methods VALUES (?,?,?,?,?,?,?)", rows)
            conn.execute(
                "INSERT INTO call_edges VALUES (?,?,?,?,?)",
                (rows[0][0], rows[1][0], 12, 0.98, "dex-xref"),
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

    def test_default_application_scope_suppresses_sdk_roots_and_retains_boundary(self):
        provider = pu_program_model.DexProgramProvider(
            self.job,
            self.workspace,
            {"androguard": True},
        )
        repo = pm.ProgramRepository((provider,))
        functions = repo.find_entities(kind="FUNCTION", limit=20)
        self.assertEqual(
            [item.display_name for item in functions.items],
            ["com.example.App.login"],
        )
        app_fn = functions.items[0]
        relations = repo.find_relationships(
            entity_id=app_fn.entity_id,
            direction="outgoing",
            limit=20,
        )
        calls = [
            item for item in relations.items if item.kind == "CALLS_EXTERNAL"
        ]
        self.assertEqual(len(calls), 1)
        boundary = provider.get_entity(calls[0].target_entity_id)
        self.assertIsNotNone(boundary)
        self.assertEqual(boundary.kind, "EXTERNAL_BOUNDARY")
        self.assertEqual(boundary.ownership, "THIRD_PARTY")
        self.assertEqual(
            boundary.properties["boundary_kind"],
            "third-party-sdk",
        )

    def test_boundary_resolves_and_retains_crossing_after_provider_restart(self):
        provider = pu_program_model.DexProgramProvider(
            self.job,
            self.workspace,
            {"androguard": True},
        )
        repo = pm.ProgramRepository((provider,))
        app_fn = repo.find_entities(
            kind="FUNCTION",
            text="login",
            limit=10,
        ).items[0]
        original = next(
            item
            for item in repo.find_relationships(
                entity_id=app_fn.entity_id,
                direction="outgoing",
                limit=20,
            ).items
            if item.kind == "CALLS_EXTERNAL"
        )
        original_boundary = provider.get_entity(original.target_entity_id)
        self.assertIsNotNone(original_boundary)

        restarted = pu_program_model.DexProgramProvider(
            self.job,
            self.workspace,
            {"androguard": True},
        )
        self.assertNotIn(original.target_entity_id, restarted._boundary_entities)
        rebuilt = restarted.get_entity(original.target_entity_id)
        self.assertIsNotNone(rebuilt)
        self.assertEqual(rebuilt.to_dict(), original_boundary.to_dict())

        restarted_repo = pm.ProgramRepository((restarted,))
        incoming = restarted_repo.find_relationships(
            entity_id=original.target_entity_id,
            direction="incoming",
            limit=20,
        )
        self.assertEqual(
            [item.relationship_id for item in incoming.items],
            [original.relationship_id],
        )

    def test_explicit_third_party_scope_exposes_sdk_function(self):
        provider = pu_program_model.DexProgramProvider(
            self.job,
            self.workspace,
            {"androguard": True},
        )
        functions = pm.ProgramRepository((provider,)).find_entities(
            kind="FUNCTION",
            ownership_scope="third_party",
            limit=20,
        )
        self.assertEqual(
            [item.display_name for item in functions.items],
            ["com.google.firebase.auth.Auth.sign"],
        )

    def test_declares_is_structural_and_private_ids_do_not_leak(self):
        provider = pu_program_model.DexProgramProvider(
            self.job,
            self.workspace,
            {"androguard": True},
        )
        repo = pm.ProgramRepository((provider,))
        clazz = repo.find_entities(
            kind="CLASS",
            text="com.example.App",
            limit=10,
        ).items[0]
        relations = repo.find_relationships(
            entity_id=clazz.entity_id,
            direction="outgoing",
            kinds=("DECLARES",),
            limit=10,
        )
        self.assertEqual(len(relations.items), 1)
        fn = provider.get_entity(relations.items[0].target_entity_id)
        self.assertIsNotNone(fn)
        self.assertNotIn("Lcom/example/App;", fn.entity_id)
        self.assertNotIn("source_json", str(fn.to_dict()))
        evidence = repo.get_evidence(fn.evidence_refs)
        self.assertEqual(evidence[0]["schema_version"], 2)

    def test_non_dex_edge_is_never_promoted_to_call(self):
        with pu_index.connect(self.job) as conn:
            pu_index.meta_set(conn, "analysis_kind", "source-fallback")
            conn.execute("UPDATE call_edges SET kind='source-xref'")
            conn.commit()
        provider = pu_program_model.DexProgramProvider(
            self.job,
            self.workspace,
            {"androguard": False},
        )
        fn = pm.ProgramRepository((provider,)).find_entities(
            kind="FUNCTION",
            text="login",
            limit=10,
        ).items[0]
        page = provider.query_relationships(
            entity_id=fn.entity_id,
            direction="outgoing",
            ownership_scope="all",
            limit=10,
        )
        self.assertEqual(
            [item.kind for item in page.items if item.kind != "DECLARES"],
            ["XREF"],
        )

    def test_provider_continuation_does_not_repeat_previous_page(self):
        provider = pu_program_model.DexProgramProvider(
            self.job,
            self.workspace,
            {"androguard": True},
        )
        first = provider.query_entities(
            kind="FUNCTION",
            ownership_scope="all",
            limit=1,
        )
        self.assertTrue(first.has_more)
        after = pm.entity_sort_key(first.items[-1])
        second = provider.query_entities(
            kind="FUNCTION",
            ownership_scope="all",
            after=after,
            limit=1,
        )
        self.assertEqual(len(second.items), 1)
        self.assertGreater(pm.entity_sort_key(second.items[0]), after)

    def test_generic_continuation_skips_completed_class_domain(self):
        provider = pu_program_model.DexProgramProvider(
            self.job,
            self.workspace,
            {"androguard": True},
        )
        function_after = ("FUNCTION", "", "", "")
        with mock.patch.object(
            provider,
            "_class_entity",
            side_effect=AssertionError("completed class domain must be skipped"),
        ):
            page = provider.query_entities(
                ownership_scope="all",
                after=function_after,
                limit=10,
            )
        self.assertTrue(page.items)
        self.assertTrue(
            all(pm.entity_sort_key(item) > function_after for item in page.items)
        )


if __name__ == "__main__":
    unittest.main()
