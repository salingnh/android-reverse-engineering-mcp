from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import context_retrieval as context
import flutter_context_retrieval as flutter_context
import flutter_program_model as fpm
import flutter_semantic as semantic
import program_model as pm


class FlutterContextRetrievalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.output = Path(self.tmp.name) / "analysis"
        self.output.mkdir()
        self.source = self.output / "asm" / "main.dart"
        self.source.parent.mkdir()
        self.source.write_text(
            "library main;\n"
            "class AuthService {\n"
            "  void login() {\n"
            "    print('login');\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )
        core_source = self.output / "asm" / "core.dart"
        core_source.write_text("class Object { String toString() => ''; }\n", encoding="utf-8")
        self.index = self.output / "flutter-index.sqlite"
        conn = semantic._open_db(self.index, writable=True)
        try:
            semantic._init_db(conn)
            metadata = {
                "schema_version": semantic.INDEX_SCHEMA_VERSION,
                "analysis_id": "flutter-aot:" + "b" * 64,
                "artifact_sha256": "b" * 64,
                "artifact_kind": "libapp.so",
                "analyzer": "blutter-semantic-index",
                "blutter_commit": "c" * 40,
                "runtime": {},
                "image_version": "0.3.1",
                "build_commit": "d" * 40,
                "scan_bytes": 100,
                "limits": {},
                "counts": {},
            }
            for key, value in metadata.items():
                conn.execute(
                    "INSERT INTO metadata(key,value) VALUES (?,?)",
                    (
                        key,
                        semantic._json(value) if not isinstance(value, str) else value,
                    ),
                )
            conn.executemany(
                "INSERT INTO libraries(id,name,url,source_file,line) VALUES (?,?,?,?,?)",
                [
                    ("lib-app", "main", "package:myapp/main.dart", "asm/main.dart", 1),
                    ("lib-core", "core", "dart:core", "asm/core.dart", 1),
                ],
            )
            conn.executemany(
                "INSERT INTO classes(id,library_id,name,class_id,size,declaration,source_file,line) VALUES (?,?,?,?,?,?,?,?)",
                [
                    ("class-app", "lib-app", "AuthService", 1, 32, "class AuthService", "asm/main.dart", 2),
                    ("class-core", "lib-core", "Object", 2, 32, "class Object", "asm/core.dart", 1),
                ],
            )
            conn.executemany(
                "INSERT INTO functions(id,library_id,class_id_ref,library_url,class_name,name,signature,native_offset,size,source_file,line) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        "dartfn-private-main",
                        "lib-app",
                        "class-app",
                        "package:myapp/main.dart",
                        "AuthService",
                        "login",
                        "void login() {",
                        4096,
                        64,
                        "asm/main.dart",
                        3,
                    ),
                    (
                        "dartfn-private-core",
                        "lib-core",
                        "class-core",
                        "dart:core",
                        "Object",
                        "toString",
                        "String toString() {",
                        8192,
                        48,
                        "asm/core.dart",
                        1,
                    ),
                ],
            )
            conn.execute(
                "INSERT INTO xrefs(caller_id,target_library_url,target_class_name,target_name,target_id,source_file,line) VALUES (?,?,?,?,?,?,?)",
                (
                    "dartfn-private-main",
                    "dart:core",
                    "Object",
                    "toString",
                    "dartfn-private-core",
                    "asm/main.dart",
                    4,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def tearDown(self):
        self.tmp.cleanup()

    def repository(self):
        return pm.ProgramRepository((fpm.FlutterProgramProvider(self.index),))

    def login_entity(self, repo):
        page = repo.find_entities(
            kind="FUNCTION",
            text="AuthService::login",
            ownership_scope="application",
            limit=10,
        )
        return next(item for item in page.items if item.display_name.endswith("::login"))

    def test_context_uses_exact_flutter_source_evidence_and_keeps_xref(self):
        repo = self.repository()
        login = self.login_entity(repo)
        result = context.ContextRetriever(
            repo,
            flutter_context.FlutterContextSourceProvider(self.output),
        ).get_function_context(entity_id=login.entity_id)
        self.assertEqual(result["root"]["entity_id"], login.entity_id)
        self.assertEqual(len(result["source_slices"]), 1)
        source = result["source_slices"][0]
        self.assertEqual(source["source_file"], "asm/main.dart")
        self.assertEqual(source["canonical_truth"], False)
        self.assertIn("login", source["text"])
        self.assertIn("XREF", [item["kind"] for item in result["relationships"]])
        self.assertNotIn("CALLS", [item["kind"] for item in result["relationships"]])
        self.assertTrue(all(item["data_flow_claim"] is False for item in result["relationships"]))

    def test_source_provider_rejects_escape_and_symlink(self):
        repo = self.repository()
        login = self.login_entity(repo)
        provider = flutter_context.FlutterContextSourceProvider(self.output)
        self.assertIsNone(provider._safe_file("../../outside.dart"))

        outside = Path(self.tmp.name) / "outside.dart"
        outside.write_text("void login() {}", encoding="utf-8")
        self.source.unlink()
        self.source.symlink_to(outside)
        evidence = repo.get_evidence(login.evidence_refs)
        self.assertIsNone(
            provider.source_slice(
                entity=login,
                evidence=evidence,
                line_limit=20,
                byte_limit=4096,
            )
        )

    def test_source_provider_enforces_line_byte_and_file_size_bounds(self):
        repo = self.repository()
        login = self.login_entity(repo)
        provider = flutter_context.FlutterContextSourceProvider(self.output)
        evidence = repo.get_evidence(login.evidence_refs)

        source = provider.source_slice(
            entity=login,
            evidence=evidence,
            line_limit=2,
            byte_limit=24,
        )
        self.assertIsNotNone(source)
        self.assertLessEqual(source["returned_lines"], 2)
        self.assertLessEqual(len(source["text"].encode("utf-8")), 24)
        self.assertTrue(source["truncated"])

        self.source.write_bytes(b"x" * (flutter_context.MAX_CONTEXT_SOURCE_FILE_BYTES + 1))
        self.assertIsNone(
            provider.source_slice(
                entity=login,
                evidence=evidence,
                line_limit=20,
                byte_limit=4096,
            )
        )


if __name__ == "__main__":
    unittest.main()
