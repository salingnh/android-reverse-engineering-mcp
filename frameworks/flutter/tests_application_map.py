from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import application_map as amap
import flutter_program_model as fpm
import flutter_semantic as semantic
import program_model as pm


class FlutterApplicationMapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.index = Path(self.tmp.name) / "flutter-index.sqlite"
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
                        semantic._json(value)
                        if not isinstance(value, str)
                        else value,
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
                    ("class-core", "lib-core", "Object", 2, 32, "class Object", "asm/core.dart", 2),
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
                        3,
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
                    5,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def tearDown(self):
        self.tmp.cleanup()

    def provider(self):
        return fpm.FlutterProgramProvider(self.index)

    def test_map_retains_dart_platform_boundary_and_xref_semantics(self):
        result = amap.ApplicationMapProjector(
            pm.ProgramRepository((self.provider(),))
        ).get_application_map(node_limit=20, edge_limit=20)
        self.assertIn(
            "package:myapp/main.dart::AuthService::login",
            [item["display_name"] for item in result["nodes"]],
        )
        boundaries = [item for item in result["nodes"] if item["kind"] == "EXTERNAL_BOUNDARY"]
        self.assertEqual(len(boundaries), 1)
        self.assertEqual(boundaries[0]["ownership"], "PLATFORM")
        self.assertIn("XREF", [item["kind"] for item in result["edges"]])
        self.assertNotIn("CALLS", [item["kind"] for item in result["edges"]])

    def test_expand_boundary_after_provider_reconstruction(self):
        first = amap.ApplicationMapProjector(
            pm.ProgramRepository((self.provider(),))
        ).get_application_map(node_limit=20, edge_limit=20)
        boundary_id = next(
            item["entity_id"]
            for item in first["nodes"]
            if item["kind"] == "EXTERNAL_BOUNDARY"
        )
        second = amap.ApplicationMapProjector(
            pm.ProgramRepository((self.provider(),))
        ).expand_application_node(
            entity_id=boundary_id,
            node_limit=20,
            edge_limit=20,
        )
        self.assertEqual(second["root_entity_id"], boundary_id)
        self.assertIn("XREF", [item["kind"] for item in second["edges"]])


if __name__ == "__main__":
    unittest.main()
