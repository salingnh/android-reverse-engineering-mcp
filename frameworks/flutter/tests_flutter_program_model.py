from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import flutter_program_model as fpm
import flutter_semantic as semantic
import program_model as pm


class FlutterProgramModelTests(unittest.TestCase):
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
                    (key, semantic._json(value) if not isinstance(value, str) else value),
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
                    ("class-app", "lib-app", "App", 1, 32, "class App", "asm/main.dart", 2),
                    ("class-core", "lib-core", "Object", 2, 32, "class Object", "asm/core.dart", 2),
                ],
            )
            conn.executemany(
                "INSERT INTO functions(id,library_id,class_id_ref,library_url,class_name,name,signature,native_offset,size,source_file,line) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                [
                    ("dartfn-private-main", "lib-app", "class-app", "package:myapp/main.dart", "App", "login", "void login() {", 4096, 64, "asm/main.dart", 3),
                    ("dartfn-private-core", "lib-core", "class-core", "dart:core", "Object", "toString", "String toString() {", 8192, 48, "asm/core.dart", 3),
                ],
            )
            conn.execute(
                "INSERT INTO xrefs(caller_id,target_library_url,target_class_name,target_name,target_id,source_file,line) VALUES (?,?,?,?,?,?,?)",
                ("dartfn-private-main", "dart:core", "Object", "toString", "dartfn-private-core", "asm/main.dart", 5),
            )
            conn.commit()
        finally:
            conn.close()

    def tearDown(self):
        self.tmp.cleanup()

    def test_default_scope_keeps_app_unknown_and_suppresses_platform(self):
        provider = fpm.FlutterProgramProvider(self.index)
        repo = pm.ProgramRepository((provider,))
        modules = repo.find_entities(kind="MODULE", limit=10)
        self.assertEqual([item.properties["uri"] for item in modules.items], ["package:myapp/main.dart"])
        functions = repo.find_entities(kind="FUNCTION", limit=10)
        self.assertEqual([item.display_name for item in functions.items], ["package:myapp/main.dart::App::login"])

    def test_flutter_xref_remains_xref_and_platform_is_boundary(self):
        provider = fpm.FlutterProgramProvider(self.index)
        repo = pm.ProgramRepository((provider,))
        fn = repo.find_entities(kind="FUNCTION", text="login", limit=10).items[0]
        relations = repo.find_relationships(entity_id=fn.entity_id, direction="outgoing", limit=20)
        xrefs = [item for item in relations.items if item.kind == "XREF"]
        self.assertEqual(len(xrefs), 1)
        self.assertNotIn("CALLS", [item.kind for item in relations.items])
        boundary = provider.get_entity(xrefs[0].target_entity_id)
        self.assertIsNotNone(boundary)
        self.assertEqual(boundary.kind, "EXTERNAL_BOUNDARY")
        self.assertEqual(boundary.ownership, "PLATFORM")

    def test_declares_hierarchy_is_application_module_class_function(self):
        provider = fpm.FlutterProgramProvider(self.index)
        repo = pm.ProgramRepository((provider,))
        app = repo.find_entities(kind="APPLICATION", limit=5).items[0]
        module_rel = repo.find_relationships(
            entity_id=app.entity_id, kinds=("DECLARES",), direction="outgoing", limit=10
        )
        self.assertEqual(len(module_rel.items), 1)
        module = provider.get_entity(module_rel.items[0].target_entity_id)
        class_rel = repo.find_relationships(
            entity_id=module.entity_id, kinds=("DECLARES",), direction="outgoing", limit=10
        )
        clazz = provider.get_entity(class_rel.items[0].target_entity_id)
        fn_rel = repo.find_relationships(
            entity_id=clazz.entity_id, kinds=("DECLARES",), direction="outgoing", limit=10
        )
        fn = provider.get_entity(fn_rel.items[0].target_entity_id)
        self.assertEqual((module.kind, clazz.kind, fn.kind), ("MODULE", "CLASS", "FUNCTION"))
        self.assertNotIn("dartfn-private-main", fn.entity_id)

    def test_same_signature_collision_uses_artifact_offset_only_when_needed(self):
        conn = semantic._open_db(self.index, writable=True)
        try:
            conn.execute(
                "INSERT INTO functions(id,library_id,class_id_ref,library_url,class_name,name,signature,native_offset,size,source_file,line) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                ("dartfn-private-main-2", "lib-app", "class-app", "package:myapp/main.dart", "App", "login", "void login() {", 4352, 64, "asm/main.dart", 9),
            )
            conn.commit()
        finally:
            conn.close()
        functions = pm.ProgramRepository((fpm.FlutterProgramProvider(self.index),)).find_entities(
            kind="FUNCTION", text="login", limit=10
        )
        self.assertEqual(len(functions.items), 2)
        self.assertEqual(len({item.entity_id for item in functions.items}), 2)
        self.assertTrue(all("@0x" in item.semantic_key for item in functions.items))


if __name__ == "__main__":
    unittest.main()
