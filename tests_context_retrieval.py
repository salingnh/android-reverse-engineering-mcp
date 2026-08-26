from __future__ import annotations

import json
import unittest

import context_retrieval as context
import program_model as pm
from ownership_contract import ownership_scope_accepts, validate_ownership_scope


class FakeProvider:
    def __init__(self, entities, relationships, evidence=None):
        self._snapshot = pm.ProgramSnapshot("a" * 64, "apk")
        self.entities = {item.entity_id: item for item in entities}
        self.relationships = list(relationships)
        self.evidence = dict(evidence or {})

    @property
    def snapshot(self):
        return self._snapshot

    def get_entity(self, entity_id):
        return self.entities.get(entity_id)

    def query_entities(
        self,
        *,
        kind=None,
        text=None,
        ownership_scope="application",
        representation=None,
        after=None,
        limit=pm.MAX_PAGE_SIZE,
    ):
        scope = validate_ownership_scope(ownership_scope)
        needle = str(text or "").lower()
        items = []
        for item in self.entities.values():
            if kind and item.kind != kind:
                continue
            if representation and item.representation != representation:
                continue
            if not ownership_scope_accepts(item.ownership, scope):
                continue
            if needle and needle not in (item.display_name + " " + item.semantic_key).lower():
                continue
            if after is not None and pm.entity_sort_key(item) <= after:
                continue
            items.append(item)
        items.sort(key=pm.entity_sort_key)
        return pm.ProviderPage(tuple(items[:limit]), has_more=len(items) > limit)

    def query_relationships(
        self,
        *,
        entity_id,
        kinds=None,
        direction="both",
        ownership_scope="application",
        after=None,
        limit=pm.MAX_PAGE_SIZE,
    ):
        items = []
        for item in self.relationships:
            if kinds and item.kind not in kinds:
                continue
            if direction == "incoming" and item.target_entity_id != entity_id:
                continue
            if direction == "outgoing" and item.source_entity_id != entity_id:
                continue
            if direction == "both" and entity_id not in {
                item.source_entity_id,
                item.target_entity_id,
            }:
                continue
            if after is not None and pm.relationship_sort_key(item) <= after:
                continue
            items.append(item)
        items.sort(key=pm.relationship_sort_key)
        return pm.ProviderPage(tuple(items[:limit]), has_more=len(items) > limit)

    def get_evidence(self, evidence_ref):
        return self.evidence.get(evidence_ref)


class FakeSourceProvider:
    def __init__(self, *, text="line 1\nline 2", truncated=False):
        self.text = text
        self.truncated = truncated

    def source_slice(self, *, entity, evidence, line_limit, byte_limit):
        encoded = self.text.encode("utf-8")[:byte_limit]
        text = encoded.decode("utf-8", "ignore")
        return {
            "entity_id": entity.entity_id,
            "source_kind": "fixture-source",
            "representation": entity.representation,
            "source_file": "fixture/Test.java",
            "start_line": 1,
            "end_line": min(line_limit, max(1, text.count("\n") + 1)),
            "returned_lines": min(line_limit, max(1, text.count("\n") + 1)),
            "truncated": self.truncated or len(encoded) < len(self.text.encode("utf-8")),
            "canonical_truth": False,
            "text": text,
        }


def entity(snapshot, kind, key, name, ownership="FIRST_PARTY", evidence_refs=(), properties=None):
    return pm.ProgramEntity(
        snapshot.snapshot_id,
        pm.entity_id(snapshot, kind, key),
        key,
        kind,
        name,
        "dex",
        ownership,
        properties or {},
        evidence_refs,
    )


def relationship(snapshot, kind, source_id, target_id, discriminator="", evidence_refs=()):
    return pm.ProgramRelationship(
        snapshot.snapshot_id,
        pm.relationship_id(snapshot, kind, source_id, target_id, discriminator),
        kind,
        source_id,
        target_id,
        "dex",
        {},
        evidence_refs,
    )


class ContextRetrievalContractTests(unittest.TestCase):
    def fixture(self, *, reverse=False):
        snapshot = pm.ProgramSnapshot("a" * 64, "apk")
        root_evidence = "pme:v1:fixture-root"
        app = entity(snapshot, "APPLICATION", "application:v1", "com.example")
        clazz = entity(
            snapshot,
            "CLASS",
            "class:v1:dex:com.example.AuthService",
            "com.example.AuthService",
            properties={"qualified_name": "com.example.AuthService"},
        )
        root = entity(
            snapshot,
            "FUNCTION",
            "function:v1:dex:auth-login",
            "com.example.AuthService.login",
            evidence_refs=(root_evidence,),
            properties={"signature": "()V", "implementation": "present"},
        )
        neighbor = entity(
            snapshot,
            "FUNCTION",
            "function:v1:dex:token",
            "com.example.TokenService.issue",
            properties={"signature": "()V", "implementation": "present"},
        )
        boundary = entity(
            snapshot,
            "EXTERNAL_BOUNDARY",
            "boundary:v1:third-party-sdk:firebase",
            "Firebase",
            ownership="THIRD_PARTY",
            properties={"boundary_kind": "third-party-sdk", "sdk": "Firebase", "target": "FirebaseAuth"},
        )
        rels = [
            relationship(snapshot, "DECLARES", app.entity_id, clazz.entity_id, "app-class"),
            relationship(snapshot, "DECLARES", clazz.entity_id, root.entity_id, "class-fn"),
            relationship(snapshot, "CALLS", root.entity_id, neighbor.entity_id, "call"),
            relationship(snapshot, "CALLS_EXTERNAL", root.entity_id, boundary.entity_id, "external"),
        ]
        entities = [app, clazz, root, neighbor, boundary]
        if reverse:
            entities.reverse()
            rels.reverse()
        evidence = {
            root_evidence: {
                "schema_version": 2,
                "analysis_id": "fixture",
                "artifact_sha256": "a" * 64,
                "analyzer": {"name": "fixture", "version": "1"},
                "state": "derived",
                "location": {"kind": "source-declaration", "source_file": "fixture/Test.java", "line": 10},
                "limitations": [],
            }
        }
        return snapshot, entities, rels, app, clazz, root, neighbor, boundary, evidence

    def retriever(self, *, reverse=False, source=True):
        _, entities, rels, *_, evidence = self.fixture(reverse=reverse)
        provider = FakeProvider(entities, rels, evidence)
        return context.ContextRetriever(
            pm.ProgramRepository((provider,)),
            FakeSourceProvider() if source else None,
        )

    def test_retrieval_is_deterministic_and_re_resolves_function(self):
        *_, root, _, _, _ = self.fixture()[2:]
        first = self.retriever().get_function_context(entity_id=root.entity_id)
        second = self.retriever(reverse=True).get_function_context(entity_id=root.entity_id)
        self.assertEqual(first, second)
        self.assertEqual(first["root"]["entity_id"], root.entity_id)
        self.assertTrue(any(item["kind"] == "CLASS" for item in first["structural_context"]["entities"]))
        self.assertEqual(first["source_slices"][0]["canonical_truth"], False)

    def test_non_function_and_default_external_function_roots_are_rejected(self):
        snapshot, entities, rels, _, clazz, root, *_rest, evidence = self.fixture()
        retriever = context.ContextRetriever(pm.ProgramRepository((FakeProvider(entities, rels, evidence),)))
        with self.assertRaises(context.ContextRetrievalError):
            retriever.get_function_context(entity_id=clazz.entity_id)
        external = entity(
            snapshot,
            "FUNCTION",
            "function:v1:dex:third-party",
            "com.vendor.Sdk.run",
            ownership="THIRD_PARTY",
            properties={"signature": "()V", "implementation": "external"},
        )
        explicit = context.ContextRetriever(
            pm.ProgramRepository((FakeProvider([*entities, external], rels, evidence),))
        )
        with self.assertRaises(context.ContextRetrievalError):
            explicit.get_function_context(entity_id=external.entity_id)
        allowed = explicit.get_function_context(
            entity_id=external.entity_id,
            ownership_scope="third_party",
        )
        self.assertEqual(allowed["root"]["entity_id"], external.entity_id)
        self.assertEqual(root.kind, "FUNCTION")

    def test_xref_and_calls_are_never_promoted_to_data_flow(self):
        snapshot, entities, _, _, _, root, neighbor, *_rest, evidence = self.fixture()
        rels = [
            relationship(snapshot, "XREF", root.entity_id, neighbor.entity_id, "xref"),
            relationship(snapshot, "CALLS", root.entity_id, neighbor.entity_id, "call"),
        ]
        result = context.ContextRetriever(
            pm.ProgramRepository((FakeProvider(entities, rels, evidence),))
        ).get_function_context(entity_id=root.entity_id)
        self.assertEqual({item["kind"] for item in result["relationships"]}, {"CALLS", "XREF"})
        self.assertTrue(all(item["data_flow_claim"] is False for item in result["relationships"]))

    def test_relationship_pagination_has_no_skip_or_duplicate(self):
        snapshot = pm.ProgramSnapshot("a" * 64, "apk")
        root = entity(
            snapshot,
            "FUNCTION",
            "function:v1:dex:root",
            "com.example.Root.run",
            properties={"signature": "()V", "implementation": "present"},
        )
        neighbors = [
            entity(
                snapshot,
                "FUNCTION",
                f"function:v1:dex:n-{index}",
                f"com.example.N{index}.run",
                properties={"signature": "()V", "implementation": "present"},
            )
            for index in range(7)
        ]
        rels = [
            relationship(snapshot, "CALLS", root.entity_id, item.entity_id, str(index))
            for index, item in enumerate(neighbors)
        ]
        retriever = context.ContextRetriever(pm.ProgramRepository((FakeProvider([root, *neighbors], rels),)))
        seen = []
        cursor = None
        for _ in range(10):
            page = retriever.get_function_context(
                entity_id=root.entity_id,
                relationship_limit=2,
                cursor=cursor,
            )
            seen.extend(item["relationship_id"] for item in page["relationships"])
            if not page["has_more"]:
                break
            self.assertIsNotNone(page["cursor"])
            cursor = page["cursor"]
        expected = [item.relationship_id for item in sorted(rels, key=pm.relationship_sort_key)]
        self.assertEqual(seen, expected)
        self.assertEqual(len(seen), len(set(seen)))

    def test_unresolved_endpoint_relationship_is_still_represented(self):
        snapshot = pm.ProgramSnapshot("a" * 64, "apk")
        root = entity(
            snapshot,
            "FUNCTION",
            "function:v1:dex:root-unresolved",
            "com.example.Root.unresolved",
            properties={"signature": "()V", "implementation": "present"},
        )
        missing_id = pm.entity_id(snapshot, "FUNCTION", "function:v1:dex:missing")
        rel = relationship(snapshot, "XREF", root.entity_id, missing_id, "unresolved")
        result = context.ContextRetriever(
            pm.ProgramRepository((FakeProvider([root], [rel]),))
        ).get_function_context(entity_id=root.entity_id)
        self.assertEqual([item["relationship_id"] for item in result["relationships"]], [rel.relationship_id])
        self.assertEqual(result["neighbors"], [])
        self.assertIn("unresolved_relationship_endpoint", result["warnings"])

    def test_response_budget_retry_keeps_cursor_aligned(self):
        snapshot = pm.ProgramSnapshot("a" * 64, "apk")
        root = entity(
            snapshot,
            "FUNCTION",
            "function:v1:dex:large-root",
            "com.example.LargeRoot.run",
            properties={"signature": "()V", "implementation": "present"},
        )
        neighbors = [
            entity(
                snapshot,
                "FUNCTION",
                f"function:v1:dex:large-{index}",
                f"com.example.Big{index}." + ("x" * 1700),
                properties={"signature": "()V", "implementation": "present"},
            )
            for index in range(20)
        ]
        rels = [
            relationship(snapshot, "CALLS", root.entity_id, item.entity_id, str(index))
            for index, item in enumerate(neighbors)
        ]
        retriever = context.ContextRetriever(pm.ProgramRepository((FakeProvider([root, *neighbors], rels),)))
        seen = []
        cursor = None
        for _ in range(10):
            page = retriever.get_function_context(
                entity_id=root.entity_id,
                relationship_limit=20,
                response_budget_bytes=context.MIN_RESPONSE_BUDGET_BYTES,
                cursor=cursor,
            )
            encoded = json.dumps(page, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self.assertLessEqual(len(encoded), context.MIN_RESPONSE_BUDGET_BYTES)
            self.assertEqual(page["serialized_bytes"], len(encoded))
            seen.extend(item["relationship_id"] for item in page["relationships"])
            if not page["has_more"]:
                break
            self.assertIsNotNone(page["cursor"])
            cursor = page["cursor"]
        expected = [item.relationship_id for item in sorted(rels, key=pm.relationship_sort_key)]
        self.assertEqual(seen, expected)
        self.assertEqual(len(seen), len(set(seen)))

    def test_normal_and_hard_response_bounds_are_explicit(self):
        _, _, _, _, _, root, *_ = self.fixture()
        normal = self.retriever().get_function_context(entity_id=root.entity_id)
        encoded = json.dumps(normal, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.assertLessEqual(len(encoded), context.DEFAULT_RESPONSE_BUDGET_BYTES)
        self.assertEqual(normal["serialized_bytes"], len(encoded))
        hard = self.retriever(source=False).get_function_context(
            entity_id=root.entity_id,
            response_budget_bytes=context.MAX_RESPONSE_BUDGET_BYTES,
        )
        hard_encoded = json.dumps(hard, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.assertLessEqual(len(hard_encoded), context.MAX_RESPONSE_BUDGET_BYTES)
        self.assertEqual(hard["serialized_bytes"], len(hard_encoded))

    def test_source_truncation_is_structured_not_character_cut_json(self):
        _, entities, rels, _, _, root, *_rest, evidence = self.fixture()
        retriever = context.ContextRetriever(
            pm.ProgramRepository((FakeProvider(entities, rels, evidence),)),
            FakeSourceProvider(text="z" * 20000, truncated=True),
        )
        result = retriever.get_function_context(
            entity_id=root.entity_id,
            source_byte_limit=1024,
        )
        self.assertTrue(result["source_slices"][0]["truncated"])
        self.assertIn("source_slice_truncated", result["warnings"])
        self.assertTrue(result["truncated"])


if __name__ == "__main__":
    unittest.main()
