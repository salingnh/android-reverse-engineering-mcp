from __future__ import annotations

import unittest
from dataclasses import dataclass
from typing import Iterable

import program_model as pm


@dataclass
class FakeProvider:
    snapshot: pm.ProgramSnapshot
    entities: list[pm.ProgramEntity]
    relationships: list[pm.ProgramRelationship]
    evidence: dict[str, dict]

    def get_entity(self, entity_id: str):
        return next((item for item in self.entities if item.entity_id == entity_id), None)

    def iter_entities(self, *, kind=None, text=None, ownership_scope="application", representation=None, limit=1000) -> Iterable[pm.ProgramEntity]:
        count = 0
        for item in self.entities:
            if kind and item.kind != kind:
                continue
            if representation and item.representation != representation:
                continue
            if text and text.lower() not in (item.display_name + " " + item.semantic_key).lower():
                continue
            if not pm.ownership_scope_accepts(item.ownership, ownership_scope):
                continue
            yield item
            count += 1
            if count >= limit:
                break

    def iter_relationships(self, *, entity_id, kinds=None, direction="both", ownership_scope="application", limit=1000):
        count = 0
        for item in self.relationships:
            if kinds and item.kind not in kinds:
                continue
            if direction == "incoming" and item.target_entity_id != entity_id:
                continue
            if direction == "outgoing" and item.source_entity_id != entity_id:
                continue
            if direction == "both" and entity_id not in {item.source_entity_id, item.target_entity_id}:
                continue
            yield item
            count += 1
            if count >= limit:
                break

    def get_evidence(self, evidence_ref):
        return self.evidence.get(evidence_ref)


def entity(snapshot, key, name, ownership="FIRST_PARTY", props=None):
    return pm.ProgramEntity(
        snapshot_id=snapshot.snapshot_id,
        entity_id=pm.entity_id(snapshot, "FUNCTION", key),
        semantic_key=key,
        kind="FUNCTION",
        display_name=name,
        representation="dex",
        ownership=ownership,
        properties=props or {"signature": "()V"},
        evidence_refs=("ev:1",),
    )


class ProgramModelContractTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = pm.ProgramSnapshot("a" * 64, "apk")

    def test_snapshot_identity_is_provider_independent(self):
        same = pm.ProgramSnapshot("a" * 64, "libapp.so")
        self.assertEqual(self.snapshot.snapshot_id, same.snapshot_id)
        self.assertNotIn("apk", self.snapshot.snapshot_key)

    def test_entity_id_deterministic_and_snapshot_scoped(self):
        key = "function:v1:dex:com.example.A#f()V"
        first = pm.entity_id(self.snapshot, "FUNCTION", key)
        self.assertEqual(first, pm.entity_id(self.snapshot, "FUNCTION", key))
        self.assertNotEqual(first, pm.entity_id(pm.ProgramSnapshot("b" * 64), "FUNCTION", key))

    def test_overload_identity_uses_signature(self):
        self.assertNotEqual(
            pm.entity_id(self.snapshot, "FUNCTION", "function:v1:dex:A#f()V"),
            pm.entity_id(self.snapshot, "FUNCTION", "function:v1:dex:A#f(I)V"),
        )

    def test_backend_specific_property_rejected(self):
        with self.assertRaises(pm.ProgramModelError):
            entity(self.snapshot, "function:v1:dex:A#f()V", "f", props={"sqlite_rowid": 7})

    def test_merge_duplicate_preserves_evidence(self):
        left = entity(self.snapshot, "function:v1:dex:A#f()V", "f")
        right = pm.ProgramEntity(**{**left.__dict__, "evidence_refs": ("ev:2",)})
        self.assertEqual(pm.merge_entity(left, right).evidence_refs, ("ev:1", "ev:2"))

    def test_property_conflict_does_not_last_write_win(self):
        left = entity(self.snapshot, "function:v1:dex:A#f()V", "f", props={"signature": "()V", "parameter_count": 0})
        right = entity(self.snapshot, "function:v1:dex:A#f()V", "f", props={"signature": "()V", "parameter_count": 1})
        merged = pm.merge_entity(left, right)
        self.assertEqual(merged.properties["signature"], "()V")
        self.assertNotIn("parameter_count", merged.properties)

    def test_conflicting_strong_ownership_becomes_unknown(self):
        left = entity(self.snapshot, "function:v1:dex:A#f()V", "f", "FIRST_PARTY")
        right = entity(self.snapshot, "function:v1:dex:A#f()V", "f", "THIRD_PARTY")
        self.assertEqual(pm.merge_entity(left, right).ownership, "UNKNOWN")

    def test_deterministic_pagination_independent_of_provider_order(self):
        items = [entity(self.snapshot, f"function:v1:dex:A#{name}()V", name) for name in ("z", "a", "m")]
        repo_a = pm.ProgramRepository([FakeProvider(self.snapshot, list(items), [], {})])
        repo_b = pm.ProgramRepository([FakeProvider(self.snapshot, list(reversed(items)), [], {})])
        page_a = repo_a.find_entities(kind="FUNCTION", limit=2)
        page_b = repo_b.find_entities(kind="FUNCTION", limit=2)
        self.assertEqual([x.entity_id for x in page_a.items], [x.entity_id for x in page_b.items])
        self.assertTrue(page_a.has_more)
        next_page = repo_a.find_entities(kind="FUNCTION", limit=2, cursor=page_a.cursor)
        self.assertEqual(len(next_page.items), 1)

    def test_cursor_is_query_and_snapshot_bound(self):
        items = [entity(self.snapshot, f"function:v1:dex:A#{x}()V", x) for x in ("a", "b")]
        repo = pm.ProgramRepository([FakeProvider(self.snapshot, items, [], {})])
        cursor = repo.find_entities(limit=1).cursor
        with self.assertRaises(pm.ProgramModelError):
            repo.find_entities(kind="CLASS", limit=1, cursor=cursor)
        other = pm.ProgramSnapshot("b" * 64)
        with self.assertRaises(pm.ProgramModelError):
            pm.ProgramRepository([FakeProvider(other, [], [], {})]).find_entities(limit=1, cursor=cursor)

    def test_cursor_tamper_rejected(self):
        items = [entity(self.snapshot, f"function:v1:dex:A#{x}()V", x) for x in ("a", "b")]
        repo = pm.ProgramRepository([FakeProvider(self.snapshot, items, [], {})])
        cursor = repo.find_entities(limit=1).cursor
        self.assertIsNotNone(cursor)
        tampered = cursor[:-1] + ("A" if cursor[-1] != "A" else "B")
        with self.assertRaises(pm.ProgramModelError):
            repo.find_entities(limit=1, cursor=tampered)

    def test_relationship_merge_preserves_evidence(self):
        left_entity = entity(self.snapshot, "function:v1:dex:A#a()V", "a")
        right_entity = entity(self.snapshot, "function:v1:dex:A#b()V", "b")
        rid = pm.relationship_id(self.snapshot, "CALLS", left_entity.entity_id, right_entity.entity_id)
        left = pm.ProgramRelationship(self.snapshot.snapshot_id, rid, "CALLS", left_entity.entity_id, right_entity.entity_id, "dex", {}, ("ev:1",))
        right = pm.ProgramRelationship(self.snapshot.snapshot_id, rid, "CALLS", left_entity.entity_id, right_entity.entity_id, "dex", {}, ("ev:2",))
        self.assertEqual(pm.merge_relationship(left, right).evidence_refs, ("ev:1", "ev:2"))

    def test_application_scope_is_first_party_plus_unknown(self):
        first = entity(self.snapshot, "function:v1:dex:A#a()V", "a", "FIRST_PARTY")
        unknown = entity(self.snapshot, "function:v1:dex:A#u()V", "u", "UNKNOWN")
        third = entity(self.snapshot, "function:v1:dex:A#t()V", "t", "THIRD_PARTY")
        repo = pm.ProgramRepository([FakeProvider(self.snapshot, [third, unknown, first], [], {})])
        self.assertEqual({x.ownership for x in repo.find_entities(limit=10).items}, {"FIRST_PARTY", "UNKNOWN"})

    def test_repository_rejects_mixed_snapshots(self):
        other = pm.ProgramSnapshot("b" * 64)
        with self.assertRaises(pm.ProgramModelError):
            pm.ProgramRepository([FakeProvider(self.snapshot, [], [], {}), FakeProvider(other, [], [], {})])


if __name__ == "__main__":
    unittest.main()
