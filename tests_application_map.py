from __future__ import annotations

import json
import unittest

import application_map as amap
import program_model as pm
from ownership_contract import ownership_scope_accepts, validate_ownership_scope


class FakeProvider:
    def __init__(self, entities, relationships):
        self._snapshot = pm.ProgramSnapshot("a" * 64, "apk")
        self.entities = {item.entity_id: item for item in entities}
        self.relationships = list(relationships)

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
        return None


def entity(snapshot, kind, key, name, ownership="FIRST_PARTY", properties=None):
    return pm.ProgramEntity(
        snapshot.snapshot_id,
        pm.entity_id(snapshot, kind, key),
        key,
        kind,
        name,
        "dex",
        ownership,
        properties or {},
        (),
    )


def relationship(snapshot, kind, source, target, discriminator=""):
    return pm.ProgramRelationship(
        snapshot.snapshot_id,
        pm.relationship_id(
            snapshot,
            kind,
            source.entity_id,
            target.entity_id,
            discriminator,
        ),
        kind,
        source.entity_id,
        target.entity_id,
        "dex",
        {},
        (),
    )


class ApplicationMapContractTests(unittest.TestCase):
    def fixture(self, reverse=False, noise=0):
        snapshot = pm.ProgramSnapshot("a" * 64, "apk")
        app = entity(snapshot, "APPLICATION", "application:v1", "com.example")
        clazz = entity(
            snapshot,
            "CLASS",
            "class:v1:dex:com.example.AuthService",
            "com.example.AuthService",
            properties={"qualified_name": "com.example.AuthService"},
        )
        login = entity(
            snapshot,
            "FUNCTION",
            "function:v1:dex:login",
            "com.example.AuthService.login",
            properties={"signature": "()V", "implementation": "present"},
        )
        boundary = entity(
            snapshot,
            "EXTERNAL_BOUNDARY",
            "boundary:v1:third-party-sdk:firebase-auth",
            "Firebase Auth",
            ownership="THIRD_PARTY",
            properties={
                "boundary_kind": "third-party-sdk",
                "owner": "Google",
                "sdk": "Firebase",
                "target": "com.google.firebase.auth.Auth.signIn",
            },
        )
        entities = [app, clazz, login, boundary]
        for index in range(noise):
            entities.append(
                entity(
                    snapshot,
                    "FUNCTION",
                    f"function:v1:dex:sdk-noise-{index:04d}",
                    f"com.google.sdk.Noise{index}.run",
                    ownership="THIRD_PARTY",
                    properties={"signature": "()V", "implementation": "external"},
                )
            )
        relations = [
            relationship(snapshot, "DECLARES", app, clazz),
            relationship(snapshot, "DECLARES", clazz, login),
            pm.ProgramRelationship(
                snapshot.snapshot_id,
                pm.relationship_id(
                    snapshot,
                    "CALLS_EXTERNAL",
                    login.entity_id,
                    boundary.entity_id,
                    "12",
                ),
                "CALLS_EXTERNAL",
                login.entity_id,
                boundary.entity_id,
                "dex",
                {"callsite_offset": 12, "boundary_kind": "third-party-sdk"},
                (),
            ),
        ]
        if reverse:
            entities.reverse()
            relations.reverse()
        return snapshot, entities, relations, app, clazz, login, boundary

    def test_projection_is_deterministic_and_retains_external_boundary(self):
        _, entities, relations, _, _, login, boundary = self.fixture(noise=500)
        first = amap.ApplicationMapProjector(
            pm.ProgramRepository((FakeProvider(entities, relations),))
        ).get_application_map(node_limit=20, edge_limit=30)
        _, reverse_entities, reverse_relations, *_ = self.fixture(
            reverse=True, noise=500
        )
        second = amap.ApplicationMapProjector(
            pm.ProgramRepository((FakeProvider(reverse_entities, reverse_relations),))
        ).get_application_map(node_limit=20, edge_limit=30)
        self.assertEqual(first, second)
        ids = {item["entity_id"] for item in first["nodes"]}
        self.assertIn(login.entity_id, ids)
        self.assertIn(boundary.entity_id, ids)
        self.assertTrue(
            any(item["kind"] == "CALLS_EXTERNAL" for item in first["edges"])
        )
        self.assertFalse(
            any("com.google.sdk.Noise" in item["display_name"] for item in first["nodes"])
        )

    def test_expansion_re_resolves_entity_after_provider_reconstruction(self):
        _, entities, relations, _, _, login, boundary = self.fixture()
        first_provider = FakeProvider(entities, relations)
        projected = amap.ApplicationMapProjector(
            pm.ProgramRepository((first_provider,))
        ).get_application_map()
        self.assertIn(boundary.entity_id, {item["entity_id"] for item in projected["nodes"]})

        # New provider/repository instance: no prior projector/process state is reused.
        second_provider = FakeProvider(list(entities), list(relations))
        expanded = amap.ApplicationMapProjector(
            pm.ProgramRepository((second_provider,))
        ).expand_application_node(entity_id=login.entity_id)
        self.assertEqual(expanded["root_entity_id"], login.entity_id)
        self.assertIn(boundary.entity_id, {item["entity_id"] for item in expanded["nodes"]})

    def test_xref_is_never_promoted(self):
        snapshot, entities, _, app, _, login, boundary = self.fixture()
        xref = relationship(snapshot, "XREF", login, boundary, "xref")
        declares = relationship(snapshot, "DECLARES", app, login)
        result = amap.ApplicationMapProjector(
            pm.ProgramRepository((FakeProvider(entities, [declares, xref]),))
        ).get_application_map(node_limit=20, edge_limit=20)
        kinds = [item["kind"] for item in result["edges"]]
        self.assertIn("XREF", kinds)
        self.assertNotIn("CALLS", kinds)
        self.assertNotIn("FLOWS_TO", kinds)

    def test_final_serialized_response_never_exceeds_hard_bound(self):
        snapshot = pm.ProgramSnapshot("a" * 64, "apk")
        app = entity(snapshot, "APPLICATION", "application:v1", "app")
        entities = [app]
        for index in range(100):
            name = f"com.example.C{index}." + ("x" * 1900)
            entities.append(
                entity(
                    snapshot,
                    "CLASS",
                    f"class:v1:dex:com.example.C{index}",
                    name,
                    properties={"qualified_name": name},
                )
            )
        result = amap.ApplicationMapProjector(
            pm.ProgramRepository((FakeProvider(entities, []),))
        ).get_application_map(node_limit=amap.MAX_NODE_LIMIT, edge_limit=10)
        encoded = json.dumps(
            result,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertLessEqual(len(encoded), amap.MAX_RESPONSE_BYTES)
        self.assertEqual(result["serialized_bytes"], len(encoded))
        self.assertTrue(result["truncated"])
        self.assertIn("response_size_budget_reached", result["warnings"])

    def test_projection_reuses_canonical_ids_and_creates_no_storage_contract(self):
        _, entities, relations, app, _, _, _ = self.fixture()
        result = amap.ApplicationMapProjector(
            pm.ProgramRepository((FakeProvider(entities, relations),))
        ).get_application_map()
        self.assertIn(app.entity_id, {item["entity_id"] for item in result["nodes"]})
        descriptor = amap.descriptor()
        self.assertTrue(descriptor["projection_only"])
        self.assertFalse(descriptor["persistent_map_storage"])
        self.assertTrue(descriptor["canonical_entity_ids_reused"])


if __name__ == "__main__":
    unittest.main()
