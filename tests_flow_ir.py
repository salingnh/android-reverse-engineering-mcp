from __future__ import annotations

import json
import unittest
from unittest import mock

import flow_ir as flow
import program_model as pm


class FlowIRTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = pm.ProgramSnapshot("a" * 64).snapshot_id
        self.owner = "pm:v1:function:owner"

    def node(
        self,
        key,
        kind="LOCAL",
        *,
        roles=(),
        label="",
        properties=None,
        snapshot=None,
    ):
        snapshot = snapshot or self.snapshot
        return flow.FlowNode(
            snapshot_id=snapshot,
            node_id=flow.flow_node_id(snapshot, kind, self.owner, key),
            semantic_key=key,
            value_kind=kind,
            owner_entity_id=self.owner,
            representation="dex",
            roles=tuple(roles),
            label=label,
            properties=properties or {},
            evidence_refs=("pme:test",),
        )

    def edge(self, source, target, kind="ASSIGNMENT", *, properties=None):
        return flow.FlowEdge(
            snapshot_id=self.snapshot,
            edge_id=flow.flow_edge_id(
                self.snapshot,
                kind,
                source.node_id,
                target.node_id,
            ),
            kind=kind,
            source_node_id=source.node_id,
            target_node_id=target.node_id,
            representation="dex",
            producer="fixture-producer",
            properties=properties or {},
            evidence_refs=("pme:edge",),
        )

    def gap(self, source, target, kind="DYNAMIC_DISPATCH"):
        return flow.FlowGap(
            snapshot_id=self.snapshot,
            gap_id=flow.flow_gap_id(
                self.snapshot,
                kind,
                self.owner,
                source.node_id,
                target.node_id,
            ),
            kind=kind,
            owner_entity_id=self.owner,
            representation="dex",
            producer="fixture-producer",
            source_node_id=source.node_id,
            target_node_id=target.node_id,
            reason="target cannot be resolved statically",
            evidence_refs=("pme:gap",),
        )

    def path(self, nodes, segments, *, complete):
        node_ids = tuple(item.node_id for item in nodes)
        segment_ids = tuple(
            item.edge_id if isinstance(item, flow.FlowEdge) else item.gap_id
            for item in segments
        )
        return flow.FlowPath(
            snapshot_id=self.snapshot,
            path_id=flow.flow_path_id(self.snapshot, node_ids, segment_ids),
            node_ids=node_ids,
            segment_ids=segment_ids,
            complete=complete,
        )

    def test_deterministic_identity_and_serialization(self):
        left = self.node("local:z")
        right = self.node("local:a", roles=("SINK", "SOURCE", "SINK"))
        edge = self.edge(right, left)
        path = self.path((right, left), (edge,), complete=True)
        first = flow.FlowDocument(
            self.snapshot,
            nodes=(left, right),
            edges=(edge,),
            paths=(path,),
        )
        second = flow.FlowDocument(
            self.snapshot,
            nodes=(right, left),
            edges=(edge,),
            paths=(path,),
        )
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(right.roles, ("SINK", "SOURCE"))
        self.assertEqual(
            json.dumps(first.to_dict(), sort_keys=True, separators=(",", ":")),
            json.dumps(second.to_dict(), sort_keys=True, separators=(",", ":")),
        )
        self.assertTrue(left.node_id.startswith("flown:v1:local:"))
        self.assertTrue(edge.edge_id.startswith("flowe:v1:assignment:"))
        self.assertTrue(path.path_id.startswith("flowp:v1:"))

    def test_node_identity_role_and_property_validation(self):
        with self.assertRaises(flow.FlowIRError):
            flow.FlowNode(
                self.snapshot,
                "flown:v1:local:not-canonical",
                "x",
                "LOCAL",
                self.owner,
                "dex",
            )
        with self.assertRaises(flow.FlowIRError):
            self.node("x", roles=("AUTH_MAGIC",))
        with self.assertRaises(flow.FlowIRError):
            self.node("x", kind="CONSTANT", properties={"raw_value": "secret"})
        with self.assertRaisesRegex(flow.FlowIRError, "constant label"):
            self.node("constant:secret", kind="CONSTANT", label="Bearer real-secret")
        with self.assertRaisesRegex(flow.FlowIRError, "value_fingerprint"):
            self.node(
                "constant:bad-fingerprint",
                kind="CONSTANT",
                properties={"value_fingerprint": "sha256:abc"},
            )
        with self.assertRaisesRegex(flow.FlowIRError, "parameter_index"):
            self.node(
                "parameter:bad-index",
                kind="PARAMETER",
                properties={"parameter_index": "0"},
            )
        constant = self.node(
            "constant:bearer",
            kind="CONSTANT",
            properties={
                "literal_kind": "string",
                "type": "java.lang.String",
                "value_fingerprint": "sha256:" + "a" * 64,
            },
        )
        self.assertNotIn("value", constant.properties)
        self.assertEqual(constant.label, "")

    def test_edge_property_types_fail_closed(self):
        left = self.node("left")
        right = self.node("right")
        with self.assertRaisesRegex(flow.FlowIRError, "statement_offset"):
            self.edge(left, right, properties={"statement_offset": -1})
        with self.assertRaisesRegex(flow.FlowIRError, "statement_offset"):
            self.edge(left, right, properties={"statement_offset": True})
        with self.assertRaisesRegex(flow.FlowIRError, "non-canonical"):
            self.edge(left, right, properties={"callsite_guess": 42})

    def test_calls_and_xref_are_not_flow_edges(self):
        left = self.node("left")
        right = self.node("right")
        for kind in ("CALLS", "XREF", "CALLS_EXTERNAL"):
            with self.subTest(kind=kind), self.assertRaises(flow.FlowIRError):
                flow.flow_edge_id(self.snapshot, kind, left.node_id, right.node_id)
        descriptor = flow.descriptor()
        self.assertFalse(descriptor["calls_xref_are_data_flow"])
        self.assertNotIn("CALLS", descriptor["edge_kinds"])
        self.assertNotIn("XREF", descriptor["edge_kinds"])

    def test_edge_endpoints_must_resolve(self):
        left = self.node("left")
        right = self.node("right")
        edge = self.edge(left, right)
        with self.assertRaisesRegex(flow.FlowIRError, "endpoint"):
            flow.FlowDocument(self.snapshot, nodes=(left,), edges=(edge,))

    def test_valid_gap_path_is_explicitly_incomplete(self):
        left = self.node("left", roles=("SOURCE",))
        right = self.node("right", roles=("SINK",))
        gap = self.gap(left, right, "REFLECTION")
        path = self.path((left, right), (gap,), complete=False)
        document = flow.FlowDocument(
            self.snapshot,
            nodes=(left, right),
            gaps=(gap,),
            paths=(path,),
        )
        self.assertEqual(document.paths[0].complete, False)
        self.assertEqual(document.gaps[0].kind, "REFLECTION")

    def test_gap_path_cannot_claim_complete(self):
        left = self.node("left")
        right = self.node("right")
        gap = self.gap(left, right)
        path = self.path((left, right), (gap,), complete=True)
        with self.assertRaisesRegex(flow.FlowIRError, "complete.*gap"):
            flow.FlowDocument(
                self.snapshot,
                nodes=(left, right),
                gaps=(gap,),
                paths=(path,),
            )

    def test_incomplete_path_requires_gap(self):
        left = self.node("left")
        right = self.node("right")
        edge = self.edge(left, right)
        path = self.path((left, right), (edge,), complete=False)
        with self.assertRaisesRegex(flow.FlowIRError, "incomplete.*gap"):
            flow.FlowDocument(
                self.snapshot,
                nodes=(left, right),
                edges=(edge,),
                paths=(path,),
            )

    def test_path_complete_is_strict_boolean(self):
        left = self.node("left")
        right = self.node("right")
        edge = self.edge(left, right)
        node_ids = (left.node_id, right.node_id)
        segment_ids = (edge.edge_id,)
        path_id = flow.flow_path_id(self.snapshot, node_ids, segment_ids)
        with self.assertRaisesRegex(flow.FlowIRError, "complete must be boolean"):
            flow.FlowPath(
                self.snapshot,
                path_id,
                node_ids,
                segment_ids,
                "false",  # type: ignore[arg-type]
            )

    def test_path_segment_must_connect_exact_adjacent_nodes(self):
        one = self.node("one")
        two = self.node("two")
        three = self.node("three")
        wrong = self.edge(one, three)
        node_ids = (one.node_id, two.node_id)
        segment_ids = (wrong.edge_id,)
        path = flow.FlowPath(
            self.snapshot,
            flow.flow_path_id(self.snapshot, node_ids, segment_ids),
            node_ids,
            segment_ids,
            True,
        )
        with self.assertRaisesRegex(flow.FlowIRError, "adjacent"):
            flow.FlowDocument(
                self.snapshot,
                nodes=(one, two, three),
                edges=(wrong,),
                paths=(path,),
            )

    def test_snapshot_mismatch_and_duplicate_ids_fail_closed(self):
        left = self.node("left")
        with self.assertRaisesRegex(flow.FlowIRError, "duplicate"):
            flow.FlowDocument(self.snapshot, nodes=(left, left))
        other = pm.ProgramSnapshot("b" * 64).snapshot_id
        foreign = self.node("foreign", snapshot=other)
        with self.assertRaisesRegex(flow.FlowIRError, "snapshot mismatch"):
            flow.FlowDocument(self.snapshot, nodes=(left, foreign))

    def test_hard_count_and_serialized_size_bounds(self):
        node = self.node("repeated")
        with self.assertRaisesRegex(flow.FlowIRError, "node count"):
            flow.FlowDocument(
                self.snapshot,
                nodes=(node,) * (flow.MAX_FLOW_NODES + 1),
            )
        one = self.node("one", label="x" * 400)
        two = self.node("two", label="y" * 400)
        with mock.patch.object(flow, "MAX_FLOW_DOCUMENT_BYTES", 512):
            with self.assertRaisesRegex(flow.FlowIRError, "serialized size"):
                flow.FlowDocument(self.snapshot, nodes=(one, two))

    def test_descriptor_is_shared_ir_not_public_operation_or_storage(self):
        descriptor = flow.descriptor()
        self.assertEqual(descriptor["flow_ir_version"], 1)
        self.assertEqual(
            descriptor["program_model_version"],
            pm.PROGRAM_MODEL_VERSION,
        )
        self.assertEqual(
            descriptor["durable_concepts"],
            ["FlowNode", "FlowEdge", "FlowPath", "FlowGap"],
        )
        self.assertFalse(descriptor["persistent_flow_storage"])
        self.assertFalse(descriptor["public_operation_added"])
        self.assertFalse(descriptor["raw_constant_values"])


if __name__ == "__main__":
    unittest.main()
