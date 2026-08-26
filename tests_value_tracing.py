from __future__ import annotations

import unittest

import flow_ir as flow
import program_model as pm
import value_tracing as tracing


class ValueTracingQueryTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = pm.ProgramSnapshot("1" * 64).snapshot_id
        self.owner = "pm:v1:function:root"

    def node(self, key, kind="LOCAL", *, owner=None, properties=None):
        owner = owner or self.owner
        semantic_key = (
            flow.constant_semantic_key(key)
            if kind == "CONSTANT"
            else key
        )
        return flow.FlowNode(
            self.snapshot,
            flow.flow_node_id(self.snapshot, kind, owner, semantic_key),
            semantic_key,
            kind,
            owner,
            "dex",
            properties=properties or {},
        )

    def edge(self, kind, source, target, discriminator):
        props = {}
        if kind == "FLOWS_TO":
            props = {"flow_kind": "fixture"}
        return flow.FlowEdge(
            self.snapshot,
            flow.flow_edge_id(
                self.snapshot, kind, source.node_id, target.node_id, discriminator
            ),
            kind,
            source.node_id,
            target.node_id,
            "dex",
            "fixture",
            discriminator,
            props,
        )

    def test_trace_parameter_forward_is_bounded_and_semantic(self):
        parameter = self.node(
            "parameter:0",
            "PARAMETER",
            properties={"parameter_index": 0, "type": "Ljava/lang/String;"},
        )
        local = self.node("local:1")
        returned = self.node("return:root", "RETURN")
        e1 = self.edge("FLOWS_TO", parameter, local, "one")
        e2 = self.edge("FLOWS_TO", local, returned, "two")
        document = flow.FlowDocument(
            self.snapshot,
            nodes=(parameter, local, returned),
            edges=(e1, e2),
        )
        result = tracing.trace_value(
            document,
            owner_entity_id=self.owner,
            selector={"kind": "parameter", "index": 0},
            direction="forward",
            max_depth=1,
            max_nodes=10,
        )
        self.assertEqual(result["seed_node_ids"], [parameter.node_id])
        self.assertEqual(result["flow"]["counts"]["nodes"], 2)
        self.assertEqual(result["flow"]["counts"]["edges"], 1)
        self.assertNotIn(returned.node_id, {item["node_id"] for item in result["flow"]["nodes"]})

    def test_source_to_sink_never_traverses_gap(self):
        source = self.node(
            "parameter:0",
            "PARAMETER",
            properties={"parameter_index": 0},
        )
        boundary = self.node("local:boundary")
        sink = self.node("return:root", "RETURN")
        first = self.edge("FLOWS_TO", source, boundary, "first")
        gap = flow.FlowGap(
            self.snapshot,
            flow.flow_gap_id(
                self.snapshot,
                "EXTERNAL_BOUNDARY",
                self.owner,
                boundary.node_id,
                sink.node_id,
                "external",
            ),
            "EXTERNAL_BOUNDARY",
            self.owner,
            "dex",
            "fixture",
            boundary.node_id,
            sink.node_id,
            "external",
            "third-party body not analyzed",
        )
        document = flow.FlowDocument(
            self.snapshot,
            nodes=(source, boundary, sink),
            edges=(first,),
            gaps=(gap,),
        )
        result = tracing.find_source_to_sink(
            document,
            owner_entity_id=self.owner,
            source_selector={"kind": "parameter", "index": 0},
            sink_selector={"kind": "return"},
        )
        self.assertEqual(result["complete_path_count"], 0)
        self.assertEqual(result["flow"]["counts"]["paths"], 0)
        self.assertEqual(result["flow"]["counts"]["gaps"], 1)

    def test_complete_source_to_sink_path_contains_edges_only(self):
        source = self.node(
            "parameter:0",
            "PARAMETER",
            properties={"parameter_index": 0},
        )
        middle = self.node("local:middle")
        sink = self.node("return:root", "RETURN")
        e1 = self.edge("ASSIGNMENT", source, middle, "move")
        e2 = self.edge("FLOWS_TO", middle, sink, "return")
        document = flow.FlowDocument(
            self.snapshot,
            nodes=(source, middle, sink),
            edges=(e1, e2),
        )
        result = tracing.find_source_to_sink(
            document,
            owner_entity_id=self.owner,
            source_selector={"kind": "parameter", "index": 0},
            sink_selector={"kind": "return"},
        )
        self.assertEqual(result["complete_path_count"], 1)
        path = result["flow"]["paths"][0]
        self.assertTrue(path["complete"])
        self.assertEqual(path["segment_ids"], [e1.edge_id, e2.edge_id])

    def test_public_selectors_do_not_accept_private_registers(self):
        node = self.node("local:any")
        document = flow.FlowDocument(self.snapshot, nodes=(node,))
        with self.assertRaisesRegex(tracing.ValueTracingError, "unsupported selector"):
            tracing.trace_value(
                document,
                owner_entity_id=self.owner,
                selector={"kind": "register", "register": 7},
            )

    def test_node_selector_can_continue_from_prior_flow_node(self):
        source = self.node("local:source")
        sink = self.node("local:sink")
        edge = self.edge("ASSIGNMENT", source, sink, "assignment")
        document = flow.FlowDocument(self.snapshot, nodes=(source, sink), edges=(edge,))
        result = tracing.trace_value(
            document,
            owner_entity_id=self.owner,
            selector={"kind": "node", "node_id": source.node_id},
            direction="forward",
        )
        self.assertEqual(result["flow"]["counts"]["edges"], 1)

    def test_limits_fail_closed(self):
        node = self.node("local:any")
        document = flow.FlowDocument(self.snapshot, nodes=(node,))
        with self.assertRaises(tracing.ValueTracingError):
            tracing.trace_value(
                document,
                owner_entity_id=self.owner,
                selector={"kind": "node", "node_id": node.node_id},
                max_nodes=501,
            )
        with self.assertRaises(tracing.ValueTracingError):
            tracing.find_source_to_sink(
                document,
                owner_entity_id=self.owner,
                source_selector={"kind": "node", "node_id": node.node_id},
                sink_selector={"kind": "node", "node_id": node.node_id},
                max_paths=101,
            )

    def test_descriptor_keeps_structural_topology_out_of_flow(self):
        descriptor = tracing.descriptor()
        self.assertEqual(descriptor["flow_ir_version"], flow.FLOW_IR_VERSION)
        self.assertFalse(descriptor["calls_xref_are_data_flow"])
        self.assertFalse(descriptor["gaps_are_traversable"])


if __name__ == "__main__":
    unittest.main()
