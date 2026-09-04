from __future__ import annotations

import unittest

import flow_ir as flow
import program_model as pm
import security_semantics as security


class SecuritySemanticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.snapshot = pm.ProgramSnapshot("9" * 64).snapshot_id
        self.owner = "pm:v1:function:security-root"
        self.counter = 0

    def node(self, key: str, kind: str = "LOCAL", *, properties=None) -> flow.FlowNode:
        semantic_key = (
            flow.constant_semantic_key(self.owner, key)
            if kind == "CONSTANT"
            else key
        )
        return flow.FlowNode(
            self.snapshot,
            flow.flow_node_id(self.snapshot, kind, self.owner, semantic_key),
            semantic_key,
            kind,
            self.owner,
            "dex",
            properties=properties or {},
        )

    def edge(self, source: flow.FlowNode, target: flow.FlowNode, kind="FLOWS_TO") -> flow.FlowEdge:
        self.counter += 1
        discriminator = f"fixture:{self.counter}"
        properties = {"flow_kind": "security-fixture"} if kind == "FLOWS_TO" else {}
        return flow.FlowEdge(
            self.snapshot,
            flow.flow_edge_id(
                self.snapshot, kind, source.node_id, target.node_id, discriminator
            ),
            kind,
            source.node_id,
            target.node_id,
            "dex",
            "security-fixture",
            discriminator,
            properties,
        )

    def gap(self, source: flow.FlowNode, target: flow.FlowNode, kind="EXTERNAL_BOUNDARY") -> flow.FlowGap:
        self.counter += 1
        discriminator = f"gap:{self.counter}"
        return flow.FlowGap(
            self.snapshot,
            flow.flow_gap_id(
                self.snapshot,
                kind,
                self.owner,
                source.node_id,
                target.node_id,
                discriminator,
            ),
            kind,
            self.owner,
            "dex",
            "security-fixture",
            source.node_id,
            target.node_id,
            discriminator,
            "fixture boundary",
        )

    def signal(self, kind: str, anchor, *, anchor_type="FLOW_NODE", discriminator="", properties=None):
        anchor_id = (
            anchor.node_id
            if anchor_type == "FLOW_NODE"
            else anchor.edge_id
            if anchor_type == "FLOW_EDGE"
            else anchor.gap_id
        )
        return security.SecuritySignal(
            self.snapshot,
            security.security_signal_id(
                self.snapshot, kind, anchor_type, anchor_id, discriminator
            ),
            kind,
            self.owner,
            "dex",
            anchor_type,
            anchor_id,
            "fixture",
            discriminator,
            properties or {},
        )

    def test_authorization_header_requires_proven_flow(self):
        source = self.node(
            "parameter:0", "PARAMETER", properties={"parameter_index": 0}
        )
        middle = self.node("local:token")
        sink = self.node("argument:header-value", "ARGUMENT", properties={"argument_index": 1})
        document = flow.FlowDocument(
            self.snapshot,
            nodes=(source, middle, sink),
            edges=(self.edge(source, middle), self.edge(middle, sink)),
        )
        overlay = security.SecurityOverlay(
            self.snapshot,
            (self.signal("AUTHORIZATION_HEADER_SINK", sink),),
        )
        result = security.find_auth_flow(document, overlay)
        self.assertEqual(result["counts"]["findings"], 1)
        self.assertEqual(result["findings"][0]["kind"], "AUTHORIZATION_HEADER_FLOW")
        self.assertTrue(result["findings"][0]["complete"])

    def test_bearer_requires_marker_on_the_proven_path(self):
        bearer = self.node("bearer", "CONSTANT", properties={"literal_kind": "dex-constant"})
        formatted = self.node("local:formatted")
        sink = self.node("argument:auth", "ARGUMENT", properties={"argument_index": 1})
        document = flow.FlowDocument(
            self.snapshot,
            nodes=(bearer, formatted, sink),
            edges=(self.edge(bearer, formatted), self.edge(formatted, sink)),
        )
        overlay = security.SecurityOverlay(
            self.snapshot,
            (
                self.signal("BEARER_SCHEME_MARKER", bearer),
                self.signal("AUTHORIZATION_HEADER_SINK", sink),
            ),
        )
        result = security.find_auth_flow(document, overlay, focus="bearer")
        self.assertEqual(result["counts"]["findings"], 1)
        self.assertEqual(result["findings"][0]["kind"], "BEARER_AUTH_FLOW")

    def test_refresh_token_requires_source_signal_and_path_to_exchange(self):
        source = self.node("return:storage", "RETURN")
        local = self.node("local:refresh")
        sink = self.node("argument:exchange", "ARGUMENT", properties={"argument_index": 0})
        document = flow.FlowDocument(
            self.snapshot,
            nodes=(source, local, sink),
            edges=(self.edge(source, local), self.edge(local, sink)),
        )
        source_signal = self.signal("REFRESH_TOKEN_SOURCE_BOUNDARY", source)
        sink_signal = self.signal("TOKEN_EXCHANGE_SINK", sink)
        overlay = security.SecurityOverlay(self.snapshot, (source_signal, sink_signal))
        result = security.find_auth_flow(document, overlay, focus="refresh_token")
        self.assertEqual(result["counts"]["findings"], 1)
        self.assertEqual(result["findings"][0]["kind"], "REFRESH_TOKEN_EXCHANGE")
        self.assertEqual(result["findings"][0]["source_signal_ids"], [source_signal.signal_id])

    def test_api_key_header_and_query_are_distinct(self):
        source = self.node(
            "parameter:key", "PARAMETER", properties={"parameter_index": 0}
        )
        header = self.node("argument:header", "ARGUMENT", properties={"argument_index": 1})
        query = self.node("argument:query", "ARGUMENT", properties={"argument_index": 1})
        document = flow.FlowDocument(
            self.snapshot,
            nodes=(source, header, query),
            edges=(self.edge(source, header), self.edge(source, query)),
        )
        overlay = security.SecurityOverlay(
            self.snapshot,
            (
                self.signal("API_KEY_HEADER_SINK", header),
                self.signal("API_KEY_QUERY_SINK", query),
            ),
        )
        result = security.find_auth_flow(document, overlay, focus="api_key")
        self.assertEqual(
            {item["kind"] for item in result["findings"]},
            {"API_KEY_HEADER_FLOW", "API_KEY_QUERY_FLOW"},
        )

    def test_string_only_markers_never_become_finding(self):
        auth = self.node("authorization", "CONSTANT", properties={"literal_kind": "dex-constant"})
        hmac = self.node("hmac", "CONSTANT", properties={"literal_kind": "dex-constant"})
        aes = self.node("aes", "CONSTANT", properties={"literal_kind": "dex-constant"})
        document = flow.FlowDocument(self.snapshot, nodes=(auth, hmac, aes))
        overlay = security.SecurityOverlay(
            self.snapshot,
            (
                self.signal("BEARER_SCHEME_MARKER", auth),
                self.signal("CRYPTO_ALGORITHM_MARKER", hmac, properties={"family": "hmac"}),
                self.signal("CRYPTO_ALGORITHM_MARKER", aes, properties={"family": "aes"}),
            ),
        )
        self.assertEqual(security.find_auth_flow(document, overlay)["counts"]["findings"], 0)
        self.assertEqual(security.trace_crypto(document, overlay)["counts"]["findings"], 0)

    def test_gap_is_reported_but_never_traversed_for_auth(self):
        source = self.node(
            "parameter:token", "PARAMETER", properties={"parameter_index": 0}
        )
        boundary = self.node("argument:boundary", "ARGUMENT", properties={"argument_index": 0})
        sink = self.node("argument:header", "ARGUMENT", properties={"argument_index": 1})
        edge = self.edge(source, boundary)
        gap = self.gap(boundary, sink)
        document = flow.FlowDocument(
            self.snapshot,
            nodes=(source, boundary, sink),
            edges=(edge,),
            gaps=(gap,),
        )
        overlay = security.SecurityOverlay(
            self.snapshot,
            (
                self.signal("AUTHORIZATION_HEADER_SINK", sink),
                self.signal("IDENTITY_SDK_BOUNDARY", gap, anchor_type="FLOW_GAP", properties={"provider": "firebase"}),
            ),
        )
        result = security.find_auth_flow(document, overlay)
        self.assertEqual(result["counts"]["findings"], 0)
        self.assertEqual(result["counts"]["boundaries"], 1)
        self.assertFalse(result["gaps_are_traversable"])

    def test_hmac_reports_app_side_inputs_and_output_after_boundary_separately(self):
        key = self.node(
            "parameter:key", "PARAMETER", properties={"parameter_index": 0}
        )
        payload = self.node(
            "parameter:payload", "PARAMETER", properties={"parameter_index": 1}
        )
        key_arg = self.node("argument:key", "ARGUMENT", properties={"argument_index": 0})
        payload_arg = self.node("argument:payload", "ARGUMENT", properties={"argument_index": 0})
        external_return = self.node("return:hmac", "RETURN")
        signature = self.node("local:signature")
        signature_sink = self.node("argument:signature", "ARGUMENT", properties={"argument_index": 1})
        edges = (
            self.edge(key, key_arg),
            self.edge(payload, payload_arg),
            self.edge(external_return, signature, "RETURN_TO_CALLSITE"),
            self.edge(signature, signature_sink),
        )
        gap = self.gap(payload_arg, external_return)
        document = flow.FlowDocument(
            self.snapshot,
            nodes=(key, payload, key_arg, payload_arg, external_return, signature, signature_sink),
            edges=edges,
            gaps=(gap,),
        )
        overlay = security.SecurityOverlay(
            self.snapshot,
            (
                self.signal("HMAC_KEY_INPUT", key_arg),
                self.signal("HMAC_PAYLOAD_INPUT", payload_arg),
                self.signal("HMAC_OUTPUT_BOUNDARY", gap, anchor_type="FLOW_GAP"),
                self.signal("SIGNATURE_HEADER_SINK", signature_sink),
            ),
        )
        result = security.trace_crypto(document, overlay, family="hmac")
        kinds = {item["kind"] for item in result["findings"]}
        self.assertIn("HMAC_KEY_INPUT_FLOW", kinds)
        self.assertIn("HMAC_PAYLOAD_INPUT_FLOW", kinds)
        self.assertIn("HMAC_OUTPUT_TO_SIGNATURE_SINK", kinds)
        self.assertEqual(result["counts"]["boundaries"], 1)
        self.assertNotIn(
            gap.gap_id,
            {segment for path in result["paths"] for segment in path["segment_ids"]},
        )

    def test_aes_reports_key_iv_payload_and_downstream_output_without_crossing_gap(self):
        key = self.node("parameter:key", "PARAMETER", properties={"parameter_index": 0})
        iv = self.node("parameter:iv", "PARAMETER", properties={"parameter_index": 1})
        payload = self.node("parameter:data", "PARAMETER", properties={"parameter_index": 2})
        key_arg = self.node("argument:key", "ARGUMENT", properties={"argument_index": 1})
        iv_arg = self.node("argument:iv", "ARGUMENT", properties={"argument_index": 2})
        payload_arg = self.node("argument:data", "ARGUMENT", properties={"argument_index": 0})
        external_return = self.node("return:aes", "RETURN")
        output = self.node("local:ciphertext")
        terminal = self.node("return:root", "RETURN")
        edges = (
            self.edge(key, key_arg),
            self.edge(iv, iv_arg),
            self.edge(payload, payload_arg),
            self.edge(external_return, output, "RETURN_TO_CALLSITE"),
            self.edge(output, terminal),
        )
        gap = self.gap(payload_arg, external_return)
        document = flow.FlowDocument(
            self.snapshot,
            nodes=(key, iv, payload, key_arg, iv_arg, payload_arg, external_return, output, terminal),
            edges=edges,
            gaps=(gap,),
        )
        overlay = security.SecurityOverlay(
            self.snapshot,
            (
                self.signal("CRYPTO_KEY_INPUT", key_arg),
                self.signal("CRYPTO_IV_INPUT", iv_arg),
                self.signal("AES_PAYLOAD_INPUT", payload_arg),
                self.signal("AES_OUTPUT_BOUNDARY", gap, anchor_type="FLOW_GAP"),
            ),
        )
        result = security.trace_crypto(document, overlay, family="aes")
        kinds = {item["kind"] for item in result["findings"]}
        self.assertTrue(
            {
                "AES_KEY_INPUT_FLOW",
                "AES_IV_INPUT_FLOW",
                "AES_PAYLOAD_INPUT_FLOW",
                "AES_OUTPUT_FLOW",
            }.issubset(kinds)
        )

    def test_signal_anchor_must_resolve(self):
        node = self.node("local:any")
        document = flow.FlowDocument(self.snapshot, nodes=(node,))
        bad_id = "flown:v1:local:" + "0" * 64
        signal = security.SecuritySignal(
            self.snapshot,
            security.security_signal_id(
                self.snapshot, "AUTHORIZATION_HEADER_SINK", "FLOW_NODE", bad_id
            ),
            "AUTHORIZATION_HEADER_SINK",
            self.owner,
            "dex",
            "FLOW_NODE",
            bad_id,
            "fixture",
        )
        overlay = security.SecurityOverlay(self.snapshot, (signal,))
        with self.assertRaisesRegex(security.SecuritySemanticsError, "anchor does not resolve"):
            security.find_auth_flow(document, overlay)

    def test_overlay_rejects_secret_shaped_property_names_and_boolean_limits(self):
        node = self.node("local:any")
        with self.assertRaisesRegex(security.SecuritySemanticsError, "unsupported security property"):
            self.signal(
                "AUTHORIZATION_HEADER_SINK",
                node,
                properties={"token_value": "super-secret"},
            )
        document = flow.FlowDocument(self.snapshot, nodes=(node,))
        overlay = security.SecurityOverlay(self.snapshot, ())
        with self.assertRaisesRegex(security.SecuritySemanticsError, "invalid security finding limit"):
            security.find_auth_flow(document, overlay, max_findings=True)

    def test_descriptor_preserves_flow_and_secret_boundaries(self):
        descriptor = security.descriptor()
        self.assertEqual(descriptor["flow_ir_version"], flow.FLOW_IR_VERSION)
        self.assertFalse(descriptor["calls_xref_are_data_flow"])
        self.assertFalse(descriptor["gaps_are_traversable"])
        self.assertFalse(descriptor["raw_secret_values"])
        self.assertFalse(descriptor["persistent_security_storage"])
        self.assertEqual(descriptor["max_path_states"], 10_000)


if __name__ == "__main__":
    unittest.main()
