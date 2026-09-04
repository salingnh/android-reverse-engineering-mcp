from __future__ import annotations

import json
import unittest

import dex_security_semantics as producer
import dex_value_tracing as dexflow
import flow_ir as flow
import program_model as pm
import security_semantics as security


class DexSecurityProducerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.snapshot = pm.ProgramSnapshot("8" * 64).snapshot_id
        self.methods: dict[str, dexflow.MethodSpec] = {}
        self.counter = 0

    def method(
        self,
        private_id: str,
        *,
        class_name: str = "com.example.Caller",
        name: str | None = None,
        descriptor: str = "()V",
        ownership: str = "FIRST_PARTY",
        is_static: bool = True,
        is_external: bool = False,
        blocks=(),
    ) -> dexflow.MethodSpec:
        item = dexflow.MethodSpec(
            private_id=private_id,
            entity_id="pm:v1:function:" + dexflow._hash(private_id)[:32],
            class_entity_id="pm:v1:class:" + dexflow._hash(class_name)[:32],
            semantic_key="function:v1:dex:" + dexflow._hash(private_id),
            class_name=class_name,
            name=name or private_id,
            descriptor=descriptor,
            ownership=ownership,
            is_static=is_static,
            is_native=False,
            is_external=is_external,
            parameters=(),
            blocks=tuple(blocks),
        )
        self.methods[private_id] = item
        return item

    def node(self, method: dexflow.MethodSpec, key: str, kind="LOCAL", properties=None):
        return flow.FlowNode(
            self.snapshot,
            flow.flow_node_id(self.snapshot, kind, method.entity_id, key),
            key,
            kind,
            method.entity_id,
            "dex",
            properties=properties or {},
        )

    def constant(self, method: dexflow.MethodSpec, instruction: dexflow.InstructionSpec):
        key = flow.constant_semantic_key(method.semantic_key, str(instruction.offset), "constant")
        return flow.FlowNode(
            self.snapshot,
            flow.flow_node_id(self.snapshot, "CONSTANT", method.entity_id, key),
            key,
            "CONSTANT",
            method.entity_id,
            "dex",
            properties={"literal_kind": "dex-constant"},
        )

    def argument(self, method: dexflow.MethodSpec, offset: int, index: int):
        key = f"argument:{dexflow._hash(method.semantic_key, offset, index)}"
        return flow.FlowNode(
            self.snapshot,
            flow.flow_node_id(self.snapshot, "ARGUMENT", method.entity_id, key),
            key,
            "ARGUMENT",
            method.entity_id,
            "dex",
            properties={"argument_index": index},
        )

    def unknown_result(self, method: dexflow.MethodSpec, offset: int):
        key = f"call-result:{dexflow._hash(method.semantic_key, offset)}"
        return flow.FlowNode(
            self.snapshot,
            flow.flow_node_id(self.snapshot, "UNKNOWN", method.entity_id, key),
            key,
            "UNKNOWN",
            method.entity_id,
            "dex",
        )

    def edge(self, source: flow.FlowNode, target: flow.FlowNode):
        self.counter += 1
        disc = f"fixture:{self.counter}"
        return flow.FlowEdge(
            self.snapshot,
            flow.flow_edge_id(self.snapshot, "FLOWS_TO", source.node_id, target.node_id, disc),
            "FLOWS_TO",
            source.node_id,
            target.node_id,
            "dex",
            "fixture",
            disc,
            {"flow_kind": "fixture"},
        )

    def gap(self, owner: dexflow.MethodSpec, source: flow.FlowNode, target: flow.FlowNode, kind="DYNAMIC_DISPATCH"):
        self.counter += 1
        disc = f"gap:{self.counter}"
        return flow.FlowGap(
            self.snapshot,
            flow.flow_gap_id(self.snapshot, kind, owner.entity_id, source.node_id, target.node_id, disc),
            kind,
            owner.entity_id,
            "dex",
            "fixture",
            source.node_id,
            target.node_id,
            disc,
            "call boundary",
        )

    def test_authorization_header_sink_requires_name_marker_flow(self):
        target = self.method(
            "header-target",
            class_name="okhttp3.Request$Builder",
            name="header",
            descriptor="(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Request$Builder;",
            ownership="THIRD_PARTY",
            is_static=False,
            is_external=True,
        )
        const = dexflow.InstructionSpec(0, "const-string", (0,), "sha256:" + "a" * 64)
        call = dexflow.InstructionSpec(2, "invoke-virtual", (9, 0, 1), call_targets=(target.private_id,))
        caller = self.method("caller", blocks=(dexflow.BlockSpec(0, (const, call)),))
        marker = self.constant(caller, const)
        name_arg = self.argument(caller, 2, 0)
        value_arg = self.argument(caller, 2, 1)
        token = self.node(caller, "parameter:token", "PARAMETER", {"parameter_index": 0})
        document = flow.FlowDocument(
            self.snapshot,
            nodes=(marker, name_arg, value_arg, token),
            edges=(self.edge(marker, name_arg), self.edge(token, value_arg)),
        )
        overlay = producer.build_overlay(document, self.methods, {(caller.private_id, 0): ("authorization",)})
        self.assertIn("AUTHORIZATION_HEADER_SINK", {item.kind for item in overlay.signals})
        self.assertEqual(security.find_auth_flow(document, overlay)["counts"]["findings"], 1)

    def test_unconnected_authorization_marker_never_creates_sink(self):
        target = self.method(
            "header-target",
            class_name="okhttp3.Request$Builder",
            name="header",
            descriptor="(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Request$Builder;",
            ownership="THIRD_PARTY",
            is_static=False,
            is_external=True,
        )
        const = dexflow.InstructionSpec(0, "const-string", (0,), "sha256:" + "a" * 64)
        call = dexflow.InstructionSpec(2, "invoke-virtual", (9, 2, 1), call_targets=(target.private_id,))
        caller = self.method("caller", blocks=(dexflow.BlockSpec(0, (const, call)),))
        document = flow.FlowDocument(
            self.snapshot,
            nodes=(self.constant(caller, const), self.argument(caller, 2, 0), self.argument(caller, 2, 1)),
        )
        overlay = producer.build_overlay(document, self.methods, {(caller.private_id, 0): ("authorization",)})
        self.assertNotIn("AUTHORIZATION_HEADER_SINK", {item.kind for item in overlay.signals})

    def test_hmac_requires_algorithm_flow_to_mac_getinstance(self):
        get_instance = self.method(
            "mac-get",
            class_name="javax.crypto.Mac",
            name="getInstance",
            descriptor="(Ljava/lang/String;)Ljavax/crypto/Mac;",
            ownership="PLATFORM",
            is_static=True,
            is_external=True,
        )
        init = self.method(
            "mac-init",
            class_name="javax.crypto.Mac",
            name="init",
            descriptor="(Ljava/security/Key;)V",
            ownership="PLATFORM",
            is_static=False,
            is_external=True,
        )
        final = self.method(
            "mac-final",
            class_name="javax.crypto.Mac",
            name="doFinal",
            descriptor="([B)[B",
            ownership="PLATFORM",
            is_static=False,
            is_external=True,
        )
        const = dexflow.InstructionSpec(0, "const-string", (0,), "sha256:" + "c" * 64)
        c0 = dexflow.InstructionSpec(2, "invoke-static", (0,), call_targets=(get_instance.private_id,))
        c1 = dexflow.InstructionSpec(4, "invoke-virtual", (9, 1), call_targets=(init.private_id,))
        c2 = dexflow.InstructionSpec(6, "invoke-virtual", (9, 2), call_targets=(final.private_id,))
        caller = self.method("caller", blocks=(dexflow.BlockSpec(0, (const, c0, c1, c2)),))
        marker = self.constant(caller, const)
        algorithm_arg = self.argument(caller, 2, 0)
        key = self.node(caller, "parameter:key", "PARAMETER", {"parameter_index": 0})
        payload = self.node(caller, "parameter:payload", "PARAMETER", {"parameter_index": 1})
        key_arg = self.argument(caller, 4, 0)
        payload_arg = self.argument(caller, 6, 0)
        result_node = self.unknown_result(caller, 6)
        gap = self.gap(caller, payload_arg, result_node)
        base_nodes = (marker, algorithm_arg, key, payload, key_arg, payload_arg, result_node)
        without_family_flow = flow.FlowDocument(
            self.snapshot,
            nodes=base_nodes,
            edges=(self.edge(key, key_arg), self.edge(payload, payload_arg)),
            gaps=(gap,),
        )
        overlay = producer.build_overlay(without_family_flow, self.methods, {(caller.private_id, 0): ("hmac",)})
        self.assertFalse({"HMAC_KEY_INPUT", "HMAC_PAYLOAD_INPUT", "HMAC_OUTPUT_BOUNDARY"}.intersection({item.kind for item in overlay.signals}))

        confirmed = flow.FlowDocument(
            self.snapshot,
            nodes=base_nodes,
            edges=(self.edge(marker, algorithm_arg), self.edge(key, key_arg), self.edge(payload, payload_arg)),
            gaps=(gap,),
        )
        overlay = producer.build_overlay(confirmed, self.methods, {(caller.private_id, 0): ("hmac",)})
        kinds = {item.kind for item in overlay.signals}
        self.assertTrue({"HMAC_KEY_INPUT", "HMAC_PAYLOAD_INPUT", "HMAC_OUTPUT_BOUNDARY"}.issubset(kinds))
        finding_kinds = {item["kind"] for item in security.trace_crypto(confirmed, overlay, family="hmac")["findings"]}
        self.assertIn("HMAC_KEY_INPUT_FLOW", finding_kinds)
        self.assertIn("HMAC_PAYLOAD_INPUT_FLOW", finding_kinds)

    def test_aes_requires_algorithm_flow_to_cipher_getinstance(self):
        get_instance = self.method(
            "cipher-get",
            class_name="javax.crypto.Cipher",
            name="getInstance",
            descriptor="(Ljava/lang/String;)Ljavax/crypto/Cipher;",
            ownership="PLATFORM",
            is_static=True,
            is_external=True,
        )
        cipher = self.method(
            "cipher-init",
            class_name="javax.crypto.Cipher",
            name="init",
            descriptor="(ILjava/security/Key;)V",
            ownership="PLATFORM",
            is_static=False,
            is_external=True,
        )
        const = dexflow.InstructionSpec(0, "const-string", (0,), "sha256:" + "b" * 64)
        get_call = dexflow.InstructionSpec(2, "invoke-static", (0,), call_targets=(get_instance.private_id,))
        init_call = dexflow.InstructionSpec(4, "invoke-virtual", (9, 1, 2), call_targets=(cipher.private_id,))
        caller = self.method("caller", blocks=(dexflow.BlockSpec(0, (const, get_call, init_call)),))
        marker = self.constant(caller, const)
        algorithm_arg = self.argument(caller, 2, 0)
        mode_arg = self.argument(caller, 4, 0)
        key_arg = self.argument(caller, 4, 1)
        key = self.node(caller, "parameter:key", "PARAMETER", {"parameter_index": 0})
        nodes = (marker, algorithm_arg, mode_arg, key_arg, key)

        unrelated = flow.FlowDocument(self.snapshot, nodes=nodes, edges=(self.edge(key, key_arg),))
        overlay = producer.build_overlay(unrelated, self.methods, {(caller.private_id, 0): ("aes",)})
        self.assertNotIn("CRYPTO_KEY_INPUT", {item.kind for item in overlay.signals})

        confirmed = flow.FlowDocument(
            self.snapshot,
            nodes=nodes,
            edges=(self.edge(marker, algorithm_arg), self.edge(key, key_arg)),
        )
        overlay = producer.build_overlay(confirmed, self.methods, {(caller.private_id, 0): ("aes",)})
        self.assertIn("CRYPTO_KEY_INPUT", {item.kind for item in overlay.signals})
        self.assertIn("CRYPTO_ALGORITHM_MARKER", {item.kind for item in overlay.signals})

    def test_identity_and_payment_sdk_stay_boundaries_and_token_source_is_post_gap_node(self):
        identity = self.method(
            "firebase-token",
            class_name="com.google.firebase.auth.FirebaseUser",
            name="getIdToken",
            descriptor="(Z)Lcom/google/android/gms/tasks/Task;",
            ownership="THIRD_PARTY",
            is_static=False,
            is_external=True,
        )
        payment = self.method(
            "stripe-confirm",
            class_name="com.stripe.android.PaymentConfiguration",
            name="init",
            descriptor="(Ljava/lang/String;)V",
            ownership="THIRD_PARTY",
            is_static=False,
            is_external=True,
        )
        c1 = dexflow.InstructionSpec(2, "invoke-virtual", (9, 0), call_targets=(identity.private_id,))
        c2 = dexflow.InstructionSpec(4, "invoke-virtual", (8, 1), call_targets=(payment.private_id,))
        caller = self.method("caller", blocks=(dexflow.BlockSpec(0, (c1, c2)),))
        a1 = self.argument(caller, 2, 0)
        a2 = self.argument(caller, 4, 0)
        r1 = self.unknown_result(caller, 2)
        r2 = self.unknown_result(caller, 4)
        g1 = self.gap(caller, a1, r1)
        g2 = self.gap(caller, a2, r2)
        document = flow.FlowDocument(self.snapshot, nodes=(a1, a2, r1, r2), gaps=(g1, g2))
        overlay = producer.build_overlay(document, self.methods, {})
        kinds = {item.kind for item in overlay.signals}
        self.assertIn("IDENTITY_SDK_BOUNDARY", kinds)
        self.assertIn("TOKEN_SOURCE_BOUNDARY", kinds)
        self.assertIn("PAYMENT_SDK_BOUNDARY", kinds)
        token = next(item for item in overlay.signals if item.kind == "TOKEN_SOURCE_BOUNDARY")
        self.assertEqual(token.anchor_type, "FLOW_NODE")
        self.assertEqual(token.anchor_id, r1.node_id)
        self.assertNotIn("publishable", json.dumps(overlay.to_dict(), sort_keys=True).lower())

    def test_safe_literal_normalization_returns_categories_only(self):
        self.assertEqual(producer._normalize_literal(" Authorization "), {"authorization"})
        self.assertEqual(producer._normalize_literal("HmacSHA256"), {"hmac"})
        self.assertEqual(producer._normalize_literal("AES/GCM/NoPadding"), {"aes"})
        self.assertEqual(producer._normalize_literal("super-secret-value"), set())

    def test_descriptor_fails_closed(self):
        value = producer.descriptor()
        self.assertFalse(value["decompiler_grep_is_finding_source"])
        self.assertFalse(value["calls_xref_are_data_flow"])
        self.assertFalse(value["gaps_are_traversable"])
        self.assertFalse(value["raw_secret_values"])
        self.assertFalse(value["receiver_alias_claimed"])
        self.assertTrue(value["stage_g_dynamic_result_anchor_respected"])
        self.assertTrue(value["crypto_family_requires_getinstance_flow"])


if __name__ == "__main__":
    unittest.main()
