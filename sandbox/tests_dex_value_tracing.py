from __future__ import annotations

import json
import unittest

import dex_value_tracing as dexflow
import flow_ir as flow
import program_model as pm
import value_tracing as tracing


class NormalizedDexFlowTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = pm.ProgramSnapshot("2" * 64).snapshot_id
        self.methods: dict[str, dexflow.MethodSpec] = {}

    @staticmethod
    def fingerprint(char: str) -> str:
        return "sha256:" + char * 64

    def method(
        self,
        private_id: str,
        *,
        descriptor="()V",
        parameters=(),
        blocks=(),
        ownership="FIRST_PARTY",
        class_entity_id="pm:v1:class:fixture",
        is_static=True,
        is_native=False,
        is_external=False,
    ):
        item = dexflow.MethodSpec(
            private_id=private_id,
            entity_id="pm:v1:function:" + dexflow._hash(private_id)[:32],
            class_entity_id=class_entity_id,
            semantic_key="function:v1:dex:" + dexflow._hash(private_id),
            class_name="com.example.Fixture",
            name=private_id,
            descriptor=descriptor,
            ownership=ownership,
            is_static=is_static,
            is_native=is_native,
            is_external=is_external,
            parameters=tuple(parameters),
            blocks=tuple(blocks),
        )
        self.methods[private_id] = item
        return item

    @staticmethod
    def evidence_ref(method, instruction, kind):
        if kind == "field" and instruction is not None and instruction.field_ref:
            return "pme:" + dexflow._hash("field", instruction.field_ref)
        return "pme:" + dexflow._hash(
            method.private_id,
            str(instruction.offset if instruction else -1),
            kind,
        )

    def builder(self, **kwargs):
        return dexflow.NormalizedDexFlowBuilder(
            snapshot_id=self.snapshot,
            method_loader=self.methods.get,
            evidence_ref=self.evidence_ref,
            **kwargs,
        )

    def test_intraprocedural_constant_move_return(self):
        root = self.method(
            "root",
            descriptor="()Ljava/lang/String;",
            blocks=(
                dexflow.BlockSpec(
                    0,
                    (
                        dexflow.InstructionSpec(
                            0,
                            "const-string",
                            (0,),
                            self.fingerprint("a"),
                        ),
                        dexflow.InstructionSpec(2, "move-object", (1, 0)),
                        dexflow.InstructionSpec(4, "return-object", (1,)),
                    ),
                ),
            ),
        )
        analysis = self.builder().build(root.private_id)
        kinds = {item.kind for item in analysis.document.edges}
        self.assertIn("CONSTANT_TO_VALUE", kinds)
        self.assertIn("ASSIGNMENT", kinds)
        self.assertIn("FLOWS_TO", kinds)
        encoded = json.dumps(analysis.document.to_dict(), sort_keys=True)
        self.assertNotIn("const-string-value", encoded)
        constants = [item for item in analysis.document.nodes if item.value_kind == "CONSTANT"]
        self.assertEqual(len(constants), 1)
        self.assertEqual(constants[0].label, "")
        self.assertRegex(constants[0].semantic_key, r"^constant:[0-9a-f]{64}$")

    def test_exact_static_argument_parameter_and_return_composition(self):
        callee = self.method(
            "callee",
            descriptor="(Ljava/lang/String;)Ljava/lang/String;",
            parameters=(dexflow.ParameterSpec(0, 0, "Ljava/lang/String;"),),
            blocks=(
                dexflow.BlockSpec(
                    0,
                    (dexflow.InstructionSpec(0, "return-object", (0,)),),
                ),
            ),
        )
        caller = self.method(
            "caller",
            descriptor="(Ljava/lang/String;)Ljava/lang/String;",
            parameters=(dexflow.ParameterSpec(0, 0, "Ljava/lang/String;"),),
            blocks=(
                dexflow.BlockSpec(
                    0,
                    (
                        dexflow.InstructionSpec(
                            0,
                            "invoke-static",
                            (0,),
                            call_targets=(callee.private_id,),
                        ),
                        dexflow.InstructionSpec(2, "move-result-object", (1,)),
                        dexflow.InstructionSpec(4, "return-object", (1,)),
                    ),
                ),
            ),
        )
        analysis = self.builder(analysis_depth=3).build(caller.private_id)
        kinds = [item.kind for item in analysis.document.edges]
        self.assertIn("ARGUMENT_TO_PARAMETER", kinds)
        self.assertIn("RETURN_TO_CALLSITE", kinds)
        root_parameter = next(
            item
            for item in analysis.document.nodes
            if item.owner_entity_id == caller.entity_id
            and item.value_kind == "PARAMETER"
        )
        root_return = next(
            item
            for item in analysis.document.nodes
            if item.owner_entity_id == caller.entity_id
            and item.value_kind == "RETURN"
        )
        result = tracing.find_source_to_sink(
            analysis.document,
            owner_entity_id=caller.entity_id,
            source_selector={"kind": "node", "node_id": root_parameter.node_id},
            sink_selector={"kind": "node", "node_id": root_return.node_id},
            max_depth=16,
        )
        self.assertGreaterEqual(result["complete_path_count"], 1)
        self.assertTrue(all(item["complete"] for item in result["flow"]["paths"]))

    def test_field_write_read_propagates_through_shared_field_node(self):
        shared_class = "pm:v1:class:shared"
        getter = self.method(
            "getter",
            descriptor="()Ljava/lang/String;",
            class_entity_id=shared_class,
            blocks=(
                dexflow.BlockSpec(
                    0,
                    (
                        dexflow.InstructionSpec(
                            0,
                            "sget-object",
                            (0,),
                            field_ref="Lcom/example/Fixture;->token:Ljava/lang/String;",
                            field_name="com.example.Fixture.token",
                        ),
                        dexflow.InstructionSpec(2, "return-object", (0,)),
                    ),
                ),
            ),
        )
        setter = self.method(
            "setter",
            descriptor="(Ljava/lang/String;)Ljava/lang/String;",
            class_entity_id=shared_class,
            parameters=(dexflow.ParameterSpec(0, 0, "Ljava/lang/String;"),),
            blocks=(
                dexflow.BlockSpec(
                    0,
                    (
                        dexflow.InstructionSpec(
                            0,
                            "sput-object",
                            (0,),
                            field_ref="Lcom/example/Fixture;->token:Ljava/lang/String;",
                            field_name="com.example.Fixture.token",
                        ),
                        dexflow.InstructionSpec(
                            2,
                            "invoke-static",
                            (),
                            call_targets=(getter.private_id,),
                        ),
                        dexflow.InstructionSpec(4, "move-result-object", (1,)),
                        dexflow.InstructionSpec(6, "return-object", (1,)),
                    ),
                ),
            ),
        )
        analysis = self.builder().build(setter.private_id)
        fields = [item for item in analysis.document.nodes if item.value_kind == "FIELD"]
        self.assertEqual(len(fields), 1)
        kinds = {item.kind for item in analysis.document.edges}
        self.assertIn("FIELD_WRITE", kinds)
        self.assertIn("FIELD_READ", kinds)
        source = next(
            item
            for item in analysis.document.nodes
            if item.owner_entity_id == setter.entity_id
            and item.value_kind == "PARAMETER"
        )
        sink = next(
            item
            for item in analysis.document.nodes
            if item.owner_entity_id == setter.entity_id
            and item.value_kind == "RETURN"
        )
        result = tracing.find_source_to_sink(
            analysis.document,
            owner_entity_id=setter.entity_id,
            source_selector={"kind": "node", "node_id": source.node_id},
            sink_selector={"kind": "node", "node_id": sink.node_id},
            max_depth=20,
        )
        self.assertGreaterEqual(result["complete_path_count"], 1)

    def test_cfg_join_emits_may_flow_from_both_reaching_definitions(self):
        root = self.method(
            "branch",
            descriptor="()I",
            blocks=(
                dexflow.BlockSpec(0, (), (10, 20)),
                dexflow.BlockSpec(
                    10,
                    (
                        dexflow.InstructionSpec(
                            10, "const/4", (0,), self.fingerprint("b")
                        ),
                    ),
                    (30,),
                ),
                dexflow.BlockSpec(
                    20,
                    (
                        dexflow.InstructionSpec(
                            20, "const/4", (0,), self.fingerprint("c")
                        ),
                    ),
                    (30,),
                ),
                dexflow.BlockSpec(
                    30,
                    (dexflow.InstructionSpec(30, "return", (0,)),),
                ),
            ),
        )
        analysis = self.builder().build(root.private_id)
        returned = next(
            item
            for item in analysis.document.nodes
            if item.owner_entity_id == root.entity_id and item.value_kind == "RETURN"
        )
        incoming = [
            edge
            for edge in analysis.document.edges
            if edge.target_node_id == returned.node_id and edge.kind == "FLOWS_TO"
        ]
        self.assertEqual(len(incoming), 2)

    def test_dynamic_dispatch_is_gap_and_not_complete_flow(self):
        target = self.method(
            "virtual-target",
            descriptor="(Ljava/lang/String;)Ljava/lang/String;",
            parameters=(dexflow.ParameterSpec(0, 1, "Ljava/lang/String;"),),
            is_static=False,
            blocks=(
                dexflow.BlockSpec(
                    0,
                    (dexflow.InstructionSpec(0, "return-object", (1,)),),
                ),
            ),
        )
        root = self.method(
            "virtual-caller",
            descriptor="(Ljava/lang/String;)Ljava/lang/String;",
            parameters=(dexflow.ParameterSpec(0, 0, "Ljava/lang/String;"),),
            blocks=(
                dexflow.BlockSpec(
                    0,
                    (
                        dexflow.InstructionSpec(
                            0,
                            "invoke-virtual",
                            (9, 0),
                            call_targets=(target.private_id,),
                        ),
                        dexflow.InstructionSpec(2, "move-result-object", (1,)),
                        dexflow.InstructionSpec(4, "return-object", (1,)),
                    ),
                ),
            ),
        )
        analysis = self.builder().build(root.private_id)
        self.assertIn("DYNAMIC_DISPATCH", {gap.kind for gap in analysis.document.gaps})
        source = next(
            item
            for item in analysis.document.nodes
            if item.owner_entity_id == root.entity_id and item.value_kind == "PARAMETER"
        )
        sink = next(
            item
            for item in analysis.document.nodes
            if item.owner_entity_id == root.entity_id and item.value_kind == "RETURN"
        )
        result = tracing.find_source_to_sink(
            analysis.document,
            owner_entity_id=root.entity_id,
            source_selector={"kind": "node", "node_id": source.node_id},
            sink_selector={"kind": "node", "node_id": sink.node_id},
        )
        self.assertEqual(result["complete_path_count"], 0)

    def test_instruction_budget_is_explicit_gap(self):
        callee = self.method(
            "budget-callee",
            descriptor="()I",
            blocks=(
                dexflow.BlockSpec(
                    0,
                    (
                        dexflow.InstructionSpec(
                            0, "const/4", (0,), self.fingerprint("d")
                        ),
                        dexflow.InstructionSpec(2, "return", (0,)),
                    ),
                ),
            ),
        )
        root = self.method(
            "budget-root",
            descriptor="()I",
            blocks=(
                dexflow.BlockSpec(
                    0,
                    (
                        dexflow.InstructionSpec(
                            0, "invoke-static", (), call_targets=(callee.private_id,)
                        ),
                        dexflow.InstructionSpec(2, "move-result", (0,)),
                        dexflow.InstructionSpec(4, "return", (0,)),
                    ),
                ),
            ),
        )
        analysis = self.builder(instruction_limit=3).build(root.private_id)
        self.assertTrue(analysis.truncated)
        self.assertIn("BUDGET", {gap.kind for gap in analysis.document.gaps})

    def test_descriptor_does_not_claim_calls_or_xrefs_are_flow(self):
        descriptor = dexflow.descriptor()
        self.assertFalse(descriptor["calls_xref_are_data_flow"])
        self.assertFalse(descriptor["persistent_flow_storage"])
        self.assertFalse(descriptor["raw_constants_emitted"])


if __name__ == "__main__":
    unittest.main()
