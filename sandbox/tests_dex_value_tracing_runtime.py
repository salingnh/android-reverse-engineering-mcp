from __future__ import annotations

import unittest

import dex_value_tracing as dexflow
import dex_value_tracing_runtime as runtime
import program_model as pm
import pu_program_model


class DalvikRuntimeAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.snapshot = pm.ProgramSnapshot("7" * 64)
        self.methods: dict[str, dexflow.MethodSpec] = {}

    def method(
        self,
        private_id: str,
        *,
        descriptor: str = "()V",
        parameters=(),
        blocks=(),
        class_name: str = "com.example.Caller",
        class_entity_id: str = "pm:v1:class:fixture",
        ownership: str = "FIRST_PARTY",
        is_static: bool = True,
        is_native: bool = False,
        is_external: bool = False,
    ) -> dexflow.MethodSpec:
        item = dexflow.MethodSpec(
            private_id=private_id,
            entity_id="pm:v1:function:" + dexflow._hash(private_id)[:32],
            class_entity_id=class_entity_id,
            semantic_key="function:v1:dex:" + dexflow._hash(private_id),
            class_name=class_name,
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

    def builder(self, **kwargs) -> runtime.DalvikFlowBuilder:
        return runtime.DalvikFlowBuilder(
            program_snapshot=self.snapshot,
            snapshot_id=self.snapshot.snapshot_id,
            method_loader=self.methods.get,
            evidence_ref=lambda method, instruction, kind: (
                "pme:"
                + dexflow._hash(
                    method.private_id,
                    str(instruction.offset if instruction else -1),
                    kind,
                )
            ),
            **kwargs,
        )

    def test_wide_argument_words_collapse_but_instance_receiver_is_preserved(self) -> None:
        self.assertEqual(
            runtime.semantic_invoke_registers(
                (0, 1, 2),
                "invoke-static",
                "(JI)V",
            ),
            (0, 2),
        )
        self.assertEqual(
            runtime.semantic_invoke_registers(
                (9, 0, 1, 2),
                "invoke-virtual",
                "(JI)V",
            ),
            (9, 0, 2),
        )
        self.assertEqual(
            runtime.semantic_invoke_registers(
                (9, 0, 1, 2),
                "invoke-virtual",
                None,
            ),
            (9, 0, 1, 2),
        )

    def test_instance_call_maps_every_semantic_argument_once(self) -> None:
        callee = self.method(
            "callee",
            descriptor="(JI)I",
            parameters=(
                dexflow.ParameterSpec(0, 0, "J"),
                dexflow.ParameterSpec(1, 2, "I"),
            ),
            is_static=False,
            blocks=(
                dexflow.BlockSpec(
                    0,
                    (dexflow.InstructionSpec(0, "return", (2,)),),
                ),
            ),
        )
        caller = self.method(
            "caller",
            descriptor="()I",
            blocks=(
                dexflow.BlockSpec(
                    0,
                    (
                        dexflow.InstructionSpec(
                            0,
                            "const-wide/16",
                            (0,),
                            "sha256:" + "a" * 64,
                        ),
                        dexflow.InstructionSpec(
                            2,
                            "const/4",
                            (2,),
                            "sha256:" + "b" * 64,
                        ),
                        # Runtime normalization retains receiver 9, collapses J
                        # from words (0,1), and keeps I at register 2.
                        dexflow.InstructionSpec(
                            4,
                            "invoke-direct",
                            (9, 0, 2),
                            call_targets=(callee.private_id,),
                        ),
                        dexflow.InstructionSpec(6, "move-result", (3,)),
                        dexflow.InstructionSpec(8, "return", (3,)),
                    ),
                ),
            ),
        )
        analysis = self.builder(analysis_depth=3).build(caller.private_id)
        mappings = [
            edge
            for edge in analysis.document.edges
            if edge.kind == "ARGUMENT_TO_PARAMETER"
        ]
        self.assertEqual(len(mappings), 2)
        self.assertEqual(
            {edge.properties["argument_index"] for edge in mappings},
            {0, 1},
        )
        self.assertEqual(
            {edge.properties["parameter_index"] for edge in mappings},
            {0, 1},
        )

    def test_reflection_precedes_virtual_dispatch_gap(self) -> None:
        instruction = dexflow.InstructionSpec(
            10,
            "invoke-virtual",
            (0, 1, 2),
            call_targets=(
                "Ljava/lang/reflect/Method; invoke "
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
            ),
        )
        self.assertEqual(runtime.dispatch_gap_kind(instruction), "REFLECTION")

    def test_field_owner_is_declaring_class_and_shared_across_accessors(self) -> None:
        field_ref = "Lcom/shared/Store;->token:Ljava/lang/String;"
        getter = self.method(
            "getter",
            descriptor="()Ljava/lang/String;",
            class_name="com.feature.Reader",
            class_entity_id="pm:v1:class:reader",
            blocks=(
                dexflow.BlockSpec(
                    0,
                    (
                        dexflow.InstructionSpec(
                            0,
                            "sget-object",
                            (0,),
                            field_ref=field_ref,
                            field_name="ignored.fallback",
                        ),
                        dexflow.InstructionSpec(2, "return-object", (0,)),
                    ),
                ),
            ),
        )
        setter = self.method(
            "setter",
            descriptor="(Ljava/lang/String;)Ljava/lang/String;",
            parameters=(dexflow.ParameterSpec(0, 0, "Ljava/lang/String;"),),
            class_name="com.feature.Writer",
            class_entity_id="pm:v1:class:writer",
            blocks=(
                dexflow.BlockSpec(
                    0,
                    (
                        dexflow.InstructionSpec(
                            0,
                            "sput-object",
                            (0,),
                            field_ref=field_ref,
                            field_name="another.fallback",
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
        analysis = self.builder(analysis_depth=3).build(setter.private_id)
        fields = [
            item for item in analysis.document.nodes if item.value_kind == "FIELD"
        ]
        self.assertEqual(len(fields), 1)
        expected_owner = pm.entity_id(
            self.snapshot,
            "CLASS",
            pu_program_model.DexProgramProvider.class_key("com.shared.Store"),
        )
        self.assertEqual(fields[0].owner_entity_id, expected_owner)
        self.assertEqual(
            fields[0].properties["field_name"],
            "com.shared.Store.token",
        )
        self.assertEqual(fields[0].evidence_refs, ())

    def test_two_addr_reads_old_destination_before_write(self) -> None:
        root = self.method(
            "two-addr",
            descriptor="(II)I",
            parameters=(
                dexflow.ParameterSpec(0, 0, "I"),
                dexflow.ParameterSpec(1, 1, "I"),
            ),
            blocks=(
                dexflow.BlockSpec(
                    0,
                    (
                        dexflow.InstructionSpec(0, "add-int/2addr", (0, 1)),
                        dexflow.InstructionSpec(2, "return", (0,)),
                    ),
                ),
            ),
        )
        analysis = self.builder().build(root.private_id)
        parameters = {
            item.properties["parameter_index"]: item
            for item in analysis.document.nodes
            if item.value_kind == "PARAMETER"
        }
        target = next(
            item
            for item in analysis.document.nodes
            if item.value_kind == "LOCAL"
        )
        incoming = {
            edge.source_node_id
            for edge in analysis.document.edges
            if edge.kind == "TRANSFORMS"
            and edge.target_node_id == target.node_id
        }
        self.assertEqual(
            incoming,
            {parameters[0].node_id, parameters[1].node_id},
        )
        self.assertNotIn(target.node_id, incoming)

    def test_three_operand_transform_can_read_old_destination(self) -> None:
        root = self.method(
            "three-operand-overlap",
            descriptor="(II)I",
            parameters=(
                dexflow.ParameterSpec(0, 0, "I"),
                dexflow.ParameterSpec(1, 1, "I"),
            ),
            blocks=(
                dexflow.BlockSpec(
                    0,
                    (
                        dexflow.InstructionSpec(0, "add-int", (0, 0, 1)),
                        dexflow.InstructionSpec(2, "return", (0,)),
                    ),
                ),
            ),
        )
        analysis = self.builder().build(root.private_id)
        target = next(
            item
            for item in analysis.document.nodes
            if item.value_kind == "LOCAL"
        )
        incoming = [
            edge
            for edge in analysis.document.edges
            if edge.kind == "TRANSFORMS"
            and edge.target_node_id == target.node_id
        ]
        self.assertEqual(len(incoming), 2)
        self.assertTrue(all(edge.source_node_id != target.node_id for edge in incoming))

    def test_same_register_move_reads_before_write(self) -> None:
        root = self.method(
            "self-move",
            descriptor="(I)I",
            parameters=(dexflow.ParameterSpec(0, 0, "I"),),
            blocks=(
                dexflow.BlockSpec(
                    0,
                    (
                        dexflow.InstructionSpec(0, "move", (0, 0)),
                        dexflow.InstructionSpec(2, "return", (0,)),
                    ),
                ),
            ),
        )
        analysis = self.builder().build(root.private_id)
        parameter = next(
            item
            for item in analysis.document.nodes
            if item.value_kind == "PARAMETER"
        )
        local = next(
            item
            for item in analysis.document.nodes
            if item.value_kind == "LOCAL"
        )
        assignment = next(
            edge
            for edge in analysis.document.edges
            if edge.kind == "ASSIGNMENT"
        )
        self.assertEqual(assignment.source_node_id, parameter.node_id)
        self.assertEqual(assignment.target_node_id, local.node_id)

    def test_move_exception_is_explicit_gap(self) -> None:
        root = self.method(
            "exception",
            descriptor="()V",
            blocks=(
                dexflow.BlockSpec(
                    0,
                    (dexflow.InstructionSpec(0, "move-exception", (0,)),),
                ),
            ),
        )
        analysis = self.builder().build(root.private_id)
        self.assertIn(
            "UNSUPPORTED_INSTRUCTION",
            {item.kind for item in analysis.document.gaps},
        )

    def test_descriptor_exposes_correctness_guards(self) -> None:
        descriptor = runtime.descriptor()
        self.assertTrue(descriptor["dalvik_abi_normalization"])
        self.assertTrue(
            descriptor["instance_receiver_preserved_until_semantic_call_layer"]
        )
        self.assertTrue(descriptor["declaring_field_owner_canonical"])
        self.assertTrue(descriptor["read_before_write_semantics"])
        self.assertTrue(descriptor["move_exception_is_explicit_gap"])


if __name__ == "__main__":
    unittest.main()
