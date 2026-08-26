from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import dex_value_tracing as dexflow
import flow_ir as flow
import program_model as pm
import pu_index
import pu_program_model


def semantic_invoke_registers(
    registers: tuple[int, ...],
    mnemonic: str,
    target_descriptor: str | None,
) -> tuple[int, ...]:
    """Convert Dalvik argument words to one register per semantic parameter."""
    words = list(registers)
    if not str(mnemonic).startswith("invoke-static") and words:
        words = words[1:]
    if not target_descriptor:
        return tuple(words)
    parameters = dexflow._descriptor_parameters(target_descriptor)
    result: list[int] = []
    cursor = 0
    for descriptor in parameters:
        if cursor >= len(words):
            break
        result.append(words[cursor])
        cursor += 2 if dexflow._wide(descriptor) else 1
    return tuple(result)


def dispatch_gap_kind(instruction: dexflow.InstructionSpec) -> str | None:
    # Reflection is more specific than the invoke-virtual opcode used by Method.invoke.
    if any(
        target.startswith(prefix)
        for target in instruction.call_targets
        for prefix in dexflow._REFLECTION_TARGETS
    ):
        return "REFLECTION"
    name = instruction.mnemonic
    if name.startswith(
        (
            "invoke-virtual",
            "invoke-interface",
            "invoke-polymorphic",
            "invoke-custom",
            "invoke-super",
        )
    ):
        return "DYNAMIC_DISPATCH"
    return None


class DalvikAbiMethodLoader(dexflow.AndroguardMethodLoader):
    def _blocks(self, method: Any) -> tuple[dexflow.BlockSpec, ...]:
        raw_blocks = super()._blocks(method)
        result: list[dexflow.BlockSpec] = []
        for block in raw_blocks:
            instructions: list[dexflow.InstructionSpec] = []
            for instruction in block.instructions:
                registers = instruction.registers
                if instruction.mnemonic.startswith("invoke-"):
                    descriptor = None
                    if len(instruction.call_targets) == 1:
                        target = self._methods.get(instruction.call_targets[0])
                        if target is not None:
                            raw = target.get_method() if hasattr(target, "get_method") else target
                            try:
                                descriptor = str(raw.get_descriptor())
                            except Exception:
                                descriptor = None
                    registers = semantic_invoke_registers(
                        registers,
                        instruction.mnemonic,
                        descriptor,
                    )
                instructions.append(replace(instruction, registers=registers))
            result.append(replace(block, instructions=tuple(instructions)))
        return tuple(result)


class DalvikFlowBuilder(dexflow.NormalizedDexFlowBuilder):
    @staticmethod
    def _dispatch_gap_kind(instruction: dexflow.InstructionSpec) -> str | None:
        return dispatch_gap_kind(instruction)

    def _field_node(
        self,
        method: dexflow.MethodSpec,
        instruction: dexflow.InstructionSpec,
    ) -> flow.FlowNode | None:
        if not instruction.field_ref:
            return None
        properties: dict[str, Any] = {}
        if instruction.field_name:
            properties["field_name"] = instruction.field_name[:1024]
        # The field is a shared semantic value across access sites. Access-specific
        # provenance belongs on FIELD_READ/FIELD_WRITE edges, not on this node.
        return self._node(
            method,
            semantic_key=self._semantic_key("field", instruction.field_ref),
            value_kind="FIELD",
            owner_entity_id=method.class_entity_id,
            properties=properties,
            evidence_refs=(),
        )


def build_dex_flow(
    job: Path,
    workspace: Path,
    caps: dict[str, Any],
    *,
    entity_id: str,
    method_limit: int = dexflow.DEFAULT_METHOD_LIMIT,
    analysis_depth: int = dexflow.DEFAULT_ANALYSIS_DEPTH,
    instruction_limit: int = dexflow.DEFAULT_INSTRUCTION_LIMIT,
) -> dexflow.DexFlowAnalysis:
    pu_index.ensure_index(job, workspace, caps)
    provider = pu_program_model.DexProgramProvider(job, workspace, caps)
    with pu_index.connect(job) as conn:
        row, truncated_lookup = provider._find_function_row(conn, str(entity_id))
    if row is None:
        if truncated_lookup:
            raise dexflow.DexValueTracingError(
                "canonical function lookup exceeded provider budget"
            )
        raise dexflow.DexValueTracingError("canonical function entity not found")

    root_private_id = str(row["id"])
    artifact = pu_index.artifact(job, workspace)
    with pu_index.androguard_analysis(artifact) as (analysis, class_members):
        loader = DalvikAbiMethodLoader(analysis, provider, class_members)

        def evidence(
            method: dexflow.MethodSpec,
            instruction: dexflow.InstructionSpec | None,
            kind: str,
        ) -> str:
            if kind == "field" and instruction is not None and instruction.field_ref:
                location = {
                    "kind": "dex-flow-field",
                    "field_ref_hash": dexflow._hash(instruction.field_ref),
                }
            else:
                location: dict[str, Any] = {
                    "kind": "dex-value-flow",
                    "flow_evidence_kind": str(kind)[:128],
                    "class": method.class_name,
                    "name": method.name,
                    "descriptor": method.descriptor,
                }
                if instruction is not None:
                    location.update(
                        {
                            "offset": instruction.offset,
                            "mnemonic": instruction.mnemonic[:128],
                        }
                    )
            return provider._evidence_ref(location)

        builder = DalvikFlowBuilder(
            snapshot_id=provider.snapshot.snapshot_id,
            method_loader=loader.load,
            evidence_ref=evidence,
            method_limit=method_limit,
            analysis_depth=analysis_depth,
            instruction_limit=instruction_limit,
        )
        return builder.build(root_private_id)


def descriptor() -> dict[str, Any]:
    base = dict(dexflow.descriptor())
    base.update(
        {
            "dalvik_abi_normalization": True,
            "wide_parameter_words_collapsed": True,
            "instance_receiver_not_public_argument": True,
            "reflection_gap_precedence": True,
            "shared_field_access_evidence_on_edges": True,
        }
    )
    return base
