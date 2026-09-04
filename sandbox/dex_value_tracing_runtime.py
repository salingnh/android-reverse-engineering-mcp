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
    """Collapse Dalvik wide argument words while preserving the instance receiver.

    The normalized builder owns receiver removal for non-static invokes. This adapter
    therefore keeps the receiver at position zero and only maps the remaining Dalvik
    argument words to one register per semantic parameter.
    """
    words = list(registers)
    is_static = str(mnemonic).startswith("invoke-static")
    receiver: int | None = None
    if not is_static and words:
        receiver = words.pop(0)
    if not target_descriptor:
        return tuple(registers)

    parameters = dexflow._descriptor_parameters(target_descriptor)
    result: list[int] = []
    cursor = 0
    for descriptor in parameters:
        if cursor >= len(words):
            break
        result.append(words[cursor])
        cursor += 2 if dexflow._wide(descriptor) else 1

    if receiver is not None:
        return (receiver, *result)
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


def declaring_class_name(field_ref: str | None) -> str | None:
    value = str(field_ref or "").strip()
    if "->" not in value:
        return None
    owner = value.split("->", 1)[0].strip()
    if not owner:
        return None
    normalized = pu_index.normalize_class_descriptor(owner)
    return normalized or None


def stable_field_name(field_ref: str | None, fallback: str | None = None) -> str | None:
    value = str(field_ref or "").strip()
    if "->" not in value:
        text = str(fallback or "").strip()
        return text or None
    owner, tail = value.split("->", 1)
    member = tail.split(":", 1)[0].strip()
    class_name = pu_index.normalize_class_descriptor(owner.strip())
    if class_name and member:
        return f"{class_name}.{member}"
    text = str(fallback or "").strip()
    return text or None


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
    def __init__(
        self,
        *,
        program_snapshot: pm.ProgramSnapshot,
        **kwargs: Any,
    ) -> None:
        self.program_snapshot = program_snapshot
        super().__init__(**kwargs)

    @staticmethod
    def _dispatch_gap_kind(instruction: dexflow.InstructionSpec) -> str | None:
        return dispatch_gap_kind(instruction)

    def _unknown_call_result_node(
        self,
        method: dexflow.MethodSpec,
        instruction: dexflow.InstructionSpec,
    ) -> flow.FlowNode:
        return self._node(
            method,
            semantic_key=self._semantic_key(
                "call-result", method.semantic_key, instruction.offset
            ),
            value_kind="UNKNOWN",
            evidence_refs=(self.evidence_ref(method, instruction, "call-result"),),
        )

    def _call(
        self,
        method: dexflow.MethodSpec,
        instruction: dexflow.InstructionSpec,
        state: dict[int, frozenset[str]],
        depth: int,
    ) -> tuple[str, Any] | None:
        """Materialize uncertainty at the invoke itself, even when result is ignored.

        The base builder historically deferred a pending call gap until a following
        move-result. Dalvik callers may legitimately ignore a return value, and void
        calls never have move-result, so that behavior could silently lose a dynamic,
        native, missing-target, external-boundary or budget gap. The runtime adapter
        emits the gap at the invoke evidence site and leaves only the known/unknown
        return node pending for optional move-result wiring.
        """
        pending = super()._call(method, instruction, state, depth)
        if not pending or pending[0] != "gap":
            return pending

        _, gap_kind, sources, reason, *return_ids = pending
        target = str(return_ids[0]) if return_ids else self._unknown_call_result_node(
            method, instruction
        ).node_id
        source_ids = tuple(str(item) for item in sources)
        if source_ids:
            for ordinal, source in enumerate(source_ids):
                self._gap(
                    method,
                    instruction,
                    str(gap_kind),
                    source=source,
                    target=target,
                    reason=str(reason),
                    discriminator=self._discriminator(
                        method.semantic_key,
                        instruction.offset,
                        "invoke-gap",
                        ordinal,
                    ),
                )
        else:
            self._gap(
                method,
                instruction,
                str(gap_kind),
                target=target,
                reason=str(reason),
                discriminator=self._discriminator(
                    method.semantic_key,
                    instruction.offset,
                    "invoke-gap",
                ),
            )
        return ("return", target)

    def _field_node(
        self,
        method: dexflow.MethodSpec,
        instruction: dexflow.InstructionSpec,
    ) -> flow.FlowNode | None:
        if not instruction.field_ref:
            return None

        declaring_class = declaring_class_name(instruction.field_ref)
        owner_entity_id = method.class_entity_id
        if declaring_class:
            class_key = pu_program_model.DexProgramProvider.class_key(declaring_class)
            owner_entity_id = pm.entity_id(
                self.program_snapshot,
                "CLASS",
                class_key,
            )

        properties: dict[str, Any] = {}
        display = stable_field_name(instruction.field_ref, instruction.field_name)
        if display:
            properties["field_name"] = display[:1024]

        # Static fields are one shared semantic value across access sites. The
        # declaring type owns the value; access-specific provenance belongs on
        # FIELD_READ/FIELD_WRITE edges rather than on the shared node.
        return self._node(
            method,
            semantic_key=self._semantic_key("field", instruction.field_ref),
            value_kind="FIELD",
            owner_entity_id=owner_entity_id,
            properties=properties,
            evidence_refs=(),
        )

    @staticmethod
    def _is_transform(instruction: dexflow.InstructionSpec) -> bool:
        return instruction.mnemonic.startswith(dexflow._TRANSFORM_PREFIXES)

    @staticmethod
    def _is_plain_move(instruction: dexflow.InstructionSpec) -> bool:
        name = instruction.mnemonic
        return (
            name.startswith("move")
            and not name.startswith("move-result")
            and name != "move-exception"
        )

    @staticmethod
    def _is_instance_field(instruction: dexflow.InstructionSpec) -> bool:
        return instruction.mnemonic.startswith(("iget", "iput"))

    def _emit_transform(
        self,
        method: dexflow.MethodSpec,
        instruction: dexflow.InstructionSpec,
        state: dict[int, frozenset[str]],
    ) -> None:
        registers = instruction.registers
        if not registers:
            self._gap(
                method,
                instruction,
                "MISSING_EVIDENCE",
                reason="transformation operands are unavailable",
                discriminator=self._discriminator(
                    method.semantic_key, instruction.offset, "transform"
                ),
            )
            return

        # Every Dalvik transformation reads all source operands before writing the
        # destination. /2addr additionally reads the old destination implicitly.
        if "/2addr" in instruction.mnemonic:
            source_registers = registers
        else:
            source_registers = registers[1:]
        captured = [
            (register, self._sources(state, register))
            for register in source_registers
        ]

        target = self._local_node(method, instruction)
        if not source_registers:
            self._gap(
                method,
                instruction,
                "MISSING_EVIDENCE",
                target=target.node_id,
                reason="transformation operands are unavailable",
                discriminator=self._discriminator(
                    method.semantic_key, instruction.offset, "transform"
                ),
            )
        for source_index, (_register, sources) in enumerate(captured):
            self._link_sources(
                method,
                instruction,
                sources,
                target.node_id,
                "TRANSFORMS",
                discriminator_prefix=f"transform:{source_index}",
                properties={"transform_kind": instruction.mnemonic[:256]},
            )
        state[registers[0]] = frozenset({target.node_id})

    def _emit_plain_move(
        self,
        method: dexflow.MethodSpec,
        instruction: dexflow.InstructionSpec,
        state: dict[int, frozenset[str]],
    ) -> None:
        registers = instruction.registers
        if not registers:
            return
        sources = (
            self._sources(state, registers[1])
            if len(registers) >= 2
            else ()
        )
        target = self._local_node(method, instruction)
        if len(registers) >= 2:
            self._link_sources(
                method,
                instruction,
                sources,
                target.node_id,
                "ASSIGNMENT",
                discriminator_prefix="move",
                properties={"statement_offset": instruction.offset},
            )
        state[registers[0]] = frozenset({target.node_id})

    def _emit_move_exception(
        self,
        method: dexflow.MethodSpec,
        instruction: dexflow.InstructionSpec,
        state: dict[int, frozenset[str]],
    ) -> None:
        registers = instruction.registers
        target = self._local_node(method, instruction)
        if registers:
            state[registers[0]] = frozenset({target.node_id})
        self._gap(
            method,
            instruction,
            "UNSUPPORTED_INSTRUCTION",
            target=target.node_id,
            reason="move-exception value source is not normalized",
            discriminator=self._discriminator(
                method.semantic_key, instruction.offset, "unsupported", "move-exception"
            ),
        )

    def _emit_instance_field(
        self,
        method: dexflow.MethodSpec,
        instruction: dexflow.InstructionSpec,
        state: dict[int, frozenset[str]],
    ) -> None:
        registers = instruction.registers
        reason = "instance-field receiver alias is not proven"
        if instruction.mnemonic.startswith("iget"):
            target = self._local_node(method, instruction)
            if registers:
                state[registers[0]] = frozenset({target.node_id})
            self._gap(
                method,
                instruction,
                "MISSING_EVIDENCE",
                target=target.node_id,
                reason=reason,
                discriminator=self._discriminator(
                    method.semantic_key, instruction.offset, "instance-field-read"
                ),
            )
            return

        sources = self._sources(state, registers[0]) if registers else ()
        if sources:
            for ordinal, source in enumerate(sources):
                self._gap(
                    method,
                    instruction,
                    "MISSING_EVIDENCE",
                    source=source,
                    reason=reason,
                    discriminator=self._discriminator(
                        method.semantic_key,
                        instruction.offset,
                        "instance-field-write",
                        ordinal,
                    ),
                )
        else:
            self._gap(
                method,
                instruction,
                "MISSING_EVIDENCE",
                reason=reason,
                discriminator=self._discriminator(
                    method.semantic_key, instruction.offset, "instance-field-write"
                ),
            )

    def _emit_block(
        self,
        method: dexflow.MethodSpec,
        block: dexflow.BlockSpec,
        incoming: dict[int, frozenset[str]],
        depth: int,
    ) -> None:
        custom = any(
            self._is_transform(item)
            or self._is_plain_move(item)
            or self._is_instance_field(item)
            or item.mnemonic == "move-exception"
            for item in block.instructions
        )
        if not custom:
            super()._emit_block(method, block, incoming, depth)
            return

        state = dict(incoming)
        segment: list[dexflow.InstructionSpec] = []

        def flush() -> None:
            nonlocal state, segment
            if not segment:
                return
            normalized = dexflow.BlockSpec(
                start=segment[0].offset,
                instructions=tuple(segment),
                successors=(),
            )
            super(DalvikFlowBuilder, self)._emit_block(
                method,
                normalized,
                state,
                depth,
            )
            state = self._transfer_state(method, normalized, state)
            segment = []

        for instruction in block.instructions:
            if self._is_transform(instruction):
                flush()
                self._emit_transform(method, instruction, state)
            elif self._is_plain_move(instruction):
                flush()
                self._emit_plain_move(method, instruction, state)
            elif self._is_instance_field(instruction):
                flush()
                self._emit_instance_field(method, instruction, state)
            elif instruction.mnemonic == "move-exception":
                flush()
                self._emit_move_exception(method, instruction, state)
            else:
                segment.append(instruction)
        flush()


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
            program_snapshot=provider.snapshot,
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
            "instance_receiver_preserved_until_semantic_call_layer": True,
            "reflection_gap_precedence": True,
            "shared_field_access_evidence_on_edges": True,
            "declaring_field_owner_canonical": True,
            "static_field_flow_proven": True,
            "instance_field_alias_required": True,
            "instance_field_unproven_is_gap": True,
            "read_before_write_semantics": True,
            "move_exception_is_explicit_gap": True,
            "call_gap_materialized_at_invoke": True,
            "ignored_call_results_preserve_gap": True,
        }
    )
    return base
