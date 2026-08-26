from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

import flow_ir as flow
import program_model as pm
import pu_index
import pu_program_model

DEX_FLOW_PRODUCER_VERSION = 1
DEFAULT_METHOD_LIMIT = 12
MAX_METHOD_LIMIT = 32
DEFAULT_ANALYSIS_DEPTH = 3
MAX_ANALYSIS_DEPTH = 8
DEFAULT_INSTRUCTION_LIMIT = 8_000
MAX_INSTRUCTION_LIMIT = 20_000
MAX_CFG_ITERATIONS = 50_000

_TRANSFORM_PREFIXES = (
    "add-", "sub-", "mul-", "div-", "rem-", "and-", "or-", "xor-",
    "shl-", "shr-", "ushr-", "neg-", "not-", "cmp", "int-to-", "long-to-",
    "float-to-", "double-to-", "instance-of", "array-length",
)
_REFLECTION_TARGETS = (
    "Ljava/lang/reflect/Method; invoke ",
    "Ljava/lang/reflect/Constructor; newInstance ",
    "Ljava/lang/Class; forName ",
)


class DexValueTracingError(ValueError):
    pass


def _hash(*parts: str) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(str(part).encode("utf-8", "replace"))
        digest.update(b"\0")
    return digest.hexdigest()


def _bounded(value: Any, name: str, minimum: int, maximum: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise DexValueTracingError(f"invalid {name}") from exc
    if result < minimum or result > maximum:
        raise DexValueTracingError(f"invalid {name}")
    return result


def _descriptor_parameters(descriptor: str) -> tuple[str, ...]:
    value = str(descriptor or "")
    if not value.startswith("(") or ")" not in value:
        return ()
    body = value[1 : value.index(")")]
    result: list[str] = []
    index = 0
    while index < len(body):
        start = index
        while index < len(body) and body[index] == "[":
            index += 1
        if index >= len(body):
            return ()
        if body[index] == "L":
            end = body.find(";", index)
            if end < 0:
                return ()
            index = end + 1
        else:
            index += 1
        result.append(body[start:index])
    return tuple(result)


def _descriptor_return(descriptor: str) -> str:
    value = str(descriptor or "")
    if ")" not in value:
        return ""
    return value[value.index(")") + 1 :]


def _wide(descriptor: str) -> bool:
    return descriptor.lstrip("[") in {"J", "D"} and not descriptor.startswith("[")


def _normalized_field_ref(raw: Any) -> tuple[str | None, str | None]:
    try:
        field = raw.get_field() if hasattr(raw, "get_field") else raw
        class_name = str(field.get_class_name())
        name = str(field.get_name())
        descriptor = str(field.get_descriptor())
        if class_name and name:
            display = f"{pu_index.normalize_class_descriptor(class_name)}.{name}"
            return f"{class_name}->{name}:{descriptor}", display
    except Exception:
        pass
    return None, None


def _operand_registers(instruction: Any, offset: int) -> tuple[int, ...]:
    result: list[int] = []
    try:
        operands = instruction.get_operands(offset)
    except Exception:
        return ()
    for operand in operands or ():
        if not isinstance(operand, tuple) or len(operand) < 2:
            continue
        kind = operand[0]
        kind_name = str(getattr(kind, "name", kind)).upper()
        if "REGISTER" not in kind_name:
            continue
        try:
            result.append(int(operand[1]))
        except (TypeError, ValueError):
            continue
    return tuple(result)


def _literal_fingerprint(instruction: Any, offset: int) -> str | None:
    try:
        operands = instruction.get_operands(offset)
    except Exception:
        return None
    safe_shape: list[str] = []
    has_non_register = False
    for operand in operands or ():
        if not isinstance(operand, tuple) or not operand:
            continue
        kind = operand[0]
        kind_name = str(getattr(kind, "name", kind)).upper()
        if "REGISTER" in kind_name:
            continue
        has_non_register = True
        # This raw material is intentionally kept only inside the producer long
        # enough to hash it. It is never stored in a FlowNode or evidence record.
        safe_shape.append(repr(tuple(operand[1:])))
    if not has_non_register:
        return None
    return "sha256:" + _hash(*safe_shape)


@dataclass(frozen=True)
class ParameterSpec:
    index: int
    register: int
    descriptor: str


@dataclass(frozen=True)
class InstructionSpec:
    offset: int
    mnemonic: str
    registers: tuple[int, ...] = ()
    literal_fingerprint: str | None = None
    call_targets: tuple[str, ...] = ()
    field_ref: str | None = None
    field_name: str | None = None


@dataclass(frozen=True)
class BlockSpec:
    start: int
    instructions: tuple[InstructionSpec, ...]
    successors: tuple[int, ...] = ()


@dataclass(frozen=True)
class MethodSpec:
    private_id: str
    entity_id: str
    class_entity_id: str
    semantic_key: str
    class_name: str
    name: str
    descriptor: str
    ownership: str
    is_static: bool
    is_native: bool
    is_external: bool
    parameters: tuple[ParameterSpec, ...]
    blocks: tuple[BlockSpec, ...]

    @property
    def instruction_count(self) -> int:
        return sum(len(block.instructions) for block in self.blocks)


@dataclass(frozen=True)
class DexFlowAnalysis:
    root_entity_id: str
    document: flow.FlowDocument
    methods_analyzed: int
    instructions_analyzed: int
    truncated: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "dex_flow_producer_version": DEX_FLOW_PRODUCER_VERSION,
            "root_entity_id": self.root_entity_id,
            "methods_analyzed": self.methods_analyzed,
            "instructions_analyzed": self.instructions_analyzed,
            "truncated": self.truncated,
            "flow": self.document.to_dict(),
        }


class NormalizedDexFlowBuilder:
    """Build bounded Flow IR from normalized DEX instructions.

    Register numbers live only in this private producer. Public FlowNode semantic
    keys and labels are hash-derived and never reveal register identifiers.
    """

    def __init__(
        self,
        *,
        snapshot_id: str,
        method_loader: Callable[[str], MethodSpec | None],
        evidence_ref: Callable[[MethodSpec, InstructionSpec | None, str], str],
        method_limit: int = DEFAULT_METHOD_LIMIT,
        analysis_depth: int = DEFAULT_ANALYSIS_DEPTH,
        instruction_limit: int = DEFAULT_INSTRUCTION_LIMIT,
    ) -> None:
        self.snapshot_id = str(snapshot_id)
        self.method_loader = method_loader
        self.evidence_ref = evidence_ref
        self.method_limit = _bounded(method_limit, "method_limit", 1, MAX_METHOD_LIMIT)
        self.analysis_depth = _bounded(
            analysis_depth, "analysis_depth", 0, MAX_ANALYSIS_DEPTH
        )
        self.instruction_limit = _bounded(
            instruction_limit,
            "instruction_limit",
            1,
            MAX_INSTRUCTION_LIMIT,
        )
        self.nodes: dict[str, flow.FlowNode] = {}
        self.edges: dict[str, flow.FlowEdge] = {}
        self.gaps: dict[str, flow.FlowGap] = {}
        self.methods: dict[str, MethodSpec] = {}
        self.analyzed: set[str] = set()
        self.analyzing: set[str] = set()
        self.instructions_analyzed = 0
        self.truncated = False

    def _semantic_key(self, prefix: str, *parts: Any) -> str:
        return f"{prefix}:{_hash(*(str(item) for item in parts))}"

    def _discriminator(self, *parts: Any) -> str:
        return "occurrence:" + _hash(*(str(item) for item in parts))

    def _node(
        self,
        method: MethodSpec,
        *,
        semantic_key: str,
        value_kind: str,
        owner_entity_id: str | None = None,
        properties: dict[str, Any] | None = None,
        evidence_refs: Iterable[str] = (),
    ) -> flow.FlowNode:
        owner = owner_entity_id or method.entity_id
        node_id = flow.flow_node_id(
            self.snapshot_id, value_kind, owner, semantic_key
        )
        item = flow.FlowNode(
            snapshot_id=self.snapshot_id,
            node_id=node_id,
            semantic_key=semantic_key,
            value_kind=value_kind,
            owner_entity_id=owner,
            representation="dex",
            properties=properties or {},
            evidence_refs=tuple(evidence_refs),
        )
        existing = self.nodes.get(item.node_id)
        if existing is not None and existing != item:
            raise DexValueTracingError("conflicting FlowNode identity")
        self.nodes[item.node_id] = item
        return item

    def _parameter_node(self, method: MethodSpec, parameter: ParameterSpec) -> flow.FlowNode:
        return self._node(
            method,
            semantic_key=self._semantic_key(
                "parameter", method.semantic_key, parameter.index
            ),
            value_kind="PARAMETER",
            properties={
                "parameter_index": parameter.index,
                "type": parameter.descriptor,
            },
            evidence_refs=(self.evidence_ref(method, None, "parameter"),),
        )

    def _return_node(self, method: MethodSpec) -> flow.FlowNode:
        return_type = _descriptor_return(method.descriptor)
        props = {"type": return_type} if return_type else {}
        return self._node(
            method,
            semantic_key=self._semantic_key("return", method.semantic_key),
            value_kind="RETURN",
            properties=props,
            evidence_refs=(self.evidence_ref(method, None, "return"),),
        )

    def _local_node(
        self, method: MethodSpec, instruction: InstructionSpec, slot: str = "result"
    ) -> flow.FlowNode:
        return self._node(
            method,
            semantic_key=self._semantic_key(
                "local", method.semantic_key, instruction.offset, slot
            ),
            value_kind="LOCAL",
            evidence_refs=(self.evidence_ref(method, instruction, "definition"),),
        )

    def _argument_node(
        self, method: MethodSpec, instruction: InstructionSpec, index: int
    ) -> flow.FlowNode:
        return self._node(
            method,
            semantic_key=self._semantic_key(
                "argument", method.semantic_key, instruction.offset, index
            ),
            value_kind="ARGUMENT",
            properties={"argument_index": index},
            evidence_refs=(self.evidence_ref(method, instruction, "argument"),),
        )

    def _constant_node(
        self, method: MethodSpec, instruction: InstructionSpec
    ) -> flow.FlowNode:
        properties: dict[str, Any] = {"literal_kind": "dex-constant"}
        if instruction.literal_fingerprint:
            properties["value_fingerprint"] = instruction.literal_fingerprint
        return self._node(
            method,
            semantic_key=flow.constant_semantic_key(
                method.semantic_key,
                str(instruction.offset),
                "constant",
            ),
            value_kind="CONSTANT",
            properties=properties,
            evidence_refs=(self.evidence_ref(method, instruction, "constant"),),
        )

    def _field_node(
        self, method: MethodSpec, instruction: InstructionSpec
    ) -> flow.FlowNode | None:
        if not instruction.field_ref:
            return None
        props: dict[str, Any] = {}
        if instruction.field_name:
            props["field_name"] = instruction.field_name[:1024]
        return self._node(
            method,
            semantic_key=self._semantic_key("field", instruction.field_ref),
            value_kind="FIELD",
            owner_entity_id=method.class_entity_id,
            properties=props,
            evidence_refs=(self.evidence_ref(method, instruction, "field"),),
        )

    def _edge(
        self,
        method: MethodSpec,
        instruction: InstructionSpec | None,
        kind: str,
        source: str,
        target: str,
        *,
        discriminator: str,
        properties: dict[str, Any] | None = None,
    ) -> flow.FlowEdge:
        edge_id = flow.flow_edge_id(
            self.snapshot_id, kind, source, target, discriminator
        )
        evidence = self.evidence_ref(method, instruction, kind.lower())
        item = flow.FlowEdge(
            snapshot_id=self.snapshot_id,
            edge_id=edge_id,
            kind=kind,
            source_node_id=source,
            target_node_id=target,
            representation="dex",
            producer="dex-localized-flow-v1",
            discriminator=discriminator,
            properties=properties or {},
            evidence_refs=(evidence,),
        )
        self.edges[item.edge_id] = item
        return item

    def _gap(
        self,
        method: MethodSpec,
        instruction: InstructionSpec | None,
        kind: str,
        *,
        source: str | None = None,
        target: str | None = None,
        reason: str,
        discriminator: str,
    ) -> flow.FlowGap:
        if source is None and target is None:
            target = self._return_node(method).node_id
        gap_id = flow.flow_gap_id(
            self.snapshot_id,
            kind,
            method.entity_id,
            source,
            target,
            discriminator,
        )
        item = flow.FlowGap(
            snapshot_id=self.snapshot_id,
            gap_id=gap_id,
            kind=kind,
            owner_entity_id=method.entity_id,
            representation="dex",
            producer="dex-localized-flow-v1",
            source_node_id=source,
            target_node_id=target,
            discriminator=discriminator,
            reason=str(reason)[: flow.MAX_TEXT_CHARS],
            evidence_refs=(self.evidence_ref(method, instruction, "gap"),),
        )
        self.gaps[item.gap_id] = item
        return item

    @staticmethod
    def _merge_states(states: Iterable[dict[int, frozenset[str]]]) -> dict[int, frozenset[str]]:
        merged: dict[int, set[str]] = defaultdict(set)
        for state in states:
            for register, definitions in state.items():
                merged[register].update(definitions)
        return {key: frozenset(sorted(value)) for key, value in merged.items() if value}

    def _entry_state(self, method: MethodSpec) -> dict[int, frozenset[str]]:
        state: dict[int, frozenset[str]] = {}
        for parameter in method.parameters:
            node = self._parameter_node(method, parameter)
            state[parameter.register] = frozenset({node.node_id})
            if _wide(parameter.descriptor):
                state[parameter.register + 1] = frozenset({node.node_id})
        return state

    def _definition_target(
        self, method: MethodSpec, instruction: InstructionSpec
    ) -> tuple[int, str] | None:
        name = instruction.mnemonic
        registers = instruction.registers
        if not registers:
            return None
        if (
            name.startswith("move")
            or name.startswith("const")
            or name.startswith("iget")
            or name.startswith("sget")
            or name.startswith(_TRANSFORM_PREFIXES)
            or name in {"new-instance", "new-array", "move-exception"}
        ):
            node = self._local_node(method, instruction)
            return registers[0], node.node_id
        return None

    def _transfer_state(
        self, method: MethodSpec, block: BlockSpec, incoming: dict[int, frozenset[str]]
    ) -> dict[int, frozenset[str]]:
        state = dict(incoming)
        for instruction in block.instructions:
            target = self._definition_target(method, instruction)
            if target is not None:
                state[target[0]] = frozenset({target[1]})
        return state

    def _cfg_states(
        self, method: MethodSpec
    ) -> dict[int, dict[int, frozenset[str]]]:
        blocks = {block.start: block for block in method.blocks}
        if not blocks:
            return {}
        entry = min(blocks)
        predecessors: dict[int, set[int]] = defaultdict(set)
        for block in blocks.values():
            for successor in block.successors:
                if successor in blocks:
                    predecessors[successor].add(block.start)
        incoming: dict[int, dict[int, frozenset[str]]] = {}
        outgoing: dict[int, dict[int, frozenset[str]]] = {}
        queue = deque([entry])
        queued = {entry}
        iterations = 0
        entry_seed = self._entry_state(method)
        while queue:
            iterations += 1
            if iterations > MAX_CFG_ITERATIONS:
                self.truncated = True
                self._gap(
                    method,
                    None,
                    "BUDGET",
                    reason="CFG reaching-definition iteration budget exceeded",
                    discriminator=self._discriminator(method.semantic_key, "cfg-budget"),
                )
                break
            start = queue.popleft()
            queued.discard(start)
            parent_states = [outgoing[parent] for parent in sorted(predecessors[start]) if parent in outgoing]
            merged = self._merge_states(parent_states)
            if start == entry:
                merged = self._merge_states((merged, entry_seed))
            previous_in = incoming.get(start)
            previous_out = outgoing.get(start)
            next_out = self._transfer_state(method, blocks[start], merged)
            if previous_in != merged:
                incoming[start] = merged
            if previous_out != next_out:
                outgoing[start] = next_out
                for successor in sorted(blocks[start].successors):
                    if successor in blocks and successor not in queued:
                        queue.append(successor)
                        queued.add(successor)
        return incoming

    @staticmethod
    def _sources(state: dict[int, frozenset[str]], register: int) -> tuple[str, ...]:
        return tuple(sorted(state.get(register, ())))

    def _link_sources(
        self,
        method: MethodSpec,
        instruction: InstructionSpec,
        sources: Iterable[str],
        target: str,
        kind: str,
        *,
        discriminator_prefix: str,
        properties: dict[str, Any] | None = None,
    ) -> None:
        values = tuple(sorted(set(sources)))
        if not values:
            self._gap(
                method,
                instruction,
                "MISSING_EVIDENCE",
                target=target,
                reason=f"no reaching definition for {instruction.mnemonic}",
                discriminator=self._discriminator(
                    method.semantic_key, instruction.offset, discriminator_prefix, "missing"
                ),
            )
            return
        for ordinal, source in enumerate(values):
            self._edge(
                method,
                instruction,
                kind,
                source,
                target,
                discriminator=self._discriminator(
                    method.semantic_key,
                    instruction.offset,
                    discriminator_prefix,
                    ordinal,
                    source,
                ),
                properties=properties,
            )

    @staticmethod
    def _dispatch_gap_kind(instruction: InstructionSpec) -> str | None:
        name = instruction.mnemonic
        if not name.startswith("invoke-"):
            return None
        if name.startswith(("invoke-virtual", "invoke-interface", "invoke-polymorphic", "invoke-custom", "invoke-super")):
            return "DYNAMIC_DISPATCH"
        if any(target.startswith(prefix) for target in instruction.call_targets for prefix in _REFLECTION_TARGETS):
            return "REFLECTION"
        return None

    def _pending_gap(
        self,
        method: MethodSpec,
        instruction: InstructionSpec,
        kind: str,
        argument_nodes: tuple[flow.FlowNode, ...],
        reason: str,
    ) -> tuple[str, str, tuple[str, ...], str]:
        return (
            "gap",
            kind,
            tuple(item.node_id for item in argument_nodes),
            reason,
        )

    def _call(
        self,
        method: MethodSpec,
        instruction: InstructionSpec,
        state: dict[int, frozenset[str]],
        depth: int,
    ) -> tuple[str, Any] | None:
        registers = instruction.registers
        target_id = instruction.call_targets[0] if len(instruction.call_targets) == 1 else None
        target_method = self.method_loader(target_id) if target_id else None
        if target_method is not None:
            self.methods.setdefault(target_method.private_id, target_method)

        is_static = instruction.mnemonic.startswith("invoke-static")
        declared_registers = registers if is_static else registers[1:]
        argument_nodes: list[flow.FlowNode] = []
        for index, register in enumerate(declared_registers):
            argument = self._argument_node(method, instruction, index)
            argument_nodes.append(argument)
            self._link_sources(
                method,
                instruction,
                self._sources(state, register),
                argument.node_id,
                "FLOWS_TO",
                discriminator_prefix=f"argument:{index}",
                properties={"flow_kind": "argument"},
            )

        dispatch_gap = self._dispatch_gap_kind(instruction)
        if dispatch_gap:
            return self._pending_gap(
                method,
                instruction,
                dispatch_gap,
                tuple(argument_nodes),
                f"{instruction.mnemonic} target is not an exact statically proven implementation",
            )
        if target_method is None:
            return self._pending_gap(
                method,
                instruction,
                "MISSING_EVIDENCE",
                tuple(argument_nodes),
                "exact call target is unavailable",
            )

        parameters = tuple(self._parameter_node(target_method, item) for item in target_method.parameters)
        for index, argument in enumerate(argument_nodes):
            if index >= len(parameters):
                break
            self._edge(
                method,
                instruction,
                "ARGUMENT_TO_PARAMETER",
                argument.node_id,
                parameters[index].node_id,
                discriminator=self._discriminator(
                    method.semantic_key, instruction.offset, "arg-param", index
                ),
                properties={
                    "argument_index": index,
                    "parameter_index": index,
                    "callsite_offset": instruction.offset,
                },
            )

        return_node = self._return_node(target_method)
        if target_method.is_native:
            return self._pending_gap(
                method,
                instruction,
                "NATIVE",
                tuple(argument_nodes),
                "callee implementation is native",
            ) + (return_node.node_id,)
        if target_method.is_external or target_method.ownership in {"THIRD_PARTY", "PLATFORM", "GENERATED"}:
            return self._pending_gap(
                method,
                instruction,
                "EXTERNAL_BOUNDARY",
                tuple(argument_nodes),
                f"callee ownership is {target_method.ownership}",
            ) + (return_node.node_id,)
        if depth >= self.analysis_depth:
            self.truncated = True
            return self._pending_gap(
                method,
                instruction,
                "BUDGET",
                tuple(argument_nodes),
                "interprocedural analysis depth limit reached",
            ) + (return_node.node_id,)
        if target_method.private_id not in self.analyzed and target_method.private_id not in self.analyzing:
            if len(self.analyzed | self.analyzing) >= self.method_limit:
                self.truncated = True
                return self._pending_gap(
                    method,
                    instruction,
                    "BUDGET",
                    tuple(argument_nodes),
                    "localized method limit reached",
                ) + (return_node.node_id,)
            if self.instructions_analyzed + target_method.instruction_count > self.instruction_limit:
                self.truncated = True
                return self._pending_gap(
                    method,
                    instruction,
                    "BUDGET",
                    tuple(argument_nodes),
                    "localized instruction limit reached",
                ) + (return_node.node_id,)
            self._analyze_method(target_method, depth + 1)
        return ("return", return_node.node_id)

    def _emit_block(
        self,
        method: MethodSpec,
        block: BlockSpec,
        incoming: dict[int, frozenset[str]],
        depth: int,
    ) -> None:
        state = dict(incoming)
        pending: tuple[Any, ...] | None = None
        for instruction in block.instructions:
            name = instruction.mnemonic
            registers = instruction.registers
            if not name.startswith("move-result") and not name.startswith("invoke-"):
                pending = None

            if name.startswith("move-result"):
                if not registers:
                    continue
                target = self._local_node(method, instruction)
                state[registers[0]] = frozenset({target.node_id})
                if pending and pending[0] == "return":
                    self._edge(
                        method,
                        instruction,
                        "RETURN_TO_CALLSITE",
                        str(pending[1]),
                        target.node_id,
                        discriminator=self._discriminator(
                            method.semantic_key, instruction.offset, "return-callsite"
                        ),
                        properties={"callsite_offset": instruction.offset},
                    )
                elif pending and pending[0] == "gap":
                    _, gap_kind, sources, reason, *return_ids = pending
                    gap_target = str(return_ids[0]) if return_ids else target.node_id
                    if sources:
                        for ordinal, source in enumerate(sources):
                            self._gap(
                                method,
                                instruction,
                                str(gap_kind),
                                source=str(source),
                                target=gap_target,
                                reason=str(reason),
                                discriminator=self._discriminator(
                                    method.semantic_key,
                                    instruction.offset,
                                    "call-gap",
                                    ordinal,
                                ),
                            )
                    else:
                        self._gap(
                            method,
                            instruction,
                            str(gap_kind),
                            target=gap_target,
                            reason=str(reason),
                            discriminator=self._discriminator(
                                method.semantic_key, instruction.offset, "call-gap"
                            ),
                        )
                    if return_ids:
                        self._edge(
                            method,
                            instruction,
                            "RETURN_TO_CALLSITE",
                            gap_target,
                            target.node_id,
                            discriminator=self._discriminator(
                                method.semantic_key,
                                instruction.offset,
                                "boundary-return-callsite",
                            ),
                            properties={"callsite_offset": instruction.offset},
                        )
                else:
                    self._gap(
                        method,
                        instruction,
                        "MISSING_EVIDENCE",
                        target=target.node_id,
                        reason="move-result has no normalized invoke result",
                        discriminator=self._discriminator(
                            method.semantic_key, instruction.offset, "orphan-move-result"
                        ),
                    )
                pending = None
                continue

            if name.startswith("invoke-"):
                pending = self._call(method, instruction, state, depth)
                continue

            if name.startswith("move") and registers:
                target = self._local_node(method, instruction)
                state[registers[0]] = frozenset({target.node_id})
                if len(registers) >= 2:
                    self._link_sources(
                        method,
                        instruction,
                        self._sources(state, registers[1]),
                        target.node_id,
                        "ASSIGNMENT",
                        discriminator_prefix="move",
                        properties={"statement_offset": instruction.offset},
                    )
                continue

            if name.startswith("const") and registers:
                constant = self._constant_node(method, instruction)
                target = self._local_node(method, instruction)
                state[registers[0]] = frozenset({target.node_id})
                self._edge(
                    method,
                    instruction,
                    "CONSTANT_TO_VALUE",
                    constant.node_id,
                    target.node_id,
                    discriminator=self._discriminator(
                        method.semantic_key, instruction.offset, "constant"
                    ),
                    properties={"statement_offset": instruction.offset},
                )
                continue

            if name.startswith(("iget", "sget")) and registers:
                target = self._local_node(method, instruction)
                state[registers[0]] = frozenset({target.node_id})
                field = self._field_node(method, instruction)
                if field is None:
                    self._gap(
                        method,
                        instruction,
                        "MISSING_EVIDENCE",
                        target=target.node_id,
                        reason="field read target is unresolved",
                        discriminator=self._discriminator(
                            method.semantic_key, instruction.offset, "field-read"
                        ),
                    )
                else:
                    self._edge(
                        method,
                        instruction,
                        "FIELD_READ",
                        field.node_id,
                        target.node_id,
                        discriminator=self._discriminator(
                            method.semantic_key, instruction.offset, "field-read"
                        ),
                        properties={
                            "field_name": instruction.field_name or "",
                            "access_offset": instruction.offset,
                        },
                    )
                continue

            if name.startswith(("iput", "sput")) and registers:
                field = self._field_node(method, instruction)
                if field is None:
                    sources = self._sources(state, registers[0])
                    for ordinal, source in enumerate(sources or (None,)):
                        self._gap(
                            method,
                            instruction,
                            "MISSING_EVIDENCE",
                            source=source,
                            reason="field write target is unresolved",
                            discriminator=self._discriminator(
                                method.semantic_key, instruction.offset, "field-write", ordinal
                            ),
                        )
                else:
                    self._link_sources(
                        method,
                        instruction,
                        self._sources(state, registers[0]),
                        field.node_id,
                        "FIELD_WRITE",
                        discriminator_prefix="field-write",
                        properties={
                            "field_name": instruction.field_name or "",
                            "access_offset": instruction.offset,
                        },
                    )
                continue

            if name.startswith(_TRANSFORM_PREFIXES) and registers:
                target = self._local_node(method, instruction)
                source_registers = registers[1:]
                state[registers[0]] = frozenset({target.node_id})
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
                for source_index, register in enumerate(source_registers):
                    self._link_sources(
                        method,
                        instruction,
                        self._sources(state, register),
                        target.node_id,
                        "TRANSFORMS",
                        discriminator_prefix=f"transform:{source_index}",
                        properties={"transform_kind": name[:256]},
                    )
                continue

            if name.startswith("return") and name != "return-void":
                return_node = self._return_node(method)
                if registers:
                    self._link_sources(
                        method,
                        instruction,
                        self._sources(state, registers[0]),
                        return_node.node_id,
                        "FLOWS_TO",
                        discriminator_prefix="return",
                        properties={"flow_kind": "return"},
                    )
                else:
                    self._gap(
                        method,
                        instruction,
                        "MISSING_EVIDENCE",
                        target=return_node.node_id,
                        reason="return operand is unavailable",
                        discriminator=self._discriminator(
                            method.semantic_key, instruction.offset, "return"
                        ),
                    )
                continue

            if name.startswith(("aget", "aput")) or name in {"filled-new-array", "fill-array-data", "move-exception"}:
                target: str | None = None
                definition = self._definition_target(method, instruction)
                if definition is not None:
                    state[definition[0]] = frozenset({definition[1]})
                    target = definition[1]
                source: str | None = None
                for register in registers[1:] if definition else registers:
                    values = self._sources(state, register)
                    if values:
                        source = values[0]
                        break
                self._gap(
                    method,
                    instruction,
                    "UNSUPPORTED_INSTRUCTION",
                    source=source,
                    target=target,
                    reason=f"{name} value semantics are not yet normalized",
                    discriminator=self._discriminator(
                        method.semantic_key, instruction.offset, "unsupported", name
                    ),
                )

    def _analyze_method(self, method: MethodSpec, depth: int) -> None:
        if method.private_id in self.analyzed or method.private_id in self.analyzing:
            return
        self.methods.setdefault(method.private_id, method)
        self._return_node(method)
        for parameter in method.parameters:
            self._parameter_node(method, parameter)
        if method.is_external:
            self._gap(
                method,
                None,
                "EXTERNAL_BOUNDARY",
                reason="method body is external",
                discriminator=self._discriminator(method.semantic_key, "external-body"),
            )
            self.analyzed.add(method.private_id)
            return
        if method.is_native:
            self._gap(
                method,
                None,
                "NATIVE",
                reason="method body is native",
                discriminator=self._discriminator(method.semantic_key, "native-body"),
            )
            self.analyzed.add(method.private_id)
            return
        if self.instructions_analyzed + method.instruction_count > self.instruction_limit:
            self.truncated = True
            self._gap(
                method,
                None,
                "BUDGET",
                reason="localized instruction limit reached before method analysis",
                discriminator=self._discriminator(method.semantic_key, "instruction-budget"),
            )
            return
        self.analyzing.add(method.private_id)
        self.instructions_analyzed += method.instruction_count
        try:
            incoming = self._cfg_states(method)
            for block in sorted(method.blocks, key=lambda item: item.start):
                if block.start not in incoming and block.start != min(
                    (item.start for item in method.blocks), default=block.start
                ):
                    continue
                self._emit_block(method, block, incoming.get(block.start, {}), depth)
        finally:
            self.analyzing.discard(method.private_id)
            self.analyzed.add(method.private_id)

    def build(self, root_private_id: str) -> DexFlowAnalysis:
        root = self.method_loader(root_private_id)
        if root is None:
            raise DexValueTracingError("root function is unavailable to DEX flow producer")
        self.methods[root.private_id] = root
        self._analyze_method(root, 0)
        document = flow.FlowDocument(
            snapshot_id=self.snapshot_id,
            nodes=tuple(self.nodes.values()),
            edges=tuple(self.edges.values()),
            gaps=tuple(self.gaps.values()),
        )
        return DexFlowAnalysis(
            root_entity_id=root.entity_id,
            document=document,
            methods_analyzed=len(self.analyzed),
            instructions_analyzed=self.instructions_analyzed,
            truncated=self.truncated,
        )


class AndroguardMethodLoader:
    def __init__(
        self,
        analysis: Any,
        provider: pu_program_model.DexProgramProvider,
        class_members: dict[str, str],
    ) -> None:
        self.analysis = analysis
        self.provider = provider
        self.class_members = class_members
        self._methods: dict[str, Any] = {}
        self._cache: dict[str, MethodSpec] = {}
        for method in analysis.get_methods():
            record = pu_index.method_record(method, class_members)
            self._methods[str(record["id"])] = method

    def _entity(self, method: Any) -> pm.ProgramEntity:
        record = pu_index.method_record(method, self.class_members)
        return self.provider._function_entity(record)

    def _parameter_specs(self, method: Any) -> tuple[ParameterSpec, ...]:
        raw = method.get_method() if hasattr(method, "get_method") else method
        code = raw.get_code() if hasattr(raw, "get_code") else None
        if code is None:
            return ()
        descriptor = str(raw.get_descriptor())
        parameters = _descriptor_parameters(descriptor)
        try:
            start = int(code.get_registers_size()) - int(code.get_ins_size())
        except Exception:
            return ()
        access = str(raw.get_access_flags_string())
        is_static = "static" in access.split()
        if not is_static:
            start += 1
        result: list[ParameterSpec] = []
        register = start
        for index, parameter in enumerate(parameters):
            result.append(ParameterSpec(index, register, parameter))
            register += 2 if _wide(parameter) else 1
        return tuple(result)

    @staticmethod
    def _field_maps(method: Any) -> tuple[dict[int, tuple[str, str]], dict[int, tuple[str, str]]]:
        reads: dict[int, tuple[str, str]] = {}
        writes: dict[int, tuple[str, str]] = {}
        for _, field, offset in method.get_xref_read() if hasattr(method, "get_xref_read") else ():
            ref, name = _normalized_field_ref(field)
            if ref and name:
                reads[int(offset)] = (ref, name)
        for _, field, offset in method.get_xref_write() if hasattr(method, "get_xref_write") else ():
            ref, name = _normalized_field_ref(field)
            if ref and name:
                writes[int(offset)] = (ref, name)
        return reads, writes

    def _blocks(self, method: Any) -> tuple[BlockSpec, ...]:
        calls: dict[int, set[str]] = defaultdict(set)
        for _, target, offset in method.get_xref_to() if hasattr(method, "get_xref_to") else ():
            record = pu_index.method_record(target, self.class_members)
            calls[int(offset)].add(str(record["id"]))
        reads, writes = self._field_maps(method)
        blocks: list[BlockSpec] = []
        basic_blocks = method.get_basic_blocks() if hasattr(method, "get_basic_blocks") else None
        candidates = basic_blocks.gets() if basic_blocks is not None and hasattr(basic_blocks, "gets") else ()
        for block in sorted(candidates, key=lambda item: int(item.get_start())):
            offset = int(block.get_start())
            instructions: list[InstructionSpec] = []
            for instruction in block.get_instructions():
                mnemonic = str(instruction.get_name()).strip().lower()
                field = reads.get(offset) or writes.get(offset)
                instructions.append(
                    InstructionSpec(
                        offset=offset,
                        mnemonic=mnemonic,
                        registers=_operand_registers(instruction, offset),
                        literal_fingerprint=(
                            _literal_fingerprint(instruction, offset)
                            if mnemonic.startswith("const")
                            else None
                        ),
                        call_targets=tuple(sorted(calls.get(offset, ()))),
                        field_ref=field[0] if field else None,
                        field_name=field[1] if field else None,
                    )
                )
                try:
                    offset += int(instruction.get_length())
                except Exception:
                    offset += 2
            successors: set[int] = set()
            for child in getattr(block, "childs", ()) or ():
                try:
                    target = child[2]
                    successors.add(int(target.get_start()))
                except Exception:
                    continue
            blocks.append(
                BlockSpec(
                    start=int(block.get_start()),
                    instructions=tuple(instructions),
                    successors=tuple(sorted(successors)),
                )
            )
        return tuple(blocks)

    def load(self, private_id: str | None) -> MethodSpec | None:
        if not private_id:
            return None
        if private_id in self._cache:
            return self._cache[private_id]
        method = self._methods.get(private_id)
        if method is None:
            return None
        entity = self._entity(method)
        raw = method.get_method() if hasattr(method, "get_method") else method
        class_name = pu_index.normalize_class_descriptor(
            getattr(method, "class_name", None)
            or raw.get_class_name()
        )
        class_key = self.provider.class_key(class_name)
        class_entity_id = pm.entity_id(self.provider.snapshot, "CLASS", class_key)
        access = str(raw.get_access_flags_string())
        item = MethodSpec(
            private_id=private_id,
            entity_id=entity.entity_id,
            class_entity_id=class_entity_id,
            semantic_key=entity.semantic_key,
            class_name=class_name,
            name=str(raw.get_name()),
            descriptor=str(raw.get_descriptor()),
            ownership=entity.ownership,
            is_static="static" in access.split(),
            is_native="native" in access.split(),
            is_external=bool(method.is_external()) if hasattr(method, "is_external") else False,
            parameters=self._parameter_specs(method),
            blocks=self._blocks(method),
        )
        self._cache[private_id] = item
        return item


def build_dex_flow(
    job: Path,
    workspace: Path,
    caps: dict[str, Any],
    *,
    entity_id: str,
    method_limit: int = DEFAULT_METHOD_LIMIT,
    analysis_depth: int = DEFAULT_ANALYSIS_DEPTH,
    instruction_limit: int = DEFAULT_INSTRUCTION_LIMIT,
) -> DexFlowAnalysis:
    provider = pu_program_model.DexProgramProvider(job, workspace, caps)
    with pu_index.connect(job) as conn:
        row, truncated_lookup = provider._find_function_row(conn, str(entity_id))
    if row is None:
        if truncated_lookup:
            raise DexValueTracingError("canonical function lookup exceeded provider budget")
        raise DexValueTracingError("canonical function entity not found")
    root_private_id = str(row["id"])
    artifact = pu_index.artifact(job, workspace)
    with pu_index.androguard_analysis(artifact) as (analysis, class_members):
        loader = AndroguardMethodLoader(analysis, provider, class_members)

        def evidence(method: MethodSpec, instruction: InstructionSpec | None, kind: str) -> str:
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

        builder = NormalizedDexFlowBuilder(
            snapshot_id=provider.snapshot.snapshot_id,
            method_loader=loader.load,
            evidence_ref=evidence,
            method_limit=method_limit,
            analysis_depth=analysis_depth,
            instruction_limit=instruction_limit,
        )
        return builder.build(root_private_id)


def descriptor() -> dict[str, Any]:
    return {
        "dex_flow_producer_version": DEX_FLOW_PRODUCER_VERSION,
        "flow_ir_version": flow.FLOW_IR_VERSION,
        "backend": "androguard-structured-bytecode",
        "persistent_flow_storage": False,
        "raw_constants_emitted": False,
        "calls_xref_are_data_flow": False,
        "cfg_reaching_definitions": True,
        "explicit_flow_gaps": True,
        "method_limit_max": MAX_METHOD_LIMIT,
        "analysis_depth_max": MAX_ANALYSIS_DEPTH,
        "instruction_limit_max": MAX_INSTRUCTION_LIMIT,
    }
