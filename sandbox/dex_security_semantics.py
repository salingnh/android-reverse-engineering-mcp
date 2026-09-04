from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import dex_value_tracing as dexflow
import dex_value_tracing_runtime as dexruntime
import flow_ir as flow
import program_model as pm
import pu_index
import pu_program_model
import security_semantics as security

DEX_SECURITY_PRODUCER_VERSION = 1
MAX_MARKER_SITES = 512
MAX_REACHABILITY_STATES = 4096

SAFE_LITERAL_MARKERS = {
    "authorization": "authorization",
    "bearer": "bearer",
    "x-api-key": "api_key",
    "api-key": "api_key",
    "api_key": "api_key",
    "apikey": "api_key",
    "refresh_token": "refresh_token",
    "access_token": "access_token",
    "x-signature": "signature",
    "signature": "signature",
    "x-signature-v1": "signature",
}

HTTP_HEADER_CONTRACTS = frozenset(
    {
        ("okhttp3.Request$Builder", "header"),
        ("okhttp3.Request$Builder", "addHeader"),
        ("okhttp3.Headers$Builder", "add"),
        ("java.net.HttpURLConnection", "setRequestProperty"),
        ("java.net.HttpURLConnection", "addRequestProperty"),
    }
)
HTTP_QUERY_CONTRACTS = frozenset(
    {
        ("okhttp3.HttpUrl$Builder", "addQueryParameter"),
        ("okhttp3.HttpUrl$Builder", "setQueryParameter"),
        ("okhttp3.HttpUrl$Builder", "addEncodedQueryParameter"),
        ("okhttp3.FormBody$Builder", "add"),
        ("okhttp3.FormBody$Builder", "addEncoded"),
    }
)
TOKEN_STORAGE_CONTRACTS = frozenset(
    {
        ("android.content.SharedPreferences", "getString"),
        ("androidx.security.crypto.EncryptedSharedPreferences", "getString"),
    }
)
IDENTITY_PREFIXES = (
    "com.google.firebase.auth.",
    "com.google.android.gms.auth.",
)
PAYMENT_PREFIXES = (
    "com.stripe.",
    "com.braintreepayments.",
    "com.paypal.",
)


class DexSecuritySemanticsError(ValueError):
    pass


@dataclass(frozen=True)
class DexSecurityAnalysis:
    flow_analysis: dexflow.DexFlowAnalysis
    overlay: security.SecurityOverlay

    def to_dict(self) -> dict[str, Any]:
        return {
            "dex_security_producer_version": DEX_SECURITY_PRODUCER_VERSION,
            "root_entity_id": self.flow_analysis.root_entity_id,
            "methods_analyzed": self.flow_analysis.methods_analyzed,
            "instructions_analyzed": self.flow_analysis.instructions_analyzed,
            "analysis_truncated": self.flow_analysis.truncated,
            "overlay": self.overlay.to_dict(),
        }


def _normalize_literal(value: str) -> set[str]:
    text = value.strip().strip("\"'").strip()
    lowered = text.lower()
    result: set[str] = set()
    marker = SAFE_LITERAL_MARKERS.get(lowered)
    if marker:
        result.add(marker)
    upper = text.upper()
    if upper.startswith("HMAC") and len(text) <= 64:
        result.add("hmac")
    if (upper == "AES" or upper.startswith("AES/")) and len(text) <= 96:
        result.add("aes")
    return result


def safe_literal_markers(instruction: Any, offset: int) -> tuple[str, ...]:
    """Return allowlisted categories from structured operands without retaining raw text."""
    try:
        operands = instruction.get_operands(offset)
    except Exception:
        return ()
    result: set[str] = set()
    for operand in operands or ():
        if not isinstance(operand, tuple):
            continue
        for item in operand[1:]:
            if isinstance(item, str):
                result.update(_normalize_literal(item))
    return tuple(sorted(result))


def _constant_node_id(
    snapshot_id: str,
    method: dexflow.MethodSpec,
    instruction: dexflow.InstructionSpec,
) -> str:
    key = flow.constant_semantic_key(method.semantic_key, str(instruction.offset), "constant")
    return flow.flow_node_id(snapshot_id, "CONSTANT", method.entity_id, key)


def _argument_node_id(
    snapshot_id: str,
    method: dexflow.MethodSpec,
    offset: int,
    index: int,
) -> str:
    key = f"argument:{dexflow._hash(method.semantic_key, offset, index)}"
    return flow.flow_node_id(snapshot_id, "ARGUMENT", method.entity_id, key)


def _return_node_id(snapshot_id: str, method: dexflow.MethodSpec) -> str:
    key = f"return:{dexflow._hash(method.semantic_key)}"
    return flow.flow_node_id(snapshot_id, "RETURN", method.entity_id, key)


def _unknown_call_result_node_id(
    snapshot_id: str,
    method: dexflow.MethodSpec,
    offset: int,
) -> str:
    key = f"call-result:{dexflow._hash(method.semantic_key, offset)}"
    return flow.flow_node_id(snapshot_id, "UNKNOWN", method.entity_id, key)


def _semantic_argument_count(instruction: dexflow.InstructionSpec) -> int:
    registers = instruction.registers
    if instruction.mnemonic.startswith("invoke-static"):
        return len(registers)
    return max(0, len(registers) - 1)


def _method_contract(method: dexflow.MethodSpec | None) -> tuple[str, str] | None:
    if method is None:
        return None
    return method.class_name, method.name


def _edge_graph(document: flow.FlowDocument) -> dict[str, tuple[str, ...]]:
    outgoing: dict[str, set[str]] = defaultdict(set)
    for edge in document.edges:
        outgoing[edge.source_node_id].add(edge.target_node_id)
    return {key: tuple(sorted(values)) for key, values in outgoing.items()}


def _reaches(
    graph: dict[str, tuple[str, ...]], source: str, target: str, *, max_depth: int = 12
) -> bool:
    if source == target:
        return True
    queue = deque([(source, 0)])
    seen = {source}
    states = 0
    while queue:
        node, depth = queue.popleft()
        states += 1
        if states > MAX_REACHABILITY_STATES:
            return False
        if depth >= max_depth:
            continue
        for child in graph.get(node, ()):
            if child == target:
                return True
            if child not in seen:
                seen.add(child)
                queue.append((child, depth + 1))
    return False


def _call_gaps(
    document: flow.FlowDocument,
    argument_ids: Iterable[str],
    result_id: str,
) -> tuple[flow.FlowGap, ...]:
    arguments = set(argument_ids)
    result = [
        item
        for item in document.gaps
        if item.target_node_id == result_id
        and (item.source_node_id is None or item.source_node_id in arguments)
    ]
    return tuple(sorted(result, key=lambda item: item.gap_id))


def _signal(
    document: flow.FlowDocument,
    *,
    kind: str,
    owner_entity_id: str,
    anchor_type: str,
    anchor_id: str,
    discriminator: str = "",
    properties: dict[str, str] | None = None,
    evidence_refs: Iterable[str] = (),
) -> security.SecuritySignal:
    return security.SecuritySignal(
        snapshot_id=document.snapshot_id,
        signal_id=security.security_signal_id(
            document.snapshot_id, kind, anchor_type, anchor_id, discriminator
        ),
        kind=kind,
        owner_entity_id=owner_entity_id,
        representation="dex",
        anchor_type=anchor_type,
        anchor_id=anchor_id,
        producer="dex-security-semantics-v1",
        discriminator=discriminator,
        properties=properties or {},
        evidence_refs=tuple(evidence_refs),
    )


def _markers_reaching_argument(
    graph: dict[str, tuple[str, ...]],
    marker_nodes: dict[str, set[str]],
    argument_id: str,
) -> set[str]:
    result: set[str] = set()
    for marker, nodes in marker_nodes.items():
        if any(_reaches(graph, node_id, argument_id) for node_id in nodes):
            result.add(marker)
    return result


def build_overlay(
    document: flow.FlowDocument,
    methods: dict[str, dexflow.MethodSpec],
    marker_sites: dict[tuple[str, int], tuple[str, ...]],
) -> security.SecurityOverlay:
    node_ids = {item.node_id for item in document.nodes}
    graph = _edge_graph(document)
    signals: dict[str, security.SecuritySignal] = {}
    marker_nodes: dict[str, set[str]] = defaultdict(set)

    def add(item: security.SecuritySignal) -> None:
        if len(signals) >= security.MAX_SECURITY_SIGNALS and item.signal_id not in signals:
            return
        signals[item.signal_id] = item

    for method in sorted(methods.values(), key=lambda item: item.private_id):
        for block in method.blocks:
            for instruction in block.instructions:
                site_markers = marker_sites.get((method.private_id, instruction.offset), ())
                if not site_markers or not instruction.mnemonic.startswith("const"):
                    continue
                constant_id = _constant_node_id(document.snapshot_id, method, instruction)
                if constant_id not in node_ids:
                    continue
                for marker in site_markers:
                    marker_nodes[marker].add(constant_id)
                    if marker == "bearer":
                        add(
                            _signal(
                                document,
                                kind="BEARER_SCHEME_MARKER",
                                owner_entity_id=method.entity_id,
                                anchor_type="FLOW_NODE",
                                anchor_id=constant_id,
                                discriminator=f"marker:{instruction.offset}:bearer",
                                properties={"token_kind": "bearer"},
                            )
                        )
                    elif marker in {"hmac", "aes"}:
                        add(
                            _signal(
                                document,
                                kind="CRYPTO_ALGORITHM_MARKER",
                                owner_entity_id=method.entity_id,
                                anchor_type="FLOW_NODE",
                                anchor_id=constant_id,
                                discriminator=f"marker:{instruction.offset}:{marker}",
                                properties={"family": marker},
                            )
                        )

    global_markers = {key for key, values in marker_nodes.items() if values}

    for method in sorted(methods.values(), key=lambda item: item.private_id):
        for block in method.blocks:
            for instruction in block.instructions:
                if not instruction.mnemonic.startswith("invoke-"):
                    continue
                target = (
                    methods.get(instruction.call_targets[0])
                    if len(instruction.call_targets) == 1
                    else None
                )
                contract = _method_contract(target)
                if contract is None:
                    continue
                class_name, name = contract
                count = _semantic_argument_count(instruction)
                arguments = [
                    _argument_node_id(document.snapshot_id, method, instruction.offset, index)
                    for index in range(count)
                ]
                arguments = [item for item in arguments if item in node_ids]
                result_id = (
                    _return_node_id(document.snapshot_id, target)
                    if target is not None
                    else _unknown_call_result_node_id(
                        document.snapshot_id, method, instruction.offset
                    )
                )
                gaps = _call_gaps(document, arguments, result_id)

                if arguments and contract in HTTP_HEADER_CONTRACTS:
                    name_markers = _markers_reaching_argument(
                        graph, marker_nodes, arguments[0]
                    )
                    if len(arguments) >= 2:
                        value_id = arguments[1]
                        for marker, kind in (
                            ("authorization", "AUTHORIZATION_HEADER_SINK"),
                            ("api_key", "API_KEY_HEADER_SINK"),
                            ("signature", "SIGNATURE_HEADER_SINK"),
                        ):
                            if marker in name_markers:
                                add(
                                    _signal(
                                        document,
                                        kind=kind,
                                        owner_entity_id=method.entity_id,
                                        anchor_type="FLOW_NODE",
                                        anchor_id=value_id,
                                        discriminator=f"{class_name}.{name}:{instruction.offset}:{marker}",
                                        properties={
                                            "channel": "header",
                                            "contract": f"{class_name}.{name}"[: security.MAX_SECURITY_TEXT],
                                        },
                                    )
                                )

                if arguments and contract in HTTP_QUERY_CONTRACTS:
                    name_markers = _markers_reaching_argument(
                        graph, marker_nodes, arguments[0]
                    )
                    if len(arguments) >= 2:
                        value_id = arguments[1]
                        if "api_key" in name_markers:
                            add(
                                _signal(
                                    document,
                                    kind="API_KEY_QUERY_SINK",
                                    owner_entity_id=method.entity_id,
                                    anchor_type="FLOW_NODE",
                                    anchor_id=value_id,
                                    discriminator=f"{class_name}.{name}:{instruction.offset}:api-key",
                                    properties={"channel": "query", "contract": f"{class_name}.{name}"},
                                )
                            )
                        if "signature" in name_markers:
                            add(
                                _signal(
                                    document,
                                    kind="SIGNATURE_QUERY_SINK",
                                    owner_entity_id=method.entity_id,
                                    anchor_type="FLOW_NODE",
                                    anchor_id=value_id,
                                    discriminator=f"{class_name}.{name}:{instruction.offset}:signature",
                                    properties={"channel": "query", "contract": f"{class_name}.{name}"},
                                )
                            )
                        if "refresh_token" in name_markers:
                            add(
                                _signal(
                                    document,
                                    kind="TOKEN_EXCHANGE_SINK",
                                    owner_entity_id=method.entity_id,
                                    anchor_type="FLOW_NODE",
                                    anchor_id=value_id,
                                    discriminator=f"{class_name}.{name}:{instruction.offset}:refresh-token",
                                    properties={"token_kind": "refresh_token", "contract": f"{class_name}.{name}"},
                                )
                            )

                if arguments and contract in TOKEN_STORAGE_CONTRACTS and gaps:
                    key_markers = _markers_reaching_argument(
                        graph, marker_nodes, arguments[0]
                    )
                    source_kind = None
                    token_kind = None
                    if "refresh_token" in key_markers:
                        source_kind = "REFRESH_TOKEN_SOURCE_BOUNDARY"
                        token_kind = "refresh_token"
                    elif "access_token" in key_markers:
                        source_kind = "TOKEN_SOURCE_BOUNDARY"
                        token_kind = "access_token"
                    if source_kind:
                        gap = gaps[0]
                        add(
                            _signal(
                                document,
                                kind=source_kind,
                                owner_entity_id=method.entity_id,
                                anchor_type="FLOW_GAP",
                                anchor_id=gap.gap_id,
                                discriminator=f"storage:{instruction.offset}:{token_kind}",
                                properties={"token_kind": token_kind, "boundary_kind": "storage"},
                                evidence_refs=gap.evidence_refs,
                            )
                        )

                if class_name.startswith(IDENTITY_PREFIXES) and gaps:
                    gap = gaps[0]
                    add(
                        _signal(
                            document,
                            kind="IDENTITY_SDK_BOUNDARY",
                            owner_entity_id=method.entity_id,
                            anchor_type="FLOW_GAP",
                            anchor_id=gap.gap_id,
                            discriminator=f"identity:{instruction.offset}",
                            properties={"provider": "firebase" if class_name.startswith("com.google.firebase.auth.") else "google", "boundary_kind": "identity_sdk"},
                            evidence_refs=gap.evidence_refs,
                        )
                    )
                    if name in {"getIdToken", "getToken", "getAccessToken"}:
                        add(
                            _signal(
                                document,
                                kind="TOKEN_SOURCE_BOUNDARY",
                                owner_entity_id=method.entity_id,
                                anchor_type="FLOW_GAP",
                                anchor_id=gap.gap_id,
                                discriminator=f"identity-token:{instruction.offset}",
                                properties={"token_kind": "access_token", "boundary_kind": "identity_sdk"},
                                evidence_refs=gap.evidence_refs,
                            )
                        )

                if class_name.startswith(PAYMENT_PREFIXES) and gaps:
                    gap = gaps[0]
                    provider = "stripe" if class_name.startswith("com.stripe.") else "braintree" if class_name.startswith("com.braintreepayments.") else "paypal"
                    add(
                        _signal(
                            document,
                            kind="PAYMENT_SDK_BOUNDARY",
                            owner_entity_id=method.entity_id,
                            anchor_type="FLOW_GAP",
                            anchor_id=gap.gap_id,
                            discriminator=f"payment:{instruction.offset}",
                            properties={"provider": provider, "boundary_kind": "payment_sdk"},
                            evidence_refs=gap.evidence_refs,
                        )
                    )

                if class_name == "javax.crypto.Mac":
                    if name == "init" and arguments:
                        add(_signal(document, kind="HMAC_KEY_INPUT", owner_entity_id=method.entity_id, anchor_type="FLOW_NODE", anchor_id=arguments[0], discriminator=f"mac-init:{instruction.offset}", properties={"family": "hmac", "contract": "javax.crypto.Mac.init"}))
                    if name in {"update", "doFinal"} and arguments:
                        add(_signal(document, kind="HMAC_PAYLOAD_INPUT", owner_entity_id=method.entity_id, anchor_type="FLOW_NODE", anchor_id=arguments[0], discriminator=f"mac-payload:{instruction.offset}", properties={"family": "hmac", "contract": f"javax.crypto.Mac.{name}"}))
                    if name == "doFinal" and gaps:
                        gap = gaps[0]
                        add(_signal(document, kind="HMAC_OUTPUT_BOUNDARY", owner_entity_id=method.entity_id, anchor_type="FLOW_GAP", anchor_id=gap.gap_id, discriminator=f"mac-output:{instruction.offset}", properties={"family": "hmac", "boundary_kind": "crypto"}, evidence_refs=gap.evidence_refs))

                if class_name == "javax.crypto.spec.IvParameterSpec" and name == "<init>" and arguments:
                    add(_signal(document, kind="CRYPTO_IV_INPUT", owner_entity_id=method.entity_id, anchor_type="FLOW_NODE", anchor_id=arguments[0], discriminator=f"iv:{instruction.offset}", properties={"family": "aes", "contract": "javax.crypto.spec.IvParameterSpec.<init>"}))
                if class_name == "javax.crypto.spec.GCMParameterSpec" and name == "<init>" and len(arguments) >= 2:
                    add(_signal(document, kind="CRYPTO_IV_INPUT", owner_entity_id=method.entity_id, anchor_type="FLOW_NODE", anchor_id=arguments[1], discriminator=f"gcm-nonce:{instruction.offset}", properties={"family": "aes", "variant": "gcm", "contract": "javax.crypto.spec.GCMParameterSpec.<init>"}))

                if class_name == "javax.crypto.Cipher" and "aes" in global_markers:
                    if name == "init" and len(arguments) >= 2:
                        add(_signal(document, kind="CRYPTO_KEY_INPUT", owner_entity_id=method.entity_id, anchor_type="FLOW_NODE", anchor_id=arguments[1], discriminator=f"cipher-key:{instruction.offset}", properties={"family": "aes", "contract": "javax.crypto.Cipher.init"}))
                    if name in {"update", "doFinal"} and arguments:
                        add(_signal(document, kind="AES_PAYLOAD_INPUT", owner_entity_id=method.entity_id, anchor_type="FLOW_NODE", anchor_id=arguments[0], discriminator=f"cipher-payload:{instruction.offset}", properties={"family": "aes", "contract": f"javax.crypto.Cipher.{name}"}))
                    if name == "doFinal" and gaps:
                        gap = gaps[0]
                        add(_signal(document, kind="AES_OUTPUT_BOUNDARY", owner_entity_id=method.entity_id, anchor_type="FLOW_GAP", anchor_id=gap.gap_id, discriminator=f"cipher-output:{instruction.offset}", properties={"family": "aes", "boundary_kind": "crypto"}, evidence_refs=gap.evidence_refs))

    overlay = security.SecurityOverlay(document.snapshot_id, tuple(signals.values()))
    overlay.validate_anchors(document)
    return overlay


def _collect_marker_sites(
    loader: dexruntime.DalvikAbiMethodLoader,
    methods: dict[str, dexflow.MethodSpec],
) -> dict[tuple[str, int], tuple[str, ...]]:
    result: dict[tuple[str, int], tuple[str, ...]] = {}
    for private_id in sorted(methods):
        method = loader._methods.get(private_id)
        if method is None:
            continue
        basic_blocks = method.get_basic_blocks() if hasattr(method, "get_basic_blocks") else None
        candidates = basic_blocks.gets() if basic_blocks is not None and hasattr(basic_blocks, "gets") else ()
        for block in sorted(candidates, key=lambda item: int(item.get_start())):
            offset = int(block.get_start())
            for instruction in block.get_instructions():
                mnemonic = str(instruction.get_name()).strip().lower()
                if mnemonic.startswith("const-string"):
                    markers = safe_literal_markers(instruction, offset)
                    if markers:
                        if len(result) >= MAX_MARKER_SITES:
                            return result
                        result[(private_id, offset)] = markers
                try:
                    offset += int(instruction.get_length())
                except Exception:
                    offset += 2
    return result


def build_dex_security(
    job: Path,
    workspace: Path,
    caps: dict[str, Any],
    *,
    entity_id: str,
    method_limit: int = dexflow.DEFAULT_METHOD_LIMIT,
    analysis_depth: int = dexflow.DEFAULT_ANALYSIS_DEPTH,
    instruction_limit: int = dexflow.DEFAULT_INSTRUCTION_LIMIT,
) -> DexSecurityAnalysis:
    pu_index.ensure_index(job, workspace, caps)
    provider = pu_program_model.DexProgramProvider(job, workspace, caps)
    with pu_index.connect(job) as conn:
        row, truncated_lookup = provider._find_function_row(conn, str(entity_id))
    if row is None:
        if truncated_lookup:
            raise DexSecuritySemanticsError("canonical function lookup exceeded provider budget")
        raise DexSecuritySemanticsError("canonical function entity not found")

    root_private_id = str(row["id"])
    artifact = pu_index.artifact(job, workspace)
    with pu_index.androguard_analysis(artifact) as (analysis, class_members):
        loader = dexruntime.DalvikAbiMethodLoader(analysis, provider, class_members)

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
                location.update({"offset": instruction.offset, "mnemonic": instruction.mnemonic[:128]})
            return provider._evidence_ref(location)

        builder = dexruntime.DalvikFlowBuilder(
            program_snapshot=provider.snapshot,
            snapshot_id=provider.snapshot.snapshot_id,
            method_loader=loader.load,
            evidence_ref=evidence,
            method_limit=method_limit,
            analysis_depth=analysis_depth,
            instruction_limit=instruction_limit,
        )
        flow_analysis = builder.build(root_private_id)
        marker_sites = _collect_marker_sites(loader, builder.methods)
        overlay = build_overlay(flow_analysis.document, builder.methods, marker_sites)
        return DexSecurityAnalysis(flow_analysis, overlay)


def descriptor() -> dict[str, Any]:
    return {
        "dex_security_producer_version": DEX_SECURITY_PRODUCER_VERSION,
        "security_semantics_version": security.SECURITY_SEMANTICS_VERSION,
        "flow_ir_version": flow.FLOW_IR_VERSION,
        "structured_dex_operands": True,
        "decompiler_grep_is_finding_source": False,
        "calls_xref_are_data_flow": False,
        "gaps_are_traversable": False,
        "raw_secret_values": False,
        "safe_literal_categories_only": True,
        "receiver_alias_claimed": False,
        "max_marker_sites": MAX_MARKER_SITES,
        "max_reachability_states": MAX_REACHABILITY_STATES,
    }
