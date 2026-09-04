from __future__ import annotations

from typing import Any

import dex_security_semantics as dexsecurity
import dex_value_tracing as dexflow
import security_semantics as security
import static_application_map
import static_context_retrieval
import static_value_tracing

INTERNAL_SECURITY_SEMANTIC_TOOLS = frozenset({"find_auth_flow", "trace_crypto"})


def _analysis(server: Any, args: dict[str, Any]) -> dexsecurity.DexSecurityAnalysis:
    job = server.core._job_dir(str(args.get("job_id", "")))
    entity_id = str(args.get("entity_id") or "").strip()
    if not entity_id or len(entity_id) > 256:
        raise server.core.ToolError("invalid security semantic entity_id")
    try:
        return dexsecurity.build_dex_security(
            job,
            server.core.WORKSPACE,
            server.pu.capabilities(),
            entity_id=entity_id,
            method_limit=int(args.get("method_limit", dexflow.DEFAULT_METHOD_LIMIT)),
            analysis_depth=int(args.get("analysis_depth", dexflow.DEFAULT_ANALYSIS_DEPTH)),
            instruction_limit=int(
                args.get("instruction_limit", dexflow.DEFAULT_INSTRUCTION_LIMIT)
            ),
        )
    except (dexsecurity.DexSecuritySemanticsError, dexflow.DexValueTracingError) as exc:
        raise server.core.ToolError(str(exc)) from exc


def _metadata(analysis: dexsecurity.DexSecurityAnalysis) -> dict[str, Any]:
    flow_analysis = analysis.flow_analysis
    return {
        "producer": dexsecurity.descriptor(),
        "root_entity_id": flow_analysis.root_entity_id,
        "methods_analyzed": flow_analysis.methods_analyzed,
        "instructions_analyzed": flow_analysis.instructions_analyzed,
        "analysis_truncated": flow_analysis.truncated,
        "security_signal_count": len(analysis.overlay.signals),
    }


def _find_auth_flow(server: Any, args: dict[str, Any]) -> dict[str, Any]:
    analysis = _analysis(server, args)
    try:
        result = security.find_auth_flow(
            analysis.flow_analysis.document,
            analysis.overlay,
            focus=str(args.get("focus", "any")),
            max_depth=int(args.get("path_depth", 16)),
            max_findings=int(args.get("finding_limit", 40)),
        )
    except security.SecuritySemanticsError as exc:
        raise server.core.ToolError(str(exc)) from exc
    result.update(_metadata(analysis))
    return result


def _trace_crypto(server: Any, args: dict[str, Any]) -> dict[str, Any]:
    analysis = _analysis(server, args)
    try:
        result = security.trace_crypto(
            analysis.flow_analysis.document,
            analysis.overlay,
            family=str(args.get("family", "any")),
            max_depth=int(args.get("path_depth", 16)),
            max_findings=int(args.get("finding_limit", 40)),
        )
    except security.SecuritySemanticsError as exc:
        raise server.core.ToolError(str(exc)) from exc
    result.update(_metadata(analysis))
    return result


def _common_properties() -> dict[str, Any]:
    return {
        "job_id": {"type": "string"},
        "entity_id": {"type": "string", "minLength": 1, "maxLength": 256},
        "method_limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": dexflow.MAX_METHOD_LIMIT,
            "default": dexflow.DEFAULT_METHOD_LIMIT,
        },
        "analysis_depth": {
            "type": "integer",
            "minimum": 0,
            "maximum": dexflow.MAX_ANALYSIS_DEPTH,
            "default": dexflow.DEFAULT_ANALYSIS_DEPTH,
        },
        "instruction_limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": dexflow.MAX_INSTRUCTION_LIMIT,
            "default": dexflow.DEFAULT_INSTRUCTION_LIMIT,
        },
        "path_depth": {
            "type": "integer",
            "minimum": 1,
            "maximum": security.MAX_SECURITY_PATH_DEPTH,
            "default": 16,
        },
        "finding_limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": security.MAX_SECURITY_FINDINGS,
            "default": 40,
        },
    }


def _tool_descriptors() -> tuple[dict[str, Any], dict[str, Any]]:
    auth = _common_properties()
    auth["focus"] = {
        "type": "string",
        "enum": list(security.AUTH_FOCUS),
        "default": "any",
    }
    crypto = _common_properties()
    crypto["family"] = {
        "type": "string",
        "enum": list(security.CRYPTO_FAMILIES),
        "default": "any",
    }
    return (
        {
            "name": "find_auth_flow",
            "description": "Internal static-core bounded authentication/token semantics over proven Flow IR paths and explicit boundaries.",
            "inputSchema": {
                "type": "object",
                "properties": auth,
                "required": ["job_id", "entity_id"],
                "additionalProperties": False,
            },
        },
        {
            "name": "trace_crypto",
            "description": "Internal static-core bounded HMAC/AES semantics over proven Flow IR paths without traversing external gaps.",
            "inputSchema": {
                "type": "object",
                "properties": crypto,
                "required": ["job_id", "entity_id"],
                "additionalProperties": False,
            },
        },
    )


def install(server: Any) -> None:
    if getattr(server, "_security_semantics_installed", False):
        return
    original_health = server.health

    def health(args: dict[str, Any]) -> dict[str, Any]:
        result = original_health(args)
        result["security_semantics"] = security.descriptor()
        result["dex_security_producer"] = dexsecurity.descriptor()
        contract = result.get("tool_contract")
        if isinstance(contract, dict):
            internal = (
                {"health"}
                | set(static_application_map.INTERNAL_APPLICATION_MAP_TOOLS)
                | set(static_context_retrieval.INTERNAL_CONTEXT_RETRIEVAL_TOOLS)
                | set(static_value_tracing.INTERNAL_VALUE_TRACING_TOOLS)
                | set(INTERNAL_SECURITY_SEMANTIC_TOOLS)
            )
            contract["public_operation_count"] = len(
                [item for item in server.core.TOOLS if item.get("name") not in internal]
            )
        return result

    def find_auth_flow(args: dict[str, Any]) -> dict[str, Any]:
        return server._pu_call(
            _find_auth_flow,
            server,
            args,
            timeout_seconds=server._timeout(args, 600),
        )

    def trace_crypto(args: dict[str, Any]) -> dict[str, Any]:
        return server._pu_call(
            _trace_crypto,
            server,
            args,
            timeout_seconds=server._timeout(args, 600),
        )

    server.health = health
    server.core.TOOL_HANDLERS.update(
        {
            "health": health,
            "find_auth_flow": find_auth_flow,
            "trace_crypto": trace_crypto,
        }
    )
    names = {str(item.get("name") or "") for item in server.core.TOOLS}
    for descriptor in _tool_descriptors():
        if descriptor["name"] not in names:
            server.core.TOOLS.append(descriptor)
            names.add(descriptor["name"])
    server._security_semantics_installed = True
