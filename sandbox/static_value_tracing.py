from __future__ import annotations

from typing import Any

import dex_value_tracing as dexflow
import dex_value_tracing_runtime as dexruntime
import static_application_map
import static_context_retrieval
import value_tracing as tracing

INTERNAL_VALUE_TRACING_TOOLS = frozenset({"trace_value", "find_source_to_sink"})


def _analysis(server: Any, args: dict[str, Any]) -> dexflow.DexFlowAnalysis:
    job = server.core._job_dir(str(args.get("job_id", "")))
    entity_id = str(args.get("entity_id") or "").strip()
    if not entity_id or len(entity_id) > 256:
        raise server.core.ToolError("invalid value tracing entity_id")
    return dexruntime.build_dex_flow(
        job,
        server.core.WORKSPACE,
        server.pu.capabilities(),
        entity_id=entity_id,
        method_limit=int(args.get("method_limit", dexflow.DEFAULT_METHOD_LIMIT)),
        analysis_depth=int(
            args.get("analysis_depth", dexflow.DEFAULT_ANALYSIS_DEPTH)
        ),
        instruction_limit=int(
            args.get("instruction_limit", dexflow.DEFAULT_INSTRUCTION_LIMIT)
        ),
    )


def _metadata(analysis: dexflow.DexFlowAnalysis) -> dict[str, Any]:
    return {
        "producer": dexruntime.descriptor(),
        "root_entity_id": analysis.root_entity_id,
        "methods_analyzed": analysis.methods_analyzed,
        "instructions_analyzed": analysis.instructions_analyzed,
        "analysis_truncated": analysis.truncated,
    }


def _trace_value(server: Any, args: dict[str, Any]) -> dict[str, Any]:
    analysis = _analysis(server, args)
    selector = args.get("seed")
    if not isinstance(selector, dict):
        raise server.core.ToolError("trace_value seed must be an object")
    try:
        result = tracing.trace_value(
            analysis.document,
            owner_entity_id=analysis.root_entity_id,
            selector=selector,
            direction=str(args.get("direction", "both")),
            max_depth=int(args.get("trace_depth", 8)),
            max_nodes=int(args.get("node_limit", 160)),
        )
    except tracing.ValueTracingError as exc:
        raise server.core.ToolError(str(exc)) from exc
    result.update(_metadata(analysis))
    return result


def _find_source_to_sink(server: Any, args: dict[str, Any]) -> dict[str, Any]:
    analysis = _analysis(server, args)
    source = args.get("source")
    sink = args.get("sink")
    if not isinstance(source, dict) or not isinstance(sink, dict):
        raise server.core.ToolError("source and sink selectors must be objects")
    try:
        result = tracing.find_source_to_sink(
            analysis.document,
            owner_entity_id=analysis.root_entity_id,
            source_selector=source,
            sink_selector=sink,
            max_depth=int(args.get("path_depth", 12)),
            max_paths=int(args.get("path_limit", 20)),
            max_nodes=int(args.get("node_limit", 240)),
        )
    except tracing.ValueTracingError as exc:
        raise server.core.ToolError(str(exc)) from exc
    result.update(_metadata(analysis))
    return result


def _selector_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "kind": {
                "type": "string",
                "enum": ["parameter", "return", "field", "node"],
            },
            "index": {"type": "integer", "minimum": 0, "maximum": 1024},
            "name": {"type": "string", "minLength": 1, "maxLength": 512},
            "node_id": {"type": "string", "minLength": 1, "maxLength": 256},
        },
        "required": ["kind"],
        "additionalProperties": False,
    }


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
    }


def _tool_descriptors() -> tuple[dict[str, Any], dict[str, Any]]:
    trace_properties = _common_properties()
    trace_properties.update(
        {
            "seed": _selector_schema(),
            "direction": {
                "type": "string",
                "enum": ["forward", "backward", "both"],
                "default": "both",
            },
            "trace_depth": {
                "type": "integer",
                "minimum": 0,
                "maximum": tracing.MAX_TRACE_DEPTH,
                "default": 8,
            },
            "node_limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": tracing.MAX_TRACE_NODES,
                "default": 160,
            },
        }
    )
    path_properties = _common_properties()
    path_properties.update(
        {
            "source": _selector_schema(),
            "sink": _selector_schema(),
            "path_depth": {
                "type": "integer",
                "minimum": 1,
                "maximum": tracing.MAX_TRACE_DEPTH,
                "default": 12,
            },
            "path_limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": tracing.MAX_TRACE_PATHS,
                "default": 20,
            },
            "node_limit": {
                "type": "integer",
                "minimum": 2,
                "maximum": tracing.MAX_TRACE_NODES,
                "default": 240,
            },
        }
    )
    return (
        {
            "name": "trace_value",
            "description": "Internal static-core localized semantic value trace over proven Flow IR edges.",
            "inputSchema": {
                "type": "object",
                "properties": trace_properties,
                "required": ["job_id", "entity_id", "seed"],
                "additionalProperties": False,
            },
        },
        {
            "name": "find_source_to_sink",
            "description": "Internal static-core bounded source-to-sink composition over proven Flow IR edges only.",
            "inputSchema": {
                "type": "object",
                "properties": path_properties,
                "required": ["job_id", "entity_id", "source", "sink"],
                "additionalProperties": False,
            },
        },
    )


def install(server: Any) -> None:
    if getattr(server, "_value_tracing_installed", False):
        return
    original_health = server.health

    def health(args: dict[str, Any]) -> dict[str, Any]:
        result = original_health(args)
        result["value_tracing"] = tracing.descriptor()
        result["dex_flow_producer"] = dexruntime.descriptor()
        contract = result.get("tool_contract")
        if isinstance(contract, dict):
            internal = (
                {"health"}
                | set(static_application_map.INTERNAL_APPLICATION_MAP_TOOLS)
                | set(static_context_retrieval.INTERNAL_CONTEXT_RETRIEVAL_TOOLS)
                | set(INTERNAL_VALUE_TRACING_TOOLS)
            )
            contract["public_operation_count"] = len(
                [item for item in server.core.TOOLS if item.get("name") not in internal]
            )
        return result

    def trace_value(args: dict[str, Any]) -> dict[str, Any]:
        return server._pu_call(
            _trace_value,
            server,
            args,
            timeout_seconds=server._timeout(args, 600),
        )

    def find_source_to_sink(args: dict[str, Any]) -> dict[str, Any]:
        return server._pu_call(
            _find_source_to_sink,
            server,
            args,
            timeout_seconds=server._timeout(args, 600),
        )

    server.health = health
    server.core.TOOL_HANDLERS.update(
        {
            "health": health,
            "trace_value": trace_value,
            "find_source_to_sink": find_source_to_sink,
        }
    )
    names = {str(item.get("name") or "") for item in server.core.TOOLS}
    for descriptor in _tool_descriptors():
        if descriptor["name"] not in names:
            server.core.TOOLS.append(descriptor)
            names.add(descriptor["name"])
    server._value_tracing_installed = True
