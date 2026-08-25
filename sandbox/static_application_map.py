from __future__ import annotations

from typing import Any

import application_map as amap
import program_model as pm
import pu_program_model

INTERNAL_APPLICATION_MAP_TOOLS = frozenset(
    {"get_application_map", "expand_application_node"}
)


def _repository(server: Any, args: dict[str, Any]) -> pm.ProgramRepository:
    job = server.core._job_dir(str(args.get("job_id", "")))
    provider = pu_program_model.DexProgramProvider(
        job,
        server.core.WORKSPACE,
        server.pu.capabilities(),
    )
    return pm.ProgramRepository((provider,))


def _get_application_map(server: Any, args: dict[str, Any]) -> dict[str, Any]:
    repo = _repository(server, args)
    projector = amap.ApplicationMapProjector(repo)
    return projector.get_application_map(
        ownership_scope=str(args.get("ownership_scope", "application")),
        node_limit=int(args.get("node_limit", amap.DEFAULT_NODE_LIMIT)),
        edge_limit=int(args.get("edge_limit", amap.DEFAULT_EDGE_LIMIT)),
    )


def _expand_application_node(server: Any, args: dict[str, Any]) -> dict[str, Any]:
    repo = _repository(server, args)
    projector = amap.ApplicationMapProjector(repo)
    kinds = args.get("relationship_kinds")
    if kinds is not None and not isinstance(kinds, list):
        raise server.core.ToolError("relationship_kinds must be an array")
    return projector.expand_application_node(
        entity_id=str(args.get("entity_id", "")),
        ownership_scope=str(args.get("ownership_scope", "application")),
        direction=str(args.get("direction", "both")),
        relationship_kinds=kinds,
        node_limit=int(args.get("node_limit", amap.DEFAULT_NODE_LIMIT)),
        edge_limit=int(args.get("edge_limit", amap.DEFAULT_EDGE_LIMIT)),
        cursor=str(args.get("cursor")) if args.get("cursor") else None,
    )


def _tool_descriptors() -> list[dict[str, Any]]:
    ownership = [
        "application",
        "all",
        "first_party",
        "third_party",
        "platform",
        "generated",
        "unknown",
    ]
    common = {
        "job_id": {"type": "string"},
        "ownership_scope": {
            "type": "string",
            "enum": ownership,
            "default": "application",
        },
        "node_limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": amap.MAX_NODE_LIMIT,
            "default": amap.DEFAULT_NODE_LIMIT,
        },
        "edge_limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": amap.MAX_EDGE_LIMIT,
            "default": amap.DEFAULT_EDGE_LIMIT,
        },
    }
    return [
        {
            "name": "get_application_map",
            "description": "Internal static-core Program Model projection hook.",
            "inputSchema": {
                "type": "object",
                "properties": dict(common),
                "required": ["job_id"],
                "additionalProperties": False,
            },
        },
        {
            "name": "expand_application_node",
            "description": "Internal static-core Program Model node expansion hook.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    **common,
                    "entity_id": {"type": "string"},
                    "direction": {
                        "type": "string",
                        "enum": ["incoming", "outgoing", "both"],
                        "default": "both",
                    },
                    "relationship_kinds": {
                        "type": "array",
                        "items": {"type": "string"},
                        "maxItems": 32,
                    },
                    "cursor": {"type": "string", "maxLength": pm.MAX_CURSOR_BYTES},
                    "node_limit": {
                        "type": "integer",
                        "minimum": 2,
                        "maximum": amap.MAX_NODE_LIMIT,
                        "default": amap.DEFAULT_NODE_LIMIT,
                    },
                },
                "required": ["job_id", "entity_id"],
                "additionalProperties": False,
            },
        },
    ]


def install(server: Any) -> None:
    if getattr(server, "_application_map_installed", False):
        return

    original_health = server.health

    def health(args: dict[str, Any]) -> dict[str, Any]:
        result = original_health(args)
        result["application_map"] = amap.descriptor()
        contract = result.get("tool_contract")
        if isinstance(contract, dict):
            contract["public_operation_count"] = len(
                [
                    item
                    for item in server.core.TOOLS
                    if item.get("name")
                    not in ({"health"} | set(INTERNAL_APPLICATION_MAP_TOOLS))
                ]
            )
        return result

    def get_application_map(args: dict[str, Any]) -> dict[str, Any]:
        return server._pu_call(
            _get_application_map,
            server,
            args,
            timeout_seconds=server._timeout(args, 300),
        )

    def expand_application_node(args: dict[str, Any]) -> dict[str, Any]:
        return server._pu_call(
            _expand_application_node,
            server,
            args,
            timeout_seconds=server._timeout(args, 300),
        )

    server.health = health
    server.core.TOOL_HANDLERS.update(
        {
            "health": health,
            "get_application_map": get_application_map,
            "expand_application_node": expand_application_node,
        }
    )
    existing = {str(item.get("name") or "") for item in server.core.TOOLS}
    for descriptor in _tool_descriptors():
        if descriptor["name"] not in existing:
            server.core.TOOLS.append(descriptor)
    server._application_map_installed = True
