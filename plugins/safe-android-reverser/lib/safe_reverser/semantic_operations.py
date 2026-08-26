from __future__ import annotations

VALUE_FLOW_SEMANTIC_OPERATIONS = frozenset(
    {"trace_value", "find_source_to_sink"}
)

CONTROL_PLANE_SEMANTIC_OPERATIONS = frozenset(
    {
        "get_application_map",
        "expand_application_node",
        "get_function_context",
    }
) | VALUE_FLOW_SEMANTIC_OPERATIONS

CONTROL_PLANE_CATALOG_OPERATIONS = frozenset(
    {"health", "list_capabilities"}
) | CONTROL_PLANE_SEMANTIC_OPERATIONS

PROGRAM_MODEL_ROUTABLE_REPRESENTATIONS = frozenset(
    {"dex", "flutter-dart-aot"}
)
VALUE_FLOW_ROUTABLE_REPRESENTATIONS = frozenset({"dex"})
