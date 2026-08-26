from __future__ import annotations

CONTROL_PLANE_SEMANTIC_OPERATIONS = frozenset(
    {
        "get_application_map",
        "expand_application_node",
        "get_function_context",
        "trace_value",
        "find_source_to_sink",
    }
)

CONTROL_PLANE_CATALOG_OPERATIONS = frozenset(
    {"health", "list_capabilities"}
) | CONTROL_PLANE_SEMANTIC_OPERATIONS

PROGRAM_MODEL_ROUTABLE_REPRESENTATIONS = frozenset(
    {"dex", "flutter-dart-aot"}
)
