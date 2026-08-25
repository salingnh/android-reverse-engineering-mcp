from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, Iterable

from .contracts import CapabilityManifest, ContractError, OPERATION_RE

MAX_TOOL_CATALOG_BYTES = 256 * 1024
MAX_TOOL_DESCRIPTION_CHARS = 4096
MAX_TOOL_SCHEMA_BYTES = 64 * 1024
CATALOG_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")


def _validate_tool_descriptor(value: Any, *, index: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"tool catalog entry {index} must be an object")
    if set(value) != {"name", "description", "inputSchema"}:
        raise ContractError(
            f"tool catalog entry {index} must contain name, description and inputSchema only"
        )
    name = value.get("name")
    description = value.get("description")
    schema = value.get("inputSchema")
    if not isinstance(name, str) or not OPERATION_RE.fullmatch(name):
        raise ContractError(f"tool catalog entry {index} has invalid name")
    if (
        not isinstance(description, str)
        or not description.strip()
        or len(description) > MAX_TOOL_DESCRIPTION_CHARS
    ):
        raise ContractError(f"tool catalog entry {index} has invalid description")
    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise ContractError(f"tool catalog entry {index} must use an object inputSchema")
    try:
        encoded_schema = json.dumps(
            schema, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ContractError(f"tool catalog entry {index} has invalid inputSchema") from exc
    if len(encoded_schema) > MAX_TOOL_SCHEMA_BYTES:
        raise ContractError(f"tool catalog entry {index} inputSchema is too large")
    return {
        "name": name,
        "description": description.strip(),
        "inputSchema": copy.deepcopy(schema),
    }


def _catalog_path(catalog_root: Path, catalog_name: str) -> Path:
    root = Path(catalog_root)
    if root.is_symlink() or not root.is_dir():
        raise ContractError("tool catalog directory is unavailable")
    root = root.resolve()
    name = str(catalog_name or "").strip()
    if not CATALOG_NAME_RE.fullmatch(name):
        raise ContractError("invalid tool catalog name")
    path = root / f"{name}.json"
    if path.is_symlink() or not path.is_file() or path.resolve().parent != root:
        raise ContractError(f"trusted tool catalog is unavailable for {name}")
    if path.stat().st_size > MAX_TOOL_CATALOG_BYTES:
        raise ContractError(f"trusted tool catalog is too large for {name}")
    return path


def load_named_tool_catalog(
    catalog_root: Path,
    catalog_name: str,
    *,
    expected_operations: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    path = _catalog_path(catalog_root, catalog_name)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"invalid trusted tool catalog for {catalog_name}") from exc
    if not isinstance(raw, list) or not raw:
        raise ContractError(
            f"trusted tool catalog must be a non-empty array for {catalog_name}"
        )
    tools = [
        _validate_tool_descriptor(item, index=index)
        for index, item in enumerate(raw)
    ]
    names = [item["name"] for item in tools]
    if len(names) != len(set(names)):
        raise ContractError(
            f"trusted tool catalog contains duplicate operations for {catalog_name}"
        )
    if expected_operations is not None:
        expected = set(expected_operations)
        actual = set(names)
        if actual != expected:
            raise ContractError(
                f"trusted tool catalog/operation drift for {catalog_name}: "
                f"missing={sorted(expected - actual)} extra={sorted(actual - expected)}"
            )
    return tools


def load_tool_catalog(
    catalog_root: Path, manifest: CapabilityManifest
) -> list[dict[str, Any]]:
    return load_named_tool_catalog(
        catalog_root,
        manifest.capability_id,
        expected_operations=manifest.operations,
    )


def catalogs_equal(
    expected: list[dict[str, Any]], actual: list[dict[str, Any]]
) -> bool:
    def normalized(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for item in items:
            if not isinstance(item, dict):
                return {}
            name = item.get("name")
            description = item.get("description")
            schema = item.get("inputSchema")
            if (
                not isinstance(name, str)
                or not isinstance(description, str)
                or not isinstance(schema, dict)
            ):
                return {}
            result[name] = {
                "description": description.strip(),
                "inputSchema": schema,
            }
        return result

    return normalized(expected) == normalized(actual)
