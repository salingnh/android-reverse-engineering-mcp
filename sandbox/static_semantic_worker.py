#!/usr/bin/env python3
"""Canonical static-core semantic worker composition.

This module extends the low-level static worker core with bounded semantic
operations. Release version ownership stays in mcp_entrypoint.py; capability
evolution must not create version-suffixed server modules.
"""
from __future__ import annotations

import json
import signal
import sqlite3
from contextlib import contextmanager
from pathlib import Path

import analysis_routing
import flutter_analysis
import mcp_server as core
import peg_schema
import program_understanding_v2 as pu

_baseline_fingerprint = core.fingerprint
OWNERSHIP_QUERY_SCOPES = list(pu.OWNERSHIP_QUERY_SCOPES)
MAX_STATIC_TOOL_CATALOG_BYTES = 256 * 1024


@contextmanager
def _deadline(seconds: int):
    """Bound semantic work in the Linux sandbox without exposing a worker shell."""
    seconds = max(1, min(int(seconds), 3600))
    if not hasattr(signal, "SIGALRM") or not hasattr(signal, "setitimer"):
        yield
        return

    def on_alarm(_signum, _frame):
        raise TimeoutError(f"semantic analysis exceeded {seconds}s deadline")

    old_handler = signal.getsignal(signal.SIGALRM)
    old_timer = signal.setitimer(signal.ITIMER_REAL, 0)
    signal.signal(signal.SIGALRM, on_alarm)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)
        if old_timer and old_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, old_timer[0], old_timer[1])


def _timeout(args, default: int) -> int:
    return max(1, min(int(args.get("timeout_seconds", default)), 3600))


def _pu_call(fn, *args, timeout_seconds: int | None = None, **kwargs):
    try:
        if timeout_seconds is None:
            return fn(*args, **kwargs)
        with _deadline(timeout_seconds):
            return fn(*args, **kwargs)
    except core.ToolError:
        raise
    except (
        ValueError,
        RuntimeError,
        ImportError,
        ModuleNotFoundError,
        OSError,
        sqlite3.Error,
    ) as exc:
        raise core.ToolError(str(exc)) from exc


def fingerprint(args):
    """Fingerprint an artifact and attach an explicit analyzer route.

    Framework detection and analyzer availability are intentionally separate.
    A partial/planned framework profile remains primary instead of silently
    falling back to JADX as the application's business-logic analyzer.
    """
    result = _baseline_fingerprint(args)
    result["analysis_route"] = analysis_routing.route_fingerprint(result)
    return result


def route_analysis(args):
    result = fingerprint(args)
    return {
        "artifact": result["artifact"],
        "framework": result["framework"],
        "analysis_route": result["analysis_route"],
    }


def _flutter_artifact(args):
    """Resolve an artifact without repeating a full DEX fingerprint pass.

    Each Flutter operation validates the concrete Flutter markers it consumes.
    This avoids fingerprinting and extracting every split twice for one tool call.
    """
    return core._workspace_artifact(str(args.get("artifact", "")))


def _artifact_label(artifact):
    return str(artifact.relative_to(core.WORKSPACE))


def inspect_flutter(args):
    artifact = _flutter_artifact(args)
    result = _pu_call(
        flutter_analysis.inspect_flutter,
        artifact,
        core._nested_apks,
        max_assets=int(args.get("max_assets", 5000)),
        timeout_seconds=_timeout(args, 300),
    )
    result["artifact"] = _artifact_label(artifact)
    return result


def identify_dart_runtime(args):
    artifact = _flutter_artifact(args)
    result = _pu_call(
        flutter_analysis.identify_dart_runtime,
        artifact,
        core._nested_apks,
        timeout_seconds=_timeout(args, 300),
    )
    result["artifact"] = _artifact_label(artifact)
    return result


def extract_flutter_assets(args):
    artifact = _flutter_artifact(args)
    result = _pu_call(
        flutter_analysis.extract_flutter_assets,
        artifact,
        core._nested_apks,
        max_items=int(args.get("max_items", 1000)),
        max_previews=int(args.get("max_previews", 20)),
        timeout_seconds=_timeout(args, 300),
    )
    result["artifact"] = _artifact_label(artifact)
    return result


def health(args):
    result = core.health(args)
    caps = pu.capabilities()
    result["version"] = core.SERVER_VERSION
    result["tools"].update(
        {
            "androguard": caps["androguard"],
            "apkid": caps["apkid"],
            "file": core.shutil.which("file") is not None,
            "strings": core.shutil.which("strings") is not None,
            "readelf": core.shutil.which("readelf") is not None,
            "objdump": core.shutil.which("objdump") is not None,
            "nm": core.shutil.which("nm") is not None,
        }
    )
    result["program_understanding"] = {
        "program_index": True,
        "index_storage": caps.get("index_storage", "sqlite"),
        "symbols": True,
        "xrefs": True,
        "cfg": caps["androguard"],
        "api_inventory": True,
        "network_model": True,
        "code_ownership": bool(caps.get("code_ownership")),
        "ownership_model_version": caps.get("ownership_model_version"),
        "ownership_query_scopes": caps.get("ownership_scopes", []),
        "default_ownership_scope": "application",
        "protector_detection": caps["apkid"],
        "wall_clock_deadlines": True,
        "analyzer_versions": caps["versions"],
        "analyzer_errors": caps.get("errors", {}),
    }
    result["analysis_routing"] = {
        "enabled": True,
        "schema_version": analysis_routing.ROUTER_SCHEMA_VERSION,
        "profiles": analysis_routing.profile_registry(),
        "principle": "detect-framework-then-analyze-business-logic-representation",
    }
    result["program_evidence_graph"] = peg_schema.schema_descriptor()
    result["framework_analysis"] = {
        "flutter": {
            "status": analysis_routing.PROFILE_REGISTRY["framework-flutter"]["status"],
            "artifact_inspection": True,
            "runtime_marker_scan": True,
            "asset_inventory": True,
            "dart_aot_index": False,
        }
    }
    result["tool_contract"] = {
        "source": "static-core.json",
        "public_operation_count": len(core.TOOLS) - 1,
        "single_descriptor_source": True,
    }
    return result


def extract_api(args):
    job = core._job_dir(str(args.get("job_id", "")))
    return _pu_call(
        pu.extract_api,
        job,
        scope=str(args.get("scope", "application")),
        max_items=int(args.get("max_items", 500)),
        timeout_seconds=_timeout(args, 600),
    )


def build_program_index(args):
    job = core._job_dir(str(args.get("job_id", "")))
    return _pu_call(
        pu.build_program_index,
        job,
        core.WORKSPACE,
        max_methods=int(args.get("max_methods", 100000)),
        max_edges=int(args.get("max_edges", 250000)),
        force=bool(args.get("force", False)),
        timeout_seconds=_timeout(args, 900),
    )


def find_symbols(args):
    job = core._job_dir(str(args.get("job_id", "")))
    return _pu_call(
        pu.find_symbols,
        job,
        core.WORKSPACE,
        str(args.get("query", "")),
        scope=str(args.get("scope", "application")),
        limit=int(args.get("limit", 100)),
        timeout_seconds=_timeout(args, 300),
    )


def find_xrefs(args):
    job = core._job_dir(str(args.get("job_id", "")))
    return _pu_call(
        pu.find_xrefs,
        job,
        core.WORKSPACE,
        str(args.get("query", "")),
        direction=str(args.get("direction", "both")),
        scope=str(args.get("scope", "application")),
        limit=int(args.get("limit", 200)),
        timeout_seconds=_timeout(args, 300),
    )


def get_cfg(args):
    job = core._job_dir(str(args.get("job_id", "")))
    return _pu_call(
        pu.get_cfg,
        job,
        core.WORKSPACE,
        str(args.get("query", "")),
        scope=str(args.get("scope", "application")),
        max_blocks=int(args.get("max_blocks", 500)),
        timeout_seconds=_timeout(args, 300),
    )


def identify_protector(args):
    artifact = core._workspace_artifact(str(args.get("artifact", "")))
    timeout = _timeout(args, 10)
    result = _pu_call(
        pu.identify_protector,
        artifact,
        timeout=timeout,
        timeout_seconds=min(3600, timeout + 20),
    )
    result["artifact"] = str(artifact.relative_to(core.WORKSPACE))
    return result


def extract_network_model(args):
    job = core._job_dir(str(args.get("job_id", "")))
    return _pu_call(
        pu.extract_network_model,
        job,
        core.WORKSPACE,
        scope=str(args.get("scope", "application")),
        max_items=int(args.get("max_items", 500)),
        timeout_seconds=_timeout(args, 600),
    )


def _catalog_candidates() -> tuple[Path, ...]:
    module_root = Path(__file__).resolve().parent
    return (
        module_root / "tool-catalogs" / "static-core.json",
        module_root.parent
        / "plugins"
        / "safe-android-reverser"
        / "tool-catalogs"
        / "static-core.json",
    )


def _load_public_tool_catalog() -> list[dict]:
    path = next(
        (
            candidate
            for candidate in _catalog_candidates()
            if candidate.is_file() and not candidate.is_symlink()
        ),
        None,
    )
    if path is None:
        raise RuntimeError("canonical static-core tool catalog is unavailable")
    if path.stat().st_size > MAX_STATIC_TOOL_CATALOG_BYTES:
        raise RuntimeError("canonical static-core tool catalog exceeds size bound")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("canonical static-core tool catalog is invalid") from exc
    if not isinstance(raw, list) or not raw:
        raise RuntimeError("canonical static-core tool catalog must be a non-empty array")

    tools: list[dict] = []
    names: list[str] = []
    for index, value in enumerate(raw):
        if not isinstance(value, dict) or set(value) != {
            "name",
            "description",
            "inputSchema",
        }:
            raise RuntimeError(f"invalid static-core tool descriptor at index {index}")
        name = value.get("name")
        description = value.get("description")
        schema = value.get("inputSchema")
        if not isinstance(name, str) or not name:
            raise RuntimeError(f"invalid static-core tool name at index {index}")
        if not isinstance(description, str) or not description.strip():
            raise RuntimeError(f"invalid static-core tool description at index {index}")
        if not isinstance(schema, dict) or schema.get("type") != "object":
            raise RuntimeError(f"invalid static-core input schema at index {index}")
        tools.append(value)
        names.append(name)

    if len(names) != len(set(names)):
        raise RuntimeError("canonical static-core tool catalog contains duplicate operations")

    expected = set(core.TOOL_HANDLERS) - {"health"}
    actual = set(names)
    if actual != expected:
        raise RuntimeError(
            "static-core tool catalog/handler drift: "
            f"missing={sorted(expected - actual)} extra={sorted(actual - expected)}"
        )
    return tools


# Make the routed fingerprint the canonical function for callers importing the
# semantic worker, while keeping the low-level function private above.
core.fingerprint = fingerprint
core.TOOL_HANDLERS.update(
    {
        "health": health,
        "fingerprint": fingerprint,
        "route_analysis": route_analysis,
        "inspect_flutter": inspect_flutter,
        "identify_dart_runtime": identify_dart_runtime,
        "extract_flutter_assets": extract_flutter_assets,
        "extract_api": extract_api,
        "build_program_index": build_program_index,
        "find_symbols": find_symbols,
        "find_xrefs": find_xrefs,
        "get_cfg": get_cfg,
        "identify_protector": identify_protector,
        "extract_network_model": extract_network_model,
    }
)

# Public descriptors have exactly one repository source of truth: the trusted
# host-side static-core.json. The same immutable file is copied into the worker
# image and loaded here. The worker owns handlers only; it does not hand-maintain
# a second public description/schema surface.
_internal_tools = [item for item in core.TOOLS if item.get("name") == "health"]
if len(_internal_tools) != 1:
    raise RuntimeError("static-core internal health descriptor is invalid")
core.TOOLS = _internal_tools + _load_public_tool_catalog()


if __name__ == "__main__":
    raise SystemExit(core.main())
