#!/usr/bin/env python3
"""Extended MCP entrypoint for bounded semantic program-understanding operations."""
from __future__ import annotations

import signal
import sqlite3
from contextlib import contextmanager

import mcp_server as core
import program_understanding_v2 as pu

core.SERVER_VERSION = "0.2.1"


class SemanticDeadlineExceeded(BaseException):
    """Private control-flow exception that analyzer `except Exception` blocks cannot swallow."""


@contextmanager
def _deadline(seconds: int):
    """Bound semantic work in the Linux sandbox without exposing a worker shell."""
    seconds = max(1, min(int(seconds), 3600))
    if not hasattr(signal, "SIGALRM") or not hasattr(signal, "setitimer"):
        yield
        return

    def on_alarm(_signum, _frame):
        raise SemanticDeadlineExceeded(f"semantic analysis exceeded {seconds}s deadline")

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
    except SemanticDeadlineExceeded as exc:
        raise core.ToolError(str(exc)) from exc
    except core.ToolError:
        raise
    except (ValueError, RuntimeError, ImportError, ModuleNotFoundError, OSError, sqlite3.Error) as exc:
        raise core.ToolError(str(exc)) from exc


def health(args):
    result = core.health(args)
    caps = pu.capabilities()
    result["version"] = core.SERVER_VERSION
    result["tools"].update({
        "androguard": caps["androguard"],
        "apkid": caps["apkid"],
        "file": core.shutil.which("file") is not None,
        "strings": core.shutil.which("strings") is not None,
        "readelf": core.shutil.which("readelf") is not None,
        "objdump": core.shutil.which("objdump") is not None,
        "nm": core.shutil.which("nm") is not None,
    })
    result["program_understanding"] = {
        "program_index": True,
        "index_storage": caps.get("index_storage", "sqlite"),
        "symbols": True,
        "xrefs": True,
        "call_path": True,
        "cfg": caps["androguard"],
        "network_model": True,
        "protector_detection": caps["apkid"],
        "wall_clock_deadlines": True,
        "analyzer_versions": caps["versions"],
        "analyzer_errors": caps.get("errors", {}),
    }
    return result


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
        limit=int(args.get("limit", 200)),
        timeout_seconds=_timeout(args, 300),
    )


def trace_call_path(args):
    job = core._job_dir(str(args.get("job_id", "")))
    return _pu_call(
        pu.trace_call_path,
        job,
        core.WORKSPACE,
        str(args.get("source", "")),
        str(args.get("target", "")),
        direction=str(args.get("direction", "forward")),
        max_depth=int(args.get("max_depth", 12)),
        max_paths=int(args.get("max_paths", 20)),
        max_visited_nodes=int(args.get("max_visited_nodes", 50000)),
        max_scanned_edges=int(args.get("max_scanned_edges", 200000)),
        timeout_seconds=_timeout(args, 300),
    )


def get_cfg(args):
    job = core._job_dir(str(args.get("job_id", "")))
    return _pu_call(
        pu.get_cfg,
        job,
        core.WORKSPACE,
        str(args.get("query", "")),
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
        max_items=int(args.get("max_items", 500)),
        timeout_seconds=_timeout(args, 600),
    )


core.TOOL_HANDLERS.update({
    "health": health,
    "build_program_index": build_program_index,
    "find_symbols": find_symbols,
    "find_xrefs": find_xrefs,
    "trace_call_path": trace_call_path,
    "get_cfg": get_cfg,
    "identify_protector": identify_protector,
    "extract_network_model": extract_network_model,
})

core.TOOLS.extend([
    {
        "name": "build_program_index",
        "description": "Build or reuse a bounded semantic program index from DEX XREFs when Androguard is available, with a lower-confidence decompiled-source fallback.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "max_methods": {"type": "integer", "minimum": 100, "maximum": 200000, "default": 100000},
                "max_edges": {"type": "integer", "minimum": 100, "maximum": 500000, "default": 250000},
                "force": {"type": "boolean", "default": False},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 3600, "default": 900}
            },
            "required": ["job_id"],
            "additionalProperties": False
        }
    },
    {
        "name": "find_symbols",
        "description": "Search normalized class/method symbols in the program index without scanning the full decompiled tree.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "query": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 3600, "default": 300}
            },
            "required": ["job_id", "query"],
            "additionalProperties": False
        }
    },
    {
        "name": "find_xrefs",
        "description": "Find incoming/outgoing method cross-references using DEX XREFs when available, returning normalized evidence edges.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "query": {"type": "string"},
                "direction": {"type": "string", "enum": ["incoming", "outgoing", "both"], "default": "both"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 200},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 3600, "default": 300}
            },
            "required": ["job_id", "query"],
            "additionalProperties": False
        }
    },
    {
        "name": "trace_call_path",
        "description": "Find bounded shortest method-call paths between source and target symbol queries using the indexed DEX XREF graph. Broad queries remain explicit candidate sets; call paths are not data-flow proof.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "source": {"type": "string", "minLength": 1, "maxLength": 512},
                "target": {"type": "string", "minLength": 1, "maxLength": 512},
                "direction": {"type": "string", "enum": ["forward", "reverse"], "default": "forward"},
                "max_depth": {"type": "integer", "minimum": 1, "maximum": 32, "default": 12},
                "max_paths": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
                "max_visited_nodes": {"type": "integer", "minimum": 200, "maximum": 200000, "default": 50000},
                "max_scanned_edges": {"type": "integer", "minimum": 100, "maximum": 500000, "default": 200000},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 3600, "default": 300}
            },
            "required": ["job_id", "source", "target"],
            "additionalProperties": False
        }
    },
    {
        "name": "get_cfg",
        "description": "Return a bounded control-flow graph for methods matching a query. Requires Androguard in the sandbox image.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "query": {"type": "string"},
                "max_blocks": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 500},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 3600, "default": 300}
            },
            "required": ["job_id", "query"],
            "additionalProperties": False
        }
    },
    {
        "name": "identify_protector",
        "description": "Identify packer/protector/obfuscator/anti-analysis signals with APKiD when that optional analyzer is installed.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "artifact": {"type": "string"},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 60, "default": 10}
            },
            "required": ["artifact"],
            "additionalProperties": False
        }
    },
    {
        "name": "extract_network_model",
        "description": "Build a structured network model linking endpoints to uniquely resolved declaring methods, caller XREFs, model hints, auth/signature evidence and source provenance.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "max_items": {"type": "integer", "minimum": 20, "maximum": 2000, "default": 500},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 3600, "default": 600}
            },
            "required": ["job_id"],
            "additionalProperties": False
        }
    }
])


if __name__ == "__main__":
    raise SystemExit(core.main())
