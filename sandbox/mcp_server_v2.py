#!/usr/bin/env python3
"""Extended MCP entrypoint for semantic program-understanding operations."""
from __future__ import annotations

import sqlite3

import mcp_server as core
import program_understanding_v2 as pu

core.SERVER_VERSION = "0.2.0"


def _pu_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
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
        "cfg": caps["androguard"],
        "network_model": True,
        "protector_detection": caps["apkid"],
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
    )


def find_symbols(args):
    job = core._job_dir(str(args.get("job_id", "")))
    return _pu_call(pu.find_symbols, job, core.WORKSPACE, str(args.get("query", "")), limit=int(args.get("limit", 100)))


def find_xrefs(args):
    job = core._job_dir(str(args.get("job_id", "")))
    return _pu_call(
        pu.find_xrefs,
        job,
        core.WORKSPACE,
        str(args.get("query", "")),
        direction=str(args.get("direction", "both")),
        limit=int(args.get("limit", 200)),
    )


def get_cfg(args):
    job = core._job_dir(str(args.get("job_id", "")))
    return _pu_call(pu.get_cfg, job, core.WORKSPACE, str(args.get("query", "")), max_blocks=int(args.get("max_blocks", 500)))


def identify_protector(args):
    artifact = core._workspace_artifact(str(args.get("artifact", "")))
    result = _pu_call(pu.identify_protector, artifact, timeout=int(args.get("timeout_seconds", 10)))
    result["artifact"] = str(artifact.relative_to(core.WORKSPACE))
    return result


def extract_network_model(args):
    job = core._job_dir(str(args.get("job_id", "")))
    return _pu_call(pu.extract_network_model, job, core.WORKSPACE, max_items=int(args.get("max_items", 500)))


core.TOOL_HANDLERS.update({
    "health": health,
    "build_program_index": build_program_index,
    "find_symbols": find_symbols,
    "find_xrefs": find_xrefs,
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
                "force": {"type": "boolean", "default": False}
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
            "properties": {"job_id": {"type": "string"}, "query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100}},
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
                "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 200}
            },
            "required": ["job_id", "query"],
            "additionalProperties": False
        }
    },
    {
        "name": "get_cfg",
        "description": "Return a bounded control-flow graph for methods matching a query. Requires Androguard in the sandbox image.",
        "inputSchema": {
            "type": "object",
            "properties": {"job_id": {"type": "string"}, "query": {"type": "string"}, "max_blocks": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 500}},
            "required": ["job_id", "query"],
            "additionalProperties": False
        }
    },
    {
        "name": "identify_protector",
        "description": "Identify packer/protector/obfuscator/anti-analysis signals with APKiD when that optional analyzer is installed.",
        "inputSchema": {
            "type": "object",
            "properties": {"artifact": {"type": "string"}, "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 60, "default": 10}},
            "required": ["artifact"],
            "additionalProperties": False
        }
    },
    {
        "name": "extract_network_model",
        "description": "Build a structured network model linking endpoints to uniquely resolved declaring methods, caller XREFs, model hints, auth/signature evidence and source provenance.",
        "inputSchema": {
            "type": "object",
            "properties": {"job_id": {"type": "string"}, "max_items": {"type": "integer", "minimum": 20, "maximum": 2000, "default": 500}},
            "required": ["job_id"],
            "additionalProperties": False
        }
    }
])


if __name__ == "__main__":
    raise SystemExit(core.main())
