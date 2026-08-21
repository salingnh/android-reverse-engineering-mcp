#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

import flutter_semantic as semantic
import safe_blutter_adapter as adapter

SEMANTIC_COMMANDS = {
    "build_flutter_index",
    "find_dart_symbols",
    "find_dart_strings",
    "find_dart_xrefs",
    "map_dart_to_native",
}
INDEX_NAME = "flutter-index.sqlite"
MAX_HASH_INPUT_BYTES = 1024 * 1024 * 1024


def _sha256(path: Path) -> str:
    size = path.stat().st_size
    if size > MAX_HASH_INPUT_BYTES:
        raise adapter.AdapterError(
            f"libapp.so exceeds semantic provenance hash budget: {size} bytes"
        )
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _output_dir(value: str, *, must_exist: bool = True) -> Path:
    path = adapter._safe_under(adapter.OUTPUT_ROOT, value, must_exist=must_exist)
    if must_exist and not path.is_dir():
        raise adapter.AdapterError("Flutter analysis output must be a directory")
    return path


def _index_path(value: str) -> Path:
    output = _output_dir(value)
    index = (output / INDEX_NAME).resolve()
    if index.parent != output or not index.is_file():
        raise adapter.AdapterError(
            f"Flutter semantic index not found: {value}/{INDEX_NAME}"
        )
    return index


def _build_index(args: argparse.Namespace) -> dict:
    libdir = adapter._safe_under(adapter.INPUT_ROOT, args.libdir)
    if not libdir.is_dir():
        raise adapter.AdapterError("libdir must be a directory")
    source = _output_dir(args.output)
    libapp, _ = adapter._lib_paths(libdir)
    runtime = adapter._runtime_info(libdir)
    if runtime.get("identity_status") != "identified":
        return {
            "status": "runtime_identity_incomplete",
            "profile": "framework-flutter",
            "executed": False,
            "runtime": runtime,
            "reason": "semantic index provenance requires a locally identified Dart runtime",
        }
    artifact_sha256 = _sha256(libapp)
    analysis_id = f"flutter-aot:{artifact_sha256}"
    return semantic.build_flutter_index(
        source,
        source / INDEX_NAME,
        analysis_id=analysis_id,
        artifact_sha256=artifact_sha256,
        blutter_commit=adapter.BLUTTER_COMMIT,
        runtime=runtime,
    )


def _semantic_main() -> int:
    parser = argparse.ArgumentParser(
        description="Bounded semantic interface for the framework-flutter profile"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build_flutter_index")
    build.add_argument("libdir")
    build.add_argument("output")

    symbols = sub.add_parser("find_dart_symbols")
    symbols.add_argument("output")
    symbols.add_argument("query")
    symbols.add_argument("--limit", type=int, default=50)

    strings = sub.add_parser("find_dart_strings")
    strings.add_argument("output")
    strings.add_argument("query")
    strings.add_argument("--limit", type=int, default=50)

    xrefs = sub.add_parser("find_dart_xrefs")
    xrefs.add_argument("output")
    xrefs.add_argument("symbol")
    xrefs.add_argument(
        "--direction", choices=["incoming", "outgoing", "both"], default="both"
    )
    xrefs.add_argument("--limit", type=int, default=100)

    mapping = sub.add_parser("map_dart_to_native")
    mapping.add_argument("output")
    mapping.add_argument("symbol")

    args = parser.parse_args()
    if args.command == "build_flutter_index":
        payload = _build_index(args)
    elif args.command == "find_dart_symbols":
        payload = semantic.find_dart_symbols(
            _index_path(args.output), args.query, args.limit
        )
    elif args.command == "find_dart_strings":
        payload = semantic.find_dart_strings(
            _index_path(args.output), args.query, args.limit
        )
    elif args.command == "find_dart_xrefs":
        payload = semantic.find_dart_xrefs(
            _index_path(args.output), args.symbol, args.direction, args.limit
        )
    else:
        payload = semantic.map_dart_to_native(
            _index_path(args.output), args.symbol
        )
    adapter._emit(payload)
    return 0 if payload.get("status") not in {"failed", "timeout", "error"} else 2


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        if command == "health":
            payload = adapter.health()
            payload["semantic_index"] = {
                "schema_version": semantic.INDEX_SCHEMA_VERSION,
                "available": True,
                "storage": "sqlite",
                "operations": sorted(SEMANTIC_COMMANDS),
                "max_query_results": semantic.MAX_QUERY_LIMIT,
                "max_scan_bytes": semantic.MAX_SCAN_BYTES,
            }
            adapter._emit(payload)
            return 0
        if command in SEMANTIC_COMMANDS:
            return _semantic_main()
        return adapter.main()
    except (adapter.AdapterError, semantic.FlutterIndexError) as exc:
        adapter._emit({"status": "error", "error": str(exc)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
