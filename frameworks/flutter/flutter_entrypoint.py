#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
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
MANIFEST_NAME = "safe-flutter-analysis.json"
MANIFEST_SCHEMA_VERSION = 1
MAX_HASH_INPUT_BYTES = 1024 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


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
    if index.parent != output or not index.is_file() or index.is_symlink():
        raise adapter.AdapterError(
            f"Flutter semantic index not found: {value}/{INDEX_NAME}"
        )
    return index


def _manifest_path(output: Path) -> Path:
    path = (output / MANIFEST_NAME).resolve()
    if path.parent != output:
        raise adapter.AdapterError("invalid Flutter analysis manifest path")
    return path


def _write_manifest(output: Path, libdir: Path, runtime: dict) -> dict:
    libapp, _ = adapter._lib_paths(libdir)
    artifact_sha256 = _sha256(libapp)
    payload = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "analysis_id": f"flutter-aot:{artifact_sha256}",
        "artifact_sha256": artifact_sha256,
        "artifact_kind": "libapp.so",
        "blutter_commit": adapter.BLUTTER_COMMIT,
        "runtime": runtime,
    }
    target = _manifest_path(output)
    if target.exists() and target.is_symlink():
        raise adapter.AdapterError("analysis manifest must not be a symlink")
    temp = output / f".{MANIFEST_NAME}.{os.getpid()}.tmp"
    try:
        temp.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        os.chmod(temp, 0o444)
        os.replace(temp, target)
    finally:
        temp.unlink(missing_ok=True)
    return payload


def _read_manifest(output: Path) -> dict:
    path = _manifest_path(output)
    if not path.is_file() or path.is_symlink():
        raise adapter.AdapterError(
            "semantic indexing requires the analysis manifest produced by this profile"
        )
    if path.stat().st_size > 64 * 1024:
        raise adapter.AdapterError("analysis manifest is oversized")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise adapter.AdapterError("analysis manifest is invalid") from exc
    if payload.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise adapter.AdapterError("unsupported analysis manifest schema")
    if not SHA256_RE.fullmatch(str(payload.get("artifact_sha256") or "")):
        raise adapter.AdapterError("analysis manifest has invalid artifact SHA-256")
    if not COMMIT_RE.fullmatch(str(payload.get("blutter_commit") or "")):
        raise adapter.AdapterError("analysis manifest has invalid Blutter commit")
    if payload.get("blutter_commit") != adapter.BLUTTER_COMMIT:
        raise adapter.AdapterError("analysis manifest belongs to another Blutter revision")
    runtime = payload.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("identity_status") != "identified":
        raise adapter.AdapterError("analysis manifest has incomplete runtime provenance")
    analysis_id = str(payload.get("analysis_id") or "")
    expected_id = f"flutter-aot:{payload['artifact_sha256']}"
    if analysis_id != expected_id:
        raise adapter.AdapterError("analysis manifest has inconsistent analysis_id")
    return payload


def _build_index_from_manifest(output: Path) -> dict:
    manifest = _read_manifest(output)
    return semantic.build_flutter_index(
        output,
        output / INDEX_NAME,
        analysis_id=manifest["analysis_id"],
        artifact_sha256=manifest["artifact_sha256"],
        blutter_commit=manifest["blutter_commit"],
        runtime=manifest["runtime"],
    )


def _analyze_command(args: argparse.Namespace) -> dict:
    libdir = adapter._safe_under(adapter.INPUT_ROOT, args.libdir)
    output = adapter._safe_under(adapter.OUTPUT_ROOT, args.output, must_exist=False)
    payload = adapter.analyze(args.libdir, args.output, args.timeout)
    if payload.get("status") != "ok":
        return payload

    runtime = payload.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("identity_status") != "identified":
        return {
            **payload,
            "status": "partial",
            "semantic_index": {
                "status": "unavailable",
                "reason": "analysis succeeded but runtime provenance is incomplete",
            },
        }

    manifest = _write_manifest(output, libdir, runtime)
    try:
        index_result = _build_index_from_manifest(output)
    except semantic.FlutterIndexError as exc:
        return {
            **payload,
            "status": "partial",
            "analysis_manifest": MANIFEST_NAME,
            "analysis_id": manifest["analysis_id"],
            "artifact_sha256": manifest["artifact_sha256"],
            "semantic_index": {"status": "error", "error": str(exc)},
        }
    return {
        **payload,
        "analysis_manifest": MANIFEST_NAME,
        "analysis_id": manifest["analysis_id"],
        "artifact_sha256": manifest["artifact_sha256"],
        "semantic_index": index_result,
    }


def _semantic_main() -> int:
    parser = argparse.ArgumentParser(
        description="Bounded semantic interface for the framework-flutter profile"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build_flutter_index")
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
        payload = _build_index_from_manifest(_output_dir(args.output))
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
        payload = semantic.map_dart_to_native(_index_path(args.output), args.symbol)
    adapter._emit(payload)
    return 0 if payload.get("status") not in {"failed", "timeout", "error"} else 2


def _parse_analyze_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze and index Flutter Dart AOT")
    parser.add_argument("libdir")
    parser.add_argument("output")
    parser.add_argument("--timeout", type=int, default=900)
    return parser.parse_args(sys.argv[2:])


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        if command == "health":
            payload = adapter.health()
            payload["semantic_index"] = {
                "schema_version": semantic.INDEX_SCHEMA_VERSION,
                "available": True,
                "storage": "sqlite",
                "automatic_after_successful_analysis": True,
                "operations": sorted(SEMANTIC_COMMANDS),
                "max_query_results": semantic.MAX_QUERY_LIMIT,
                "max_scan_bytes": semantic.MAX_SCAN_BYTES,
            }
            adapter._emit(payload)
            return 0
        if command == "analyze":
            payload = _analyze_command(_parse_analyze_args())
            adapter._emit(payload)
            return 0 if payload.get("status") not in {"failed", "timeout", "error"} else 2
        if command in SEMANTIC_COMMANDS:
            return _semantic_main()
        return adapter.main()
    except (adapter.AdapterError, semantic.FlutterIndexError) as exc:
        adapter._emit({"status": "error", "error": str(exc)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
