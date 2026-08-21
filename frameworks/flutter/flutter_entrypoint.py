#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path

import flutter_network as network
import flutter_semantic as semantic
import safe_blutter_adapter as adapter

SEMANTIC_COMMANDS = {
    "build_flutter_index",
    "find_dart_symbols",
    "find_dart_strings",
    "find_dart_xrefs",
    "map_dart_to_native",
    "extract_flutter_network_model",
}
INDEX_NAME = "flutter-index.sqlite"
MANIFEST_NAME = "safe-flutter-analysis.json"
MANIFEST_SCHEMA_VERSION = 1
MAX_HASH_INPUT_BYTES = 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_BUILD_IDENTITY_LENGTH = 128
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise adapter.AdapterError("libapp.so must be a regular file")
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


def _build_identity(env_name: str) -> str:
    value = str(os.environ.get(env_name, "unknown") or "unknown").strip()
    if not value or len(value) > MAX_BUILD_IDENTITY_LENGTH:
        raise adapter.AdapterError(f"invalid {env_name} provenance value")
    return value


def _lexical_under_without_symlinks(root: Path, value: str) -> Path:
    """Validate a caller-supplied path without following existing symlink components."""

    root = Path(os.path.abspath(root))
    raw = Path(value)
    candidate = Path(os.path.abspath(raw if raw.is_absolute() else root / raw))
    if candidate != root and root not in candidate.parents:
        raise adapter.AdapterError(f"path escapes allowed root: {value}")

    current = root
    if candidate != root:
        for part in candidate.relative_to(root).parts:
            current = current / part
            if current.is_symlink():
                raise adapter.AdapterError(
                    f"symlinked path components are not allowed: {value}"
                )
    return candidate


def _output_dir(value: str, *, must_exist: bool = True) -> Path:
    _lexical_under_without_symlinks(adapter.OUTPUT_ROOT, value)
    path = adapter._safe_under(adapter.OUTPUT_ROOT, value, must_exist=must_exist)
    if must_exist and not path.is_dir():
        raise adapter.AdapterError("Flutter analysis output must be a directory")
    return path


def _fresh_analysis_output(value: str) -> Path:
    output = _output_dir(value, must_exist=False)
    if output == adapter.OUTPUT_ROOT:
        raise adapter.AdapterError(
            "analysis output must be a dedicated child directory under /output"
        )
    if output.exists():
        if not output.is_dir():
            raise adapter.AdapterError("analysis output must be a directory")
        try:
            next(output.iterdir())
        except StopIteration:
            pass
        else:
            raise adapter.AdapterError(
                "analysis output must be new or empty; stale Blutter evidence is not reusable"
            )
    return output


def _index_path(value: str) -> Path:
    output = _output_dir(value)
    lexical = output / INDEX_NAME
    if lexical.is_symlink():
        raise adapter.AdapterError("Flutter semantic index must not be a symlink")
    index = lexical.resolve()
    if index.parent != output or not index.is_file():
        raise adapter.AdapterError(
            f"Flutter semantic index not found: {value}/{INDEX_NAME}"
        )
    return index


def _manifest_path(output: Path) -> Path:
    output = output.resolve()
    path = output / MANIFEST_NAME
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
        "image_version": _build_identity("SAFE_REVERSER_IMAGE_VERSION"),
        "build_commit": _build_identity("SAFE_REVERSER_BUILD_COMMIT"),
    }
    target = _manifest_path(output)
    if target.is_symlink() or target.exists():
        raise adapter.AdapterError(
            "analysis manifest already exists or is symlinked; use a fresh output"
        )

    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output,
            prefix=f".{MANIFEST_NAME}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            json.dump(
                payload,
                handle,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, 0o444)
        os.replace(temp_path, target)
        temp_path = None
    except (OSError, TypeError, ValueError) as exc:
        raise adapter.AdapterError("failed to persist analysis manifest") from exc
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
    return payload


def _read_manifest(output: Path) -> dict:
    path = _manifest_path(output)
    if path.is_symlink() or not path.is_file():
        raise adapter.AdapterError(
            "semantic indexing requires the analysis manifest produced by this profile"
        )
    if path.resolve().parent != output.resolve():
        raise adapter.AdapterError("analysis manifest escapes its output directory")
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise adapter.AdapterError("analysis manifest is oversized")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise adapter.AdapterError("analysis manifest is invalid") from exc
    if not isinstance(payload, dict):
        raise adapter.AdapterError("analysis manifest must be a JSON object")
    if payload.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise adapter.AdapterError("unsupported analysis manifest schema")
    if payload.get("artifact_kind") != "libapp.so":
        raise adapter.AdapterError("analysis manifest has an unsupported artifact kind")
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
    for key in ("image_version", "build_commit"):
        value = payload.get(key)
        if not isinstance(value, str) or not value or len(value) > MAX_BUILD_IDENTITY_LENGTH:
            raise adapter.AdapterError(f"analysis manifest has invalid {key}")
    return payload


def _build_index_from_manifest(output: Path) -> dict:
    manifest = _read_manifest(output)
    index = output / INDEX_NAME
    if index.is_symlink():
        raise adapter.AdapterError("Flutter semantic index must not be a symlink")
    return semantic.build_flutter_index(
        output,
        index,
        analysis_id=manifest["analysis_id"],
        artifact_sha256=manifest["artifact_sha256"],
        blutter_commit=manifest["blutter_commit"],
        runtime=manifest["runtime"],
        image_version=manifest["image_version"],
        build_commit=manifest["build_commit"],
    )


def _analyze_command(args: argparse.Namespace) -> dict:
    libdir = adapter._safe_under(adapter.INPUT_ROOT, args.libdir)
    if not libdir.is_dir():
        raise adapter.AdapterError("libdir must be a directory")
    _fresh_analysis_output(args.output)

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

    # adapter.analyze creates the output directory. Re-resolve it after execution,
    # while the no-symlink/fresh-output policy was already enforced before execution.
    output = _output_dir(args.output)
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

    model = sub.add_parser("extract_flutter_network_model")
    model.add_argument("output")
    model.add_argument("--limit", type=int, default=100)

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
    elif args.command == "map_dart_to_native":
        payload = semantic.map_dart_to_native(_index_path(args.output), args.symbol)
    else:
        payload = network.extract_flutter_network_model(
            _index_path(args.output), args.limit
        )
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
                "network_model_max_items": network.MAX_MODEL_ITEMS,
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
