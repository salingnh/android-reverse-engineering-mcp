#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

BLUTTER_ROOT = Path(os.environ.get("SAFE_BLUTTER_ROOT", "/opt/blutter")).resolve()
INPUT_ROOT = Path(os.environ.get("SAFE_FLUTTER_INPUT", "/input")).resolve()
OUTPUT_ROOT = Path(os.environ.get("SAFE_FLUTTER_OUTPUT", "/output")).resolve()
BLUTTER_COMMIT = os.environ.get("SAFE_BLUTTER_COMMIT", "unknown")
MAX_PROCESS_OUTPUT = 120_000


class AdapterError(Exception):
    pass


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))


def _safe_under(root: Path, value: str, *, must_exist: bool = True) -> Path:
    raw = Path(value)
    candidate = raw.resolve() if raw.is_absolute() else (root / raw).resolve()
    if candidate != root and root not in candidate.parents:
        raise AdapterError(f"path escapes allowed root: {value}")
    if must_exist and not candidate.exists():
        raise AdapterError(f"path does not exist: {value}")
    return candidate


def _lib_paths(libdir: Path) -> tuple[Path, Path]:
    libapp = (libdir / "libapp.so").resolve()
    libflutter = (libdir / "libflutter.so").resolve()
    if libapp.parent != libdir or libflutter.parent != libdir:
        raise AdapterError("invalid Flutter library directory")
    if not libapp.is_file() or not libflutter.is_file():
        raise AdapterError("input directory must contain libapp.so and libflutter.so")
    return libapp, libflutter


def _import_blutter():
    sys.path.insert(0, str(BLUTTER_ROOT))
    try:
        from blutter import BlutterInput, get_dart_lib_info  # type: ignore
    except Exception as exc:
        raise AdapterError(f"cannot import pinned Blutter source: {type(exc).__name__}: {exc}") from exc
    return BlutterInput, get_dart_lib_info


def _runtime_info(libdir: Path) -> tuple[Any, dict[str, Any]]:
    libapp, libflutter = _lib_paths(libdir)
    BlutterInput, get_dart_lib_info = _import_blutter()
    try:
        info = get_dart_lib_info(str(libapp), str(libflutter))
    except SystemExit as exc:
        raise AdapterError(f"Blutter runtime identification failed: {exc}") from exc
    except Exception as exc:
        raise AdapterError(f"Blutter runtime identification failed: {type(exc).__name__}: {exc}") from exc
    probe = BlutterInput(str(libapp), info, "/output/probe", False, False, False)
    binary = Path(probe.blutter_file).resolve()
    if binary != BLUTTER_ROOT and BLUTTER_ROOT not in binary.parents:
        raise AdapterError("derived Blutter binary path escapes pinned analyzer root")
    payload = {
        "dart_version": str(info.version),
        "os": str(info.os_name),
        "arch": str(info.arch),
        "snapshot_hash": info.snapshot_hash,
        "compressed_pointers": bool(info.has_compressed_ptrs),
        "runtime_key": str(info.lib_name),
        "expected_binary": str(binary.relative_to(BLUTTER_ROOT)),
        "binary_cached": binary.is_file(),
    }
    return info, payload


def health() -> dict[str, Any]:
    binaries = []
    bin_dir = BLUTTER_ROOT / "bin"
    if bin_dir.is_dir():
        binaries = sorted(
            path.name for path in bin_dir.iterdir() if path.is_file() and path.name.startswith("blutter_")
        )[:500]
    return {
        "profile": "framework-flutter",
        "adapter": "safe-blutter-adapter",
        "blutter_commit": BLUTTER_COMMIT,
        "blutter_root": str(BLUTTER_ROOT),
        "network_required_at_runtime": False,
        "build_on_demand_allowed": False,
        "cached_binary_count": len(binaries),
        "cached_binaries": binaries,
    }


def inspect(libdir_value: str) -> dict[str, Any]:
    libdir = _safe_under(INPUT_ROOT, libdir_value)
    if not libdir.is_dir():
        raise AdapterError("libdir must be a directory")
    _, runtime = _runtime_info(libdir)
    return {
        "status": "ready" if runtime["binary_cached"] else "runtime_cache_miss",
        "profile": "framework-flutter",
        "blutter_commit": BLUTTER_COMMIT,
        "runtime": runtime,
        "next_action": (
            "run_analyze" if runtime["binary_cached"] else "publish a framework-flutter image containing the exact prebuilt runtime analyzer"
        ),
    }


def analyze(libdir_value: str, output_value: str, timeout: int) -> dict[str, Any]:
    libdir = _safe_under(INPUT_ROOT, libdir_value)
    output = _safe_under(OUTPUT_ROOT, output_value, must_exist=False)
    if not libdir.is_dir():
        raise AdapterError("libdir must be a directory")
    if output.exists() and not output.is_dir():
        raise AdapterError("output must be a directory")
    output.mkdir(parents=True, exist_ok=True)
    libapp, _ = _lib_paths(libdir)
    _, runtime = _runtime_info(libdir)
    binary = (BLUTTER_ROOT / runtime["expected_binary"]).resolve()
    if not runtime["binary_cached"]:
        return {
            "status": "runtime_cache_miss",
            "profile": "framework-flutter",
            "blutter_commit": BLUTTER_COMMIT,
            "runtime": runtime,
            "executed": False,
            "reason": "Blutter build-on-demand is disabled in the analysis runtime",
        }

    timeout = max(1, min(int(timeout), 3600))
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/tmp/home",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TMPDIR": "/tmp",
    }
    Path("/tmp/home").mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            [str(binary), "-i", str(libapp), "-o", str(output)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            env=env,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raw = exc.stdout or ""
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace")
        return {
            "status": "timeout",
            "profile": "framework-flutter",
            "runtime": runtime,
            "executed": True,
            "exit_code": 124,
            "output": raw[-MAX_PROCESS_OUTPUT:],
        }

    generated = []
    if output.is_dir():
        generated = sorted(
            str(path.relative_to(output))
            for path in output.rglob("*")
            if path.is_file()
        )[:20_000]
    return {
        "status": "ok" if proc.returncode == 0 else "failed",
        "profile": "framework-flutter",
        "blutter_commit": BLUTTER_COMMIT,
        "runtime": runtime,
        "executed": True,
        "exit_code": proc.returncode,
        "output": proc.stdout[-MAX_PROCESS_OUTPUT:],
        "generated_files": generated,
        "generated_files_truncated": len(generated) >= 20_000,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline-safe wrapper around a pinned Blutter checkout")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("health")
    inspect_parser = sub.add_parser("inspect")
    inspect_parser.add_argument("libdir")
    analyze_parser = sub.add_parser("analyze")
    analyze_parser.add_argument("libdir")
    analyze_parser.add_argument("output")
    analyze_parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    try:
        if args.command == "health":
            payload = health()
        elif args.command == "inspect":
            payload = inspect(args.libdir)
        else:
            payload = analyze(args.libdir, args.output, args.timeout)
        _emit(payload)
        return 0 if payload.get("status") not in {"failed", "timeout"} else 2
    except AdapterError as exc:
        _emit({"status": "error", "error": str(exc)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
