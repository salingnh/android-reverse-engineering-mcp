#!/usr/bin/env python3
"""Controlled build-time helper for producing one exact Blutter runtime binary.

This script is for CI/image BUILD stages only. Network-dependent Dart source
retrieval occurs here, never in the final analysis runtime. It also preserves the
Dart SDK redistribution license alongside the generated binary.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from cache_identity import validate_runtime_identity

BLUTTER_ROOT = Path("/opt/blutter")
LICENSE_ROOT = Path("/opt/licenses")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dart-version", required=True)
    parser.add_argument("--snapshot-hash", required=True)
    parser.add_argument("--arch", choices=["arm64"], default="arm64")
    parser.add_argument("--compressed-pointers", choices=["true", "false"], default="true")
    parser.add_argument("--blutter-commit", required=True)
    args = parser.parse_args()

    try:
        identity = validate_runtime_identity(
            dart_version=args.dart_version,
            snapshot_hash=args.snapshot_hash,
            arch=args.arch,
            os_name="android",
            blutter_commit=args.blutter_commit,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    sys.path.insert(0, str(BLUTTER_ROOT))
    from blutter import BlutterInput, cmake_blutter  # type: ignore
    from dartvm_fetch_build import (  # type: ignore
        DartLibInfo,
        checkout_dart,
        cmake_dart,
    )

    info = DartLibInfo(
        identity["dart_version"],
        identity["os"],
        identity["arch"],
        args.compressed_pointers == "true",
        identity["snapshot_hash"],
    )

    dart_checkout = Path(checkout_dart(info)).resolve()
    if not (dart_checkout / ".git").is_dir():
        raise SystemExit("controlled Dart checkout is missing Git metadata needed for license provenance")

    # Upstream Blutter removes most Dart top-level files after sparse checkout,
    # but retains .git. Read the exact checked-out revision's LICENSE from Git
    # object storage before producing a redistributable static runtime binary.
    license_text = subprocess.run(
        ["git", "-C", str(dart_checkout), "show", "HEAD:LICENSE"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout
    if "Redistribution and use in source and binary forms" not in license_text:
        raise SystemExit("unexpected Dart SDK license content")
    LICENSE_ROOT.mkdir(parents=True, exist_ok=True)
    (LICENSE_ROOT / "DART-SDK-LICENSE").write_text(license_text, encoding="utf-8")

    cmake_dart(info, str(dart_checkout))
    build_input = BlutterInput(
        "/dev/null",
        info,
        "/tmp/blutter-build-output",
        True,
        False,
        False,
    )
    cmake_blutter(build_input)
    binary = Path(build_input.blutter_file)
    if not binary.is_file():
        raise SystemExit(f"expected Blutter binary was not produced: {binary}")
    if not (LICENSE_ROOT / "DART-SDK-LICENSE").is_file():
        raise SystemExit("Dart SDK redistribution license was not preserved")
    print(binary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
