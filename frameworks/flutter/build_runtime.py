#!/usr/bin/env python3
"""Controlled build-time helper for producing one exact Blutter runtime binary.

This script is for CI/image BUILD stages only. It intentionally performs the
network-dependent Dart source fetch before the final analysis image exists.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

BLUTTER_ROOT = Path("/opt/blutter")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?$")
SNAPSHOT_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dart-version", required=True)
    parser.add_argument("--snapshot-hash", required=True)
    parser.add_argument("--arch", choices=["arm64"], default="arm64")
    parser.add_argument("--compressed-pointers", choices=["true", "false"], default="true")
    args = parser.parse_args()

    if not VERSION_RE.fullmatch(args.dart_version):
        raise SystemExit("invalid Dart version")
    if not SNAPSHOT_RE.fullmatch(args.snapshot_hash):
        raise SystemExit("invalid snapshot hash")

    sys.path.insert(0, str(BLUTTER_ROOT))
    from blutter import BlutterInput, cmake_blutter  # type: ignore
    from dartvm_fetch_build import DartLibInfo, fetch_and_build  # type: ignore

    info = DartLibInfo(
        args.dart_version,
        "android",
        args.arch,
        args.compressed_pointers == "true",
        args.snapshot_hash.lower(),
    )
    fetch_and_build(info)
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
    print(binary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
