#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re

CACHE_SCHEMA_VERSION = 3
CAPABILITY_API_VERSION = 1
WORKER_ABI_VERSION = 1
DART_VERSION_RE = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]{1,24})?$"
)
SNAPSHOT_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")
BLUTTER_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
SUPPORTED_ARCHES = {"arm64"}
SUPPORTED_OSES = {"android"}


def validate_runtime_identity(
    *,
    dart_version: str,
    snapshot_hash: str,
    arch: str,
    os_name: str,
    blutter_commit: str,
) -> dict[str, str]:
    dart_version = str(dart_version or "").strip()
    snapshot_hash = str(snapshot_hash or "").strip().lower()
    arch = str(arch or "").strip().lower()
    os_name = str(os_name or "").strip().lower()
    blutter_commit = str(blutter_commit or "").strip().lower()

    if not DART_VERSION_RE.fullmatch(dart_version):
        raise ValueError("invalid or unsupported Dart semantic version")
    if not SNAPSHOT_HASH_RE.fullmatch(snapshot_hash):
        raise ValueError("snapshot hash must be 32..64 hexadecimal characters")
    if arch not in SUPPORTED_ARCHES:
        raise ValueError(f"unsupported Flutter AOT architecture: {arch}")
    if os_name not in SUPPORTED_OSES:
        raise ValueError(f"unsupported Flutter AOT operating system: {os_name}")
    if not BLUTTER_COMMIT_RE.fullmatch(blutter_commit):
        raise ValueError("Blutter commit must be a full 40-character Git SHA")

    return {
        "dart_version": dart_version,
        "snapshot_hash": snapshot_hash,
        "arch": arch,
        "os": os_name,
        "blutter_commit": blutter_commit,
    }


def runtime_cache_tag(
    *,
    dart_version: str,
    snapshot_hash: str,
    arch: str,
    compressed_pointers: bool,
    blutter_commit: str,
    os_name: str | None = None,
    os: str | None = None,
) -> str:
    # `validate_runtime_identity()` returns the normalized field as `os` so its
    # mapping can be passed here directly. CLI/build callers may use `os_name`.
    runtime_os = os_name if os_name is not None else os
    if os_name is not None and os is not None and os_name != os:
        raise ValueError("conflicting Flutter runtime operating-system values")
    identity = validate_runtime_identity(
        dart_version=dart_version,
        snapshot_hash=snapshot_hash,
        arch=arch,
        os_name=str(runtime_os or ""),
        blutter_commit=blutter_commit,
    )
    canonical = {
        **identity,
        "compressed_pointers": bool(compressed_pointers),
        "cache_schema": CACHE_SCHEMA_VERSION,
        "capability_api": CAPABILITY_API_VERSION,
        "worker_abi": WORKER_ABI_VERSION,
    }
    digest = hashlib.sha256(
        json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()
    mode = "cp" if compressed_pointers else "ncp"
    tag = f"dart-{identity['dart_version']}-{identity['arch']}-{mode}-{digest}"
    if len(tag) > 128:
        raise ValueError("derived runtime cache tag exceeds OCI tag length")
    return tag


def runtime_request_identity(
    *,
    dart_version: str,
    snapshot_hash: str,
    arch: str,
    compressed_pointers: bool,
    blutter_commit: str,
    os_name: str | None = None,
    os: str | None = None,
) -> str:
    runtime_os = os_name if os_name is not None else os
    if os_name is not None and os is not None and os_name != os:
        raise ValueError("conflicting Flutter runtime operating-system values")
    identity = validate_runtime_identity(
        dart_version=dart_version,
        snapshot_hash=snapshot_hash,
        arch=arch,
        os_name=str(runtime_os or ""),
        blutter_commit=blutter_commit,
    )
    canonical = {
        **identity,
        "compressed_pointers": bool(compressed_pointers),
        "runtime_cache_schema": CACHE_SCHEMA_VERSION,
        "capability_api": CAPABILITY_API_VERSION,
        "worker_abi": WORKER_ABI_VERSION,
    }
    return hashlib.sha256(
        json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Derive exact Flutter runtime cache identity")
    parser.add_argument("--dart-version", required=True)
    parser.add_argument("--snapshot-hash", required=True)
    parser.add_argument("--arch", default="arm64")
    parser.add_argument("--os", dest="os_name", default="android")
    parser.add_argument("--compressed-pointers", choices=["true", "false"], default="true")
    parser.add_argument("--blutter-commit", required=True)
    parser.add_argument(
        "--output",
        choices=["cache-tag", "request-identity"],
        default="cache-tag",
    )
    args = parser.parse_args()
    function = (
        runtime_request_identity
        if args.output == "request-identity"
        else runtime_cache_tag
    )
    print(
        function(
            dart_version=args.dart_version,
            snapshot_hash=args.snapshot_hash,
            arch=args.arch,
            os_name=args.os_name,
            compressed_pointers=args.compressed_pointers == "true",
            blutter_commit=args.blutter_commit,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
