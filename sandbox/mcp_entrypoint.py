#!/usr/bin/env python3
"""Release-aware entrypoint for the isolated static-core capability worker."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import mcp_server_v2 as server

SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def _release_version() -> str:
    candidates = [
        os.environ.get("SAFE_REVERSER_IMAGE_VERSION", ""),
        Path(__file__).with_name("VERSION").read_text(encoding="utf-8").strip()
        if Path(__file__).with_name("VERSION").is_file()
        else "",
    ]
    for value in candidates:
        value = value.strip()
        if SEMVER_RE.fullmatch(value):
            return value
    raise RuntimeError("safe-android-reverser image has no valid release version metadata")


RELEASE_VERSION = _release_version()
server.core.SERVER_VERSION = RELEASE_VERSION
_original_health = server.health


def health(args: dict[str, Any]) -> dict[str, Any]:
    result = _original_health(args)
    plugin_version = os.environ.get("SAFE_REVERSER_PLUGIN_VERSION") or None
    image_version = os.environ.get("SAFE_REVERSER_IMAGE_VERSION") or RELEASE_VERSION
    versions = [RELEASE_VERSION, image_version]
    if plugin_version:
        versions.append(plugin_version)
    result["release"] = {
        "server_version": RELEASE_VERSION,
        "plugin_version": plugin_version,
        "image_version": image_version,
        "image_ref": os.environ.get("SAFE_REVERSER_IMAGE_REF") or None,
        "image_id": os.environ.get("SAFE_REVERSER_IMAGE_ID") or None,
        "build_commit": os.environ.get("SAFE_REVERSER_BUILD_COMMIT") or None,
        "version_consistent": len(set(versions)) == 1,
    }
    result["capability_worker"] = {
        "id": "static-core",
        "capability_api": 1,
        "worker_abi": 1,
        "runtime_readiness_authority": "host-control-plane",
    }
    return result


server.core.TOOL_HANDLERS["health"] = health


if __name__ == "__main__":
    raise SystemExit(server.core.main())
