#!/usr/bin/env python3
"""Fail CI when plugin, marketplace, wrapper, image and release tag drift apart."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = ROOT / "plugins" / "safe-android-reverser"
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def fail(message: str) -> None:
    raise SystemExit(f"release consistency error: {message}")


version = (PLUGIN_ROOT / "VERSION").read_text(encoding="utf-8").strip()
if not SEMVER_RE.fullmatch(version):
    fail(f"invalid VERSION value: {version!r}")

plugin = json.loads((PLUGIN_ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
if plugin.get("version") != version:
    fail(f"plugin.json version={plugin.get('version')!r}, expected {version!r}")

marketplace = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
entries = [item for item in marketplace.get("plugins", []) if item.get("name") == "safe-android-reverser"]
if len(entries) != 1:
    fail(f"expected exactly one safe-android-reverser marketplace entry, found {len(entries)}")
if entries[0].get("version") != version:
    fail(f"marketplace version={entries[0].get('version')!r}, expected {version!r}")

wrapper = (PLUGIN_ROOT / "bin" / "safe-reverser-mcp").read_text(encoding="utf-8")
required_wrapper_fragments = [
    'VERSION_FILE="$PLUGIN_ROOT/VERSION"',
    'ghcr.io/salingnh/safe-android-reverser:$VERSION',
    'SAFE_REVERSER_PLUGIN_VERSION=$VERSION',
    'org.opencontainers.image.version',
]
for fragment in required_wrapper_fragments:
    if fragment not in wrapper:
        fail(f"wrapper is missing release binding: {fragment}")

image_file = (ROOT / "sandbox" / "Dockerfile").read_text(encoding="utf-8")
required_image_fragments = [
    "ARG SAFE_REVERSER_VERSION",
    "org.opencontainers.image.version",
    "SAFE_REVERSER_IMAGE_VERSION",
    "COPY plugins/safe-android-reverser/VERSION /opt/safe-reverser/VERSION",
    'ENTRYPOINT ["python3", "/opt/safe-reverser/mcp_entrypoint.py"]',
]
for fragment in required_image_fragments:
    if fragment not in image_file:
        fail(f"Dockerfile is missing release binding: {fragment}")

workflow = (ROOT / ".github" / "workflows" / "build-safe-sandbox.yml").read_text(encoding="utf-8")
if "type=raw,value=" in workflow:
    fail("workflow must not publish a mutable hard-coded semver tag")
if "type=sha,prefix=sha-" not in workflow:
    fail("workflow must publish a commit-addressable sha-* tag")
if "type=match,pattern=safe-v(.*),group=1" not in workflow:
    fail("workflow must derive release image tags from safe-vX.Y.Z git tags")

ref_type = os.environ.get("GITHUB_REF_TYPE", "")
ref_name = os.environ.get("GITHUB_REF_NAME", "")
if ref_type == "tag":
    if not ref_name.startswith("safe-v"):
        fail(f"release workflow received unsupported tag: {ref_name}")
    tag_version = ref_name.removeprefix("safe-v")
    if tag_version != version:
        fail(f"git tag version={tag_version!r}, VERSION={version!r}")

print(f"release consistency OK: {version}")
