#!/usr/bin/env python3
"""Fail CI when plugin, capability contracts, worker images, workflows or release tags drift."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = ROOT / "plugins" / "safe-android-reverser"
CAPABILITY_ROOT = PLUGIN_ROOT / "capabilities"
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
CAPABILITY_API = 1
WORKER_ABI = 1


def fail(message: str) -> None:
    raise SystemExit(f"release consistency error: {message}")


version = (PLUGIN_ROOT / "VERSION").read_text(encoding="utf-8").strip()
if not SEMVER_RE.fullmatch(version):
    fail(f"invalid VERSION value: {version!r}")

plugin = json.loads(
    (PLUGIN_ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
)
if plugin.get("version") != version:
    fail(f"plugin.json version={plugin.get('version')!r}, expected {version!r}")

marketplace = json.loads(
    (ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8")
)
entries = [
    item
    for item in marketplace.get("plugins", [])
    if item.get("name") == "safe-android-reverser"
]
if len(entries) != 1:
    fail(
        f"expected exactly one safe-android-reverser marketplace entry, found {len(entries)}"
    )
if entries[0].get("version") != version:
    fail(f"marketplace version={entries[0].get('version')!r}, expected {version!r}")

mcp_manifest = json.loads((PLUGIN_ROOT / ".mcp.json").read_text(encoding="utf-8"))
servers = mcp_manifest.get("mcpServers")
if not isinstance(servers, dict) or set(servers) != {"safe-android-reverser"}:
    fail("plugin must expose exactly one public safe-android-reverser MCP server")
server = servers["safe-android-reverser"]
if server.get("command") != "${CLAUDE_PLUGIN_ROOT}/bin/safe-reverser-mcp":
    fail("public MCP server must use the host control-plane launcher")

wrapper = (PLUGIN_ROOT / "bin" / "safe-reverser-mcp").read_text(encoding="utf-8")
required_wrapper_fragments = [
    'VERSION_FILE="$PLUGIN_ROOT/VERSION"',
    'SAFE_REVERSER_PLUGIN_VERSION="$VERSION"',
    'mcp-control-plane.py',
]
for fragment in required_wrapper_fragments:
    if fragment not in wrapper:
        fail(f"control-plane launcher is missing release binding: {fragment}")
if " image inspect " in wrapper or '"$RUNTIME" pull' in wrapper:
    fail("launcher must not own capability image lifecycle; Runtime Driver owns it")

expected_capabilities = {
    "static-core": {
        "protocol": "mcp-stdio",
        "repository": "ghcr.io/salingnh/safe-android-reverser",
    },
    "framework-flutter": {
        "protocol": "cli-json",
        "repository": "ghcr.io/salingnh/safe-android-reverser-flutter",
    },
}
seen_operations: set[str] = set()
for capability_id, expected in expected_capabilities.items():
    path = CAPABILITY_ROOT / f"{capability_id}.json"
    if not path.is_file():
        fail(f"missing capability manifest: {path.relative_to(ROOT)}")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("id") != capability_id:
        fail(f"capability manifest id drift: {path.name}")
    if manifest.get("capability_api") != CAPABILITY_API:
        fail(f"capability_api drift in {path.name}")
    if manifest.get("worker_abi") != WORKER_ABI:
        fail(f"worker_abi drift in {path.name}")
    if manifest.get("protocol") != expected["protocol"]:
        fail(f"worker protocol drift in {path.name}")
    image = manifest.get("image") or {}
    if image.get("repository") != expected["repository"]:
        fail(f"worker image repository drift in {path.name}")
    operations = manifest.get("operations")
    if not isinstance(operations, list) or not operations:
        fail(f"capability operations missing in {path.name}")
    overlap = seen_operations.intersection(operations)
    if overlap:
        fail(f"public operation ownership collides: {sorted(overlap)}")
    seen_operations.update(operations)

image_checks = {
    ROOT / "sandbox" / "Dockerfile": [
        'io.safe-reverser.capability.id="static-core"',
        'io.safe-reverser.capability.api="1"',
        'io.safe-reverser.worker.abi="1"',
    ],
    ROOT / "frameworks" / "flutter" / "Dockerfile": [
        'io.safe-reverser.capability.id="framework-flutter"',
        'io.safe-reverser.capability.api="1"',
        'io.safe-reverser.worker.abi="1"',
    ],
    ROOT / "frameworks" / "flutter" / "Dockerfile.runtime": [
        'io.safe-reverser.capability.id="framework-flutter"',
        'io.safe-reverser.capability.api="1"',
        'io.safe-reverser.worker.abi="1"',
        'io.safe-reverser.runtime-cache.schema="2"',
    ],
}
for path, fragments in image_checks.items():
    text = path.read_text(encoding="utf-8")
    if "ARG SAFE_REVERSER_VERSION" not in text or "org.opencontainers.image.version" not in text:
        fail(f"worker image lacks release version binding: {path.relative_to(ROOT)}")
    for fragment in fragments:
        if fragment not in text:
            fail(f"worker image lacks contract label {fragment}: {path.relative_to(ROOT)}")

for workflow_name in ("build-safe-sandbox.yml", "build-flutter-profile.yml"):
    workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(
        encoding="utf-8"
    )
    if "type=raw,value=" in workflow:
        fail(f"{workflow_name} must not publish a mutable hard-coded semver tag")
    if "type=sha,prefix=sha-" not in workflow:
        fail(f"{workflow_name} must publish a commit-addressable sha-* tag")
    if "type=match,pattern=safe-v(.*),group=1" not in workflow:
        fail(f"{workflow_name} must derive release image tags from safe-vX.Y.Z git tags")

ref_type = os.environ.get("GITHUB_REF_TYPE", "")
ref_name = os.environ.get("GITHUB_REF_NAME", "")
if ref_type == "tag":
    if not ref_name.startswith("safe-v"):
        fail(f"release workflow received unsupported tag: {ref_name}")
    tag_version = ref_name.removeprefix("safe-v")
    if tag_version != version:
        fail(f"git tag version={tag_version!r}, VERSION={version!r}")

print(
    f"release consistency OK: version={version} capability_api={CAPABILITY_API} worker_abi={WORKER_ABI}"
)
