#!/usr/bin/env python3
"""Fail CI when plugin, capability contracts, worker images, workflows or release tags drift."""
from __future__ import annotations

import importlib.util
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
EVIDENCE_ENVELOPE = 1
FLUTTER_CACHE_SCHEMA = 2
RESERVED_PUBLIC_OPERATIONS = {"health", "list_capabilities"}


def fail(message: str) -> None:
    raise SystemExit(f"release consistency error: {message}")


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        fail(f"cannot load contract module: {path.relative_to(ROOT)}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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

for legacy in (
    PLUGIN_ROOT / "bin" / "safe-flutter-mcp",
    PLUGIN_ROOT / "bin" / "flutter-mcp-host.py",
    ROOT / "sandbox" / "mcp_server_v2.py",
):
    if legacy.exists():
        fail(f"legacy orchestration/server file must not return: {legacy.relative_to(ROOT)}")
if not (ROOT / "sandbox" / "static_semantic_worker.py").is_file():
    fail("canonical static semantic worker is missing")

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
if "mkdir -p \"$DATA_DIR\"" in wrapper:
    fail("launcher must not create data root before shared path-policy validation")

expected_capabilities = {
    "static-core": {
        "activation": "required",
        "adapter": "mcp-container",
        "protocol": "mcp-stdio",
        "repository": "ghcr.io/salingnh/safe-android-reverser",
    },
    "framework-flutter": {
        "activation": "required",
        "adapter": "flutter-aot",
        "protocol": "cli-json",
        "repository": "ghcr.io/salingnh/safe-android-reverser-flutter",
    },
}
manifest_ids = {path.stem for path in CAPABILITY_ROOT.glob("*.json")}
if manifest_ids != set(expected_capabilities):
    fail(
        f"0.3 capability manifest set drift: actual={sorted(manifest_ids)} expected={sorted(expected_capabilities)}"
    )

seen_operations: set[str] = set()
for capability_id, expected in expected_capabilities.items():
    path = CAPABILITY_ROOT / f"{capability_id}.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("id") != capability_id:
        fail(f"capability manifest id drift: {path.name}")
    if manifest.get("capability_api") != CAPABILITY_API:
        fail(f"capability_api drift in {path.name}")
    if manifest.get("worker_abi") != WORKER_ABI:
        fail(f"worker_abi drift in {path.name}")
    for field in ("activation", "adapter", "protocol"):
        if manifest.get(field) != expected[field]:
            fail(f"{field} drift in {path.name}")
    image = manifest.get("image") or {}
    if image.get("repository") != expected["repository"]:
        fail(f"worker image repository drift in {path.name}")
    operations = manifest.get("operations")
    if not isinstance(operations, list) or not operations:
        fail(f"capability operations missing in {path.name}")
    reserved = RESERVED_PUBLIC_OPERATIONS.intersection(operations)
    if reserved:
        fail(f"capability owns reserved public operations in {path.name}: {sorted(reserved)}")
    overlap = seen_operations.intersection(operations)
    if overlap:
        fail(f"public operation ownership collides: {sorted(overlap)}")
    seen_operations.update(operations)

init_text = (PLUGIN_ROOT / "lib" / "safe_reverser" / "__init__.py").read_text(
    encoding="utf-8"
)
for fragment in (
    f"CAPABILITY_API_VERSION = {CAPABILITY_API}",
    f"WORKER_ABI_VERSION = {WORKER_ABI}",
    f"EVIDENCE_ENVELOPE_VERSION = {EVIDENCE_ENVELOPE}",
):
    if fragment not in init_text:
        fail(f"host platform contract constant drift: {fragment}")

flutter_cache = load_module(
    "release_flutter_cache_identity", ROOT / "frameworks" / "flutter" / "cache_identity.py"
)
if flutter_cache.CAPABILITY_API_VERSION != CAPABILITY_API:
    fail("Flutter cache identity capability API drift")
if flutter_cache.WORKER_ABI_VERSION != WORKER_ABI:
    fail("Flutter cache identity Worker ABI drift")
if flutter_cache.CACHE_SCHEMA_VERSION != FLUTTER_CACHE_SCHEMA:
    fail("Flutter runtime-cache schema drift")

runtime_text = (PLUGIN_ROOT / "lib" / "safe_reverser" / "runtime.py").read_text(
    encoding="utf-8"
)
worker_text = (PLUGIN_ROOT / "lib" / "safe_reverser" / "worker.py").read_text(
    encoding="utf-8"
)
flutter_text = (PLUGIN_ROOT / "lib" / "safe_reverser" / "flutter.py").read_text(
    encoding="utf-8"
)
control_text = (PLUGIN_ROOT / "lib" / "safe_reverser" / "control_plane.py").read_text(
    encoding="utf-8"
)
for fragment in ("class VerifiedImage", "immutable_image_ref", "immutable_ref"):
    if fragment not in runtime_text:
        fail(f"Runtime Driver lost immutable-image contract marker: {fragment}")
for fragment in (
    "MAX_MOUNTS",
    "MAX_COMMAND_ARGS",
    "MAX_STDIN_BYTES",
    "_validate_mount",
):
    if fragment not in runtime_text:
        fail(f"Runtime Driver lost bounded invocation marker: {fragment}")
for fragment in ("verified.immutable_ref", "SAFE_REVERSER_IMAGE_ID"):
    if fragment not in worker_text:
        fail(f"MCP worker lost immutable-image execution marker: {fragment}")
for fragment in (
    "runtime_image_id",
    "_immutable_ref(verified",
    "_probe_base_worker",
    "runtime_download_inside_sandbox",
):
    if fragment not in flutter_text:
        fail(f"Flutter adapter lost worker verification marker: {fragment}")
for fragment in (
    "MAX_REQUEST_CHARS",
    "MAX_REQUEST_BYTES",
    "MAX_TOOL_TEXT_BYTES",
    "_bounded_request_lines",
    "result exceeds bounded response size",
):
    if fragment not in control_text:
        fail(f"control plane lost bounded MCP framing marker: {fragment}")

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
    if (
        "ARG SAFE_REVERSER_VERSION" not in text
        or "org.opencontainers.image.version" not in text
    ):
        fail(f"worker image lacks release version binding: {path.relative_to(ROOT)}")
    for fragment in fragments:
        if fragment not in text:
            fail(
                f"worker image lacks contract label {fragment}: {path.relative_to(ROOT)}"
            )

for workflow_name in (
    "build-safe-sandbox.yml",
    "build-flutter-profile.yml",
):
    workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(
        encoding="utf-8"
    )
    if "type=raw,value=" in workflow:
        fail(f"{workflow_name} must not publish a mutable hard-coded semver tag")
    if "type=sha,prefix=sha-" not in workflow:
        fail(f"{workflow_name} must publish a commit-addressable sha-* tag")
    if "type=match,pattern=safe-v(.*),group=1" not in workflow:
        fail(
            f"{workflow_name} must derive release image tags from safe-vX.Y.Z git tags"
        )

control_workflow = (
    ROOT / ".github" / "workflows" / "test-control-plane.yml"
).read_text(encoding="utf-8")
for fragment in (
    "test_platform_architecture.py",
    "test_public_operation_contract.py",
    "test_cross_worker_contracts.py",
    "test_runtime_image_pinning.py",
    "test_platform_bounds.py",
    "SAFE_REVERSER_CAPABILITY_IMAGE_STATIC_CORE",
    "SAFE_REVERSER_CAPABILITY_IMAGE_FRAMEWORK_FLUTTER",
    "capabilities']['diagnostics']",
    "image_id'].startswith('sha256:')",
    "network_required_at_runtime",
):
    if fragment not in control_workflow:
        fail(f"control-plane CI is missing contract gate: {fragment}")

ref_type = os.environ.get("GITHUB_REF_TYPE", "")
ref_name = os.environ.get("GITHUB_REF_NAME", "")
if ref_type == "tag":
    if not ref_name.startswith("safe-v"):
        fail(f"release workflow received unsupported tag: {ref_name}")
    tag_version = ref_name.removeprefix("safe-v")
    if tag_version != version:
        fail(f"git tag version={tag_version!r}, VERSION={version!r}")

print(
    "release consistency OK: "
    f"version={version} capability_api={CAPABILITY_API} "
    f"worker_abi={WORKER_ABI} evidence={EVIDENCE_ENVELOPE} "
    f"flutter_cache_schema={FLUTTER_CACHE_SCHEMA} "
    "immutable_image_execution=required bounded_platform_io=required"
)
