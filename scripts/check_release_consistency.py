#!/usr/bin/env python3
"""Fail CI when plugin, capability contracts, worker images, workflows or release tags drift."""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = ROOT / "plugins" / "safe-android-reverser"
CAPABILITY_ROOT = PLUGIN_ROOT / "capabilities"
PLUGIN_LIB = PLUGIN_ROOT / "lib"
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
CAPABILITY_API = 1
WORKER_ABI = 1
EVIDENCE_ENVELOPE = 1
FLUTTER_CACHE_SCHEMA = 3
RESERVED_PUBLIC_OPERATIONS = {"health", "list_capabilities"}

# A release can require a baseline subset without making it the forever-complete
# capability list. Additional compatible manifests are valid extensions.
REQUIRED_BASELINE = {
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


def fail(message: str) -> None:
    raise SystemExit(f"release consistency error: {message}")


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        fail(f"cannot load contract module: {path.relative_to(ROOT)}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if str(PLUGIN_LIB) not in sys.path:
    sys.path.insert(0, str(PLUGIN_LIB))

from safe_reverser import (  # noqa: E402
    CAPABILITY_API_VERSION,
    EVIDENCE_ENVELOPE_VERSION,
    WORKER_ABI_VERSION,
)
from safe_reverser.registry import CapabilityRegistry  # noqa: E402


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

# Dead-reference regression gate: renaming the canonical worker must also update
# tests/importers. Construct the legacy name so the checker does not self-match.
legacy_module_name = "mcp_" + "server_v2"
for scan_root in (ROOT / "sandbox", PLUGIN_ROOT / "tests"):
    for path in scan_root.rglob("*.py"):
        if legacy_module_name in path.read_text(encoding="utf-8"):
            fail(
                "legacy static worker module reference remains: "
                f"{path.relative_to(ROOT)} -> {legacy_module_name}"
            )

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

# Parse every manifest through the real Capability SPI. Registry construction
# validates schema, trust/activation/network semantics and operation collisions.
try:
    registry = CapabilityRegistry(CAPABILITY_ROOT)
except Exception as exc:
    fail(f"capability registry validation failed: {exc}")

manifests = registry.manifests()
missing_baseline = set(REQUIRED_BASELINE) - set(manifests)
if missing_baseline:
    fail(f"required baseline capabilities are missing: {sorted(missing_baseline)}")

for capability_id, manifest in manifests.items():
    if manifest.capability_api != CAPABILITY_API:
        fail(f"capability_api drift in {capability_id}")
    if manifest.worker_abi != WORKER_ABI:
        fail(f"worker_abi drift in {capability_id}")
    reserved = RESERVED_PUBLIC_OPERATIONS.intersection(manifest.operations)
    if reserved:
        fail(
            f"capability owns reserved public operations in {capability_id}: {sorted(reserved)}"
        )

for capability_id, expected in REQUIRED_BASELINE.items():
    manifest = manifests[capability_id]
    for field in ("activation", "adapter", "protocol"):
        actual = getattr(manifest, field)
        if actual != expected[field]:
            fail(
                f"{field} drift in baseline capability {capability_id}: "
                f"actual={actual!r} expected={expected[field]!r}"
            )
    if manifest.image_repository != expected["repository"]:
        fail(
            f"worker image repository drift in baseline capability {capability_id}: "
            f"actual={manifest.image_repository!r} expected={expected['repository']!r}"
        )

if CAPABILITY_API_VERSION != CAPABILITY_API:
    fail("host Capability API constant drift")
if WORKER_ABI_VERSION != WORKER_ABI:
    fail("host Worker ABI constant drift")
if EVIDENCE_ENVELOPE_VERSION != EVIDENCE_ENVELOPE:
    fail("host EvidenceEnvelope constant drift")

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
        'io.safe-reverser.runtime-cache.schema="3"',
        'io.safe-reverser.dart.os="${TARGET_OS}"',
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
    "issubset",
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
    f"baseline={sorted(REQUIRED_BASELINE)} manifests={sorted(manifests)} "
    "immutable_image_execution=required bounded_platform_io=required"
)
