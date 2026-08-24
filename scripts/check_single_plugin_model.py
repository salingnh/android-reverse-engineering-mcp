#!/usr/bin/env python3
"""Enforce the single-plugin, MCP-only product model."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGINS_ROOT = ROOT / "plugins"
MARKETPLACE_FILE = ROOT / ".claude-plugin" / "marketplace.json"
SUPPORTED_PLUGIN = "safe-android-reverser"
SUPPORTED_SOURCE = "./plugins/safe-android-reverser"
LEGACY_PLUGIN = "android-reverse-engineering"


def fail(message: str) -> None:
    raise SystemExit(f"single-plugin model error: {message}")


plugin_dirs = sorted(path.name for path in PLUGINS_ROOT.iterdir() if path.is_dir())
if plugin_dirs != [SUPPORTED_PLUGIN]:
    fail(
        "plugins/ must contain only safe-android-reverser; "
        f"found {plugin_dirs}"
    )

legacy_root = PLUGINS_ROOT / LEGACY_PLUGIN
if legacy_root.exists():
    fail(f"legacy host-executed plugin must not exist: {legacy_root.relative_to(ROOT)}")

marketplace = json.loads(MARKETPLACE_FILE.read_text(encoding="utf-8"))
entries = marketplace.get("plugins")
if not isinstance(entries, list):
    fail("marketplace plugins must be a list")
if len(entries) != 1:
    fail(f"marketplace must expose exactly one plugin, found {len(entries)}")

entry = entries[0]
if entry.get("name") != SUPPORTED_PLUGIN:
    fail(f"unsupported marketplace plugin: {entry.get('name')!r}")
if entry.get("source") != SUPPORTED_SOURCE:
    fail(f"safe plugin source drift: {entry.get('source')!r}")

manifest = ROOT / "plugins" / SUPPORTED_PLUGIN / ".claude-plugin" / "plugin.json"
if not manifest.is_file():
    fail("safe-android-reverser plugin manifest is missing")

mcp_manifest = ROOT / "plugins" / SUPPORTED_PLUGIN / ".mcp.json"
if not mcp_manifest.is_file():
    fail("safe-android-reverser MCP manifest is missing")

print(
    "single-plugin model OK: marketplace=safe-android-reverser "
    "legacy_fallback=absent product_entrypoints=1"
)
