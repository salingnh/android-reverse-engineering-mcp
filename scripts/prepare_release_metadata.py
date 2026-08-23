#!/usr/bin/env python3
"""Prepare Safe Android Reverser release metadata deterministically.

This script is intentionally narrow: it updates the canonical plugin version and the
small set of user-facing release-status locations that must move with a release.
It is idempotent for the same target version and fails closed when expected document
markers are missing.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_FILE = ROOT / "plugins/safe-android-reverser/VERSION"
PLUGIN_FILE = ROOT / "plugins/safe-android-reverser/.claude-plugin/plugin.json"
MARKETPLACE_FILE = ROOT / ".claude-plugin/marketplace.json"
README_FILE = ROOT / "README.md"
INSTALL_FILE = ROOT / "docs/INSTALL_MCP.md"
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def parse_version(value: str) -> tuple[int, int, int]:
    value = value.strip()
    if not SEMVER_RE.fullmatch(value):
        raise SystemExit(f"invalid release version: {value!r}; expected X.Y.Z")
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def replace_once(text: str, pattern: str, replacement: str, *, label: str, flags: int = 0) -> str:
    updated, count = re.subn(pattern, replacement, text, count=1, flags=flags)
    if count != 1:
        raise SystemExit(f"release metadata marker not found exactly once: {label}")
    return updated


def prepare(target: str) -> None:
    target_tuple = parse_version(target)
    current = VERSION_FILE.read_text(encoding="utf-8").strip()
    current_tuple = parse_version(current)
    if target_tuple < current_tuple:
        raise SystemExit(f"release version must not go backwards: current={current}, target={target}")

    VERSION_FILE.write_text(target + "\n", encoding="utf-8")

    plugin = load_json(PLUGIN_FILE)
    if plugin.get("name") != "safe-android-reverser":
        raise SystemExit("unexpected plugin manifest identity")
    plugin["version"] = target
    write_json(PLUGIN_FILE, plugin)

    marketplace = load_json(MARKETPLACE_FILE)
    matches = [item for item in marketplace.get("plugins", []) if item.get("name") == "safe-android-reverser"]
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one safe-android-reverser marketplace entry, found {len(matches)}")
    matches[0]["version"] = target
    write_json(MARKETPLACE_FILE, marketplace)

    readme = README_FILE.read_text(encoding="utf-8")
    readme = replace_once(
        readme,
        r"Current published release: \*\*[0-9]+\.[0-9]+\.[0-9]+\*\*\.",
        f"Current published release: **{target}**.",
        label="README current published release",
    )
    # Replace the old milestone-specific warning when present with a durable release rule.
    readme = re.sub(
        r"\n\*\*[^\n]*active[^\n]*milestone[^\n]*\*\*\n",
        "\nRelease metadata reaches `master` only after exact-head CI, immutable capability-image verification, and GitHub Release creation.\n",
        readme,
        count=1,
        flags=re.IGNORECASE,
    )
    README_FILE.write_text(readme, encoding="utf-8")

    install = INSTALL_FILE.read_text(encoding="utf-8")
    install = replace_once(
        install,
        r"Current published release is \*\*[0-9]+\.[0-9]+\.[0-9]+\*\*\.[^\n]*",
        (
            f"Current published release is **{target}**. Release metadata is promoted to `master` "
            "only after exact-head CI and immutable capability-image verification complete."
        ),
        label="INSTALL current published release paragraph",
    )
    INSTALL_FILE.write_text(install, encoding="utf-8")


def verify(target: str) -> None:
    parse_version(target)
    actual = VERSION_FILE.read_text(encoding="utf-8").strip()
    if actual != target:
        raise SystemExit(f"VERSION mismatch: expected {target}, found {actual}")

    plugin = load_json(PLUGIN_FILE)
    if plugin.get("version") != target:
        raise SystemExit("plugin.json version mismatch")

    marketplace = load_json(MARKETPLACE_FILE)
    matches = [item for item in marketplace.get("plugins", []) if item.get("name") == "safe-android-reverser"]
    if len(matches) != 1 or matches[0].get("version") != target:
        raise SystemExit("marketplace safe-android-reverser version mismatch")

    if f"Current published release: **{target}**." not in README_FILE.read_text(encoding="utf-8"):
        raise SystemExit("README release status mismatch")
    if f"Current published release is **{target}**." not in INSTALL_FILE.read_text(encoding="utf-8"):
        raise SystemExit("INSTALL release status mismatch")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("version", help="semantic release version X.Y.Z")
    parser.add_argument("--check", action="store_true", help="verify metadata instead of modifying files")
    args = parser.parse_args()

    if args.check:
        verify(args.version)
    else:
        prepare(args.version)
        verify(args.version)
