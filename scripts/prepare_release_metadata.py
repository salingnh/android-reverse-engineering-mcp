#!/usr/bin/env python3
"""Prepare Safe Android Reverser release metadata deterministically.

The helper updates the canonical plugin version plus the small set of user-facing
release-status sections that must move with a release. It is idempotent for the same
target version and fails closed when expected document structure is missing.
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
    release_status = (
        "## Release status\n\n"
        f"Current published release: **{target}**.\n\n"
        "Release metadata reaches `master` only after exact-head CI, immutable capability-image "
        "verification, and GitHub Release creation.\n"
    )
    readme = replace_once(
        readme,
        r"## Release status\n\n.*?(?=\n## Quick start\n)",
        release_status,
        label="README release status section",
        flags=re.DOTALL,
    )
    README_FILE.write_text(readme, encoding="utf-8")

    install = INSTALL_FILE.read_text(encoding="utf-8")
    install_intro = (
        "# Install, update and use Safe Android Reverser MCP\n\n"
        "This is the supported installation/update path for Safe Android Reverser.\n\n"
        f"Current published release is **{target}**. Release metadata is promoted to `master` only "
        "after exact-head CI and immutable capability-image verification complete.\n\n"
    )
    install = replace_once(
        install,
        r"# Install, update and use Safe Android Reverser MCP\n\n"
        r"This is the supported installation/update path for Safe Android Reverser\.\n\n"
        r".*?(?=## Distribution model from 0\.3\n)",
        install_intro,
        label="INSTALL release intro",
        flags=re.DOTALL,
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

    readme = README_FILE.read_text(encoding="utf-8")
    if f"Current published release: **{target}**." not in readme:
        raise SystemExit("README release status mismatch")
    if "Release candidate:" in readme.split("## Quick start", 1)[0]:
        raise SystemExit("README still advertises release candidate state")

    install = INSTALL_FILE.read_text(encoding="utf-8")
    if f"Current published release is **{target}**." not in install:
        raise SystemExit("INSTALL release status mismatch")
    if "Release candidate:" in install.split("## Distribution model", 1)[0]:
        raise SystemExit("INSTALL still advertises release candidate state")


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
