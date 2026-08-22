from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any


class PathPolicyError(ValueError):
    pass


def secure_directory_root(value: Path | str, *, create: bool = False) -> Path:
    """Resolve a host directory without traversing existing symlink components."""

    lexical = Path(os.path.abspath(Path(value).expanduser()))
    anchor = Path(lexical.anchor)
    current = anchor
    parts = lexical.parts[1:] if lexical.is_absolute() else lexical.parts
    for part in parts:
        current = current / part
        if current.exists() and current.is_symlink():
            raise PathPolicyError("directory root contains a symlinked path component")
    if create:
        lexical.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not lexical.exists() or not lexical.is_dir():
        raise PathPolicyError("directory root must be an existing directory")
    current = anchor
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise PathPolicyError("directory root contains a symlinked path component")
    return lexical.resolve()


def secure_child(root: Path, value: str, *, must_exist: bool = True) -> Path:
    root = Path(os.path.abspath(root)).resolve()
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise PathPolicyError("path must be a non-empty string")
    raw = Path(value)
    if raw.is_absolute():
        raise PathPolicyError("absolute paths are not allowed")
    lexical = Path(os.path.abspath(root / raw))
    if lexical != root and root not in lexical.parents:
        raise PathPolicyError("path escapes allowed root")
    current = root
    if lexical != root:
        for part in lexical.relative_to(root).parts:
            current = current / part
            if current.is_symlink():
                raise PathPolicyError("symlinked path components are not allowed")
    resolved = lexical.resolve()
    if resolved != root and root not in resolved.parents:
        raise PathPolicyError("resolved path escapes allowed root")
    if must_exist and not resolved.exists():
        raise PathPolicyError("path does not exist")
    return resolved


def ensure_private_child(root: Path, name: str) -> Path:
    root = Path(os.path.abspath(root)).resolve()
    if not root.is_dir():
        raise PathPolicyError("data root must be an existing regular directory")
    candidate = root / name
    if candidate.is_symlink():
        raise PathPolicyError(f"{name} must not be a symlink")
    candidate.mkdir(mode=0o700, parents=False, exist_ok=True)
    if candidate.is_symlink():
        raise PathPolicyError(f"{name} must not be a symlink")
    resolved = candidate.resolve()
    if resolved.parent != root:
        raise PathPolicyError(f"{name} escapes data root")
    return resolved


def atomic_write_json(
    directory: Path, filename: str, payload: dict[str, Any], *, max_bytes: int
) -> None:
    directory = directory.resolve()
    target = directory / filename
    if target.is_symlink():
        raise PathPolicyError("metadata target must not be a symlink")
    encoded = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    if len(encoded) > max_bytes:
        raise PathPolicyError("metadata exceeds bounded size")
    temp: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=directory,
            prefix=f".{filename}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp = Path(handle.name)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, target)
        temp = None
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def read_json_file(
    directory: Path, filename: str, *, max_bytes: int
) -> dict[str, Any]:
    directory = directory.resolve()
    path = directory / filename
    if path.is_symlink() or not path.is_file() or path.resolve().parent != directory:
        raise PathPolicyError("metadata file is unavailable or unsafe")
    if path.stat().st_size > max_bytes:
        raise PathPolicyError("metadata file exceeds bounded size")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PathPolicyError("metadata file is invalid") from exc
    if not isinstance(value, dict):
        raise PathPolicyError("metadata file must contain an object")
    return value


def remove_direct_child(directory: Path, name: str) -> None:
    directory = directory.resolve()
    path = directory / name
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or path.resolve().parent != directory:
        raise PathPolicyError("refusing to remove unsafe child path")
    if not path.is_dir():
        raise PathPolicyError("expected removable child directory")
    shutil.rmtree(path)
