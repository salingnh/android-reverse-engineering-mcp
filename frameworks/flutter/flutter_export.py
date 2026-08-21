#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any

import safe_blutter_adapter as adapter

EXPORT_ROOT = Path(os.environ.get("SAFE_FLUTTER_EXPORT_ROOT", "/export")).resolve()
MAX_EXPORT_FILES = adapter.MAX_GENERATED_FILES
MAX_EXPORT_FILE_BYTES = adapter.MAX_GENERATED_FILE_BYTES
MAX_EXPORT_BYTES = adapter.REQUIRED_OUTPUT_VOLUME_BYTES
MAX_EXPORT_ENTRIES = 50_000
MAX_PATH_LENGTH = 4096


class FlutterExportError(adapter.AdapterError):
    pass


def _lexical_under_without_symlinks(root: Path, value: str) -> Path:
    root = Path(os.path.abspath(root))
    raw = Path(value)
    candidate = Path(os.path.abspath(raw if raw.is_absolute() else root / raw))
    if candidate != root and root not in candidate.parents:
        raise FlutterExportError(f"path escapes allowed export root: {value}")
    current = root
    if candidate != root:
        for part in candidate.relative_to(root).parts:
            current = current / part
            if current.is_symlink():
                raise FlutterExportError(f"symlinked export path is not allowed: {value}")
    return candidate


def _copy_regular_file(source: Path, destination: Path, expected_size: int) -> int:
    written = 0
    with source.open("rb") as src, destination.open("xb") as dst:
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > MAX_EXPORT_FILE_BYTES:
                raise FlutterExportError(
                    f"generated file exceeds {MAX_EXPORT_FILE_BYTES} bytes"
                )
            dst.write(chunk)
        dst.flush()
        os.fsync(dst.fileno())
    if written != expected_size:
        raise FlutterExportError("generated file changed while being exported")
    return written


def export_analysis(source: Path, destination_value: str) -> dict[str, Any]:
    source = source.resolve()
    output_root = adapter.OUTPUT_ROOT.resolve()
    if source == output_root or output_root not in source.parents or not source.is_dir():
        raise FlutterExportError("analysis source must be a child directory under /output")

    destination = _lexical_under_without_symlinks(EXPORT_ROOT, destination_value)
    if destination == EXPORT_ROOT or destination.parent != EXPORT_ROOT:
        raise FlutterExportError("export destination must be a direct child under /export")
    if destination.exists() or destination.is_symlink():
        raise FlutterExportError("export destination already exists; use a fresh job")
    EXPORT_ROOT.mkdir(parents=True, exist_ok=True)

    stage: Path | None = Path(
        tempfile.mkdtemp(prefix=".safe-flutter-export-", dir=EXPORT_ROOT)
    )
    files = 0
    entries = 0
    total_bytes = 0
    try:
        for dirpath, dirnames, filenames in os.walk(source, followlinks=False):
            base = Path(dirpath)
            rel_dir = base.relative_to(source)
            if len(rel_dir.as_posix()) > MAX_PATH_LENGTH:
                raise FlutterExportError("generated directory path is oversized")

            for name in list(dirnames):
                entries += 1
                if entries > MAX_EXPORT_ENTRIES:
                    raise FlutterExportError(
                        f"generated entries exceed {MAX_EXPORT_ENTRIES}"
                    )
                child = base / name
                if child.is_symlink():
                    raise FlutterExportError("symlinks are not allowed in analyzer output")
                mode = child.lstat().st_mode
                if not stat.S_ISDIR(mode):
                    raise FlutterExportError("non-directory entry found in analyzer output")
                rel = child.relative_to(source)
                if len(rel.as_posix()) > MAX_PATH_LENGTH:
                    raise FlutterExportError("generated directory path is oversized")
                (stage / rel).mkdir(parents=True, exist_ok=True)

            for name in filenames:
                entries += 1
                files += 1
                if entries > MAX_EXPORT_ENTRIES:
                    raise FlutterExportError(
                        f"generated entries exceed {MAX_EXPORT_ENTRIES}"
                    )
                if files > MAX_EXPORT_FILES:
                    raise FlutterExportError(
                        f"generated files exceed {MAX_EXPORT_FILES}"
                    )
                child = base / name
                if child.is_symlink():
                    raise FlutterExportError("symlinks are not allowed in analyzer output")
                mode = child.lstat().st_mode
                if not stat.S_ISREG(mode):
                    raise FlutterExportError("non-regular file found in analyzer output")
                rel = child.relative_to(source)
                if len(rel.as_posix()) > MAX_PATH_LENGTH:
                    raise FlutterExportError("generated file path is oversized")
                size = child.stat().st_size
                if size > MAX_EXPORT_FILE_BYTES:
                    raise FlutterExportError(
                        f"generated file exceeds {MAX_EXPORT_FILE_BYTES} bytes"
                    )
                if total_bytes + size > MAX_EXPORT_BYTES:
                    raise FlutterExportError(
                        f"generated output exceeds {MAX_EXPORT_BYTES} bytes"
                    )
                dest = stage / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                total_bytes += _copy_regular_file(child, dest, size)

        os.replace(stage, destination)
        stage = None
        return {
            "status": "ok",
            "destination": destination.name,
            "files": files,
            "entries": entries,
            "bytes": total_bytes,
            "limits": {
                "max_files": MAX_EXPORT_FILES,
                "max_entries": MAX_EXPORT_ENTRIES,
                "max_file_bytes": MAX_EXPORT_FILE_BYTES,
                "max_total_bytes": MAX_EXPORT_BYTES,
                "max_path_length": MAX_PATH_LENGTH,
            },
        }
    finally:
        if stage is not None and stage.exists():
            shutil.rmtree(stage, ignore_errors=True)
