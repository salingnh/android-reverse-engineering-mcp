from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

MAX_JOB_SCAN = 10_000
MAX_PERSISTED_JOBS = 10_000
MAX_LIST_JOBS = 100
MAX_JOB_META_BYTES = 128 * 1024
JOB_ID_CHARS = frozenset("0123456789abcdef")


class StaticJobSafetyError(ValueError):
    pass


def secure_job_root(value: Path | str, *, create: bool) -> Path:
    lexical = Path(os.path.abspath(Path(value)))
    if not lexical.is_absolute():
        raise StaticJobSafetyError("static job root must be absolute")
    anchor = Path(lexical.anchor)
    current = anchor
    parts = lexical.parts[1:]
    for part in parts:
        current = current / part
        if current.exists() and current.is_symlink():
            raise StaticJobSafetyError("static job root contains a symlinked path component")
    if create:
        lexical.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not lexical.is_dir():
        raise StaticJobSafetyError("static job root must be an existing directory")
    current = anchor
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise StaticJobSafetyError("static job root contains a symlinked path component")
    return lexical.resolve()


def valid_job_id(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 12
        and all(ch in JOB_ID_CHARS for ch in value)
    )


def resolve_job(root: Path, job_id: str) -> Path:
    if not valid_job_id(job_id):
        raise StaticJobSafetyError("invalid job_id")
    root = root.resolve()
    path = root / job_id
    if path.is_symlink() or not path.is_dir():
        raise StaticJobSafetyError(f"job not found: {job_id}")
    resolved = path.resolve()
    if resolved.parent != root:
        raise StaticJobSafetyError("job path escapes static job root")
    return resolved


def _scan(root: Path):
    scanned = 0
    for path in root.iterdir():
        scanned += 1
        if scanned > MAX_JOB_SCAN:
            raise StaticJobSafetyError(
                f"static job root exceeds scan budget of {MAX_JOB_SCAN} entries"
            )
        yield path


def preflight_create(root: Path) -> None:
    jobs = 0
    for path in _scan(root.resolve()):
        if path.is_symlink() or not path.is_dir() or not valid_job_id(path.name):
            continue
        jobs += 1
        if jobs >= MAX_PERSISTED_JOBS:
            raise StaticJobSafetyError(
                f"static job root reached persisted-job limit of {MAX_PERSISTED_JOBS}"
            )


def read_metadata(job: Path) -> dict[str, Any]:
    meta = job / "job.json"
    if meta.is_symlink() or not meta.is_file() or meta.resolve().parent != job.resolve():
        return {"job_id": job.name, "metadata_status": "unavailable"}
    try:
        size = meta.stat().st_size
    except OSError:
        return {"job_id": job.name, "metadata_status": "unavailable"}
    if size > MAX_JOB_META_BYTES:
        return {
            "job_id": job.name,
            "metadata_status": "oversized",
            "metadata_bytes": size,
        }
    try:
        value = json.loads(meta.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {"job_id": job.name, "metadata_status": "invalid"}
    if not isinstance(value, dict) or value.get("job_id") != job.name:
        return {"job_id": job.name, "metadata_status": "invalid"}
    return value


def list_jobs(root: Path) -> dict[str, Any]:
    root = root.resolve()
    rows: list[tuple[float, dict[str, Any]]] = []
    for path in _scan(root):
        if path.is_symlink() or not path.is_dir() or not valid_job_id(path.name):
            continue
        resolved = path.resolve()
        if resolved.parent != root:
            continue
        try:
            stamp = path.stat().st_mtime
        except OSError:
            continue
        rows.append((stamp, read_metadata(resolved)))
    rows.sort(key=lambda item: item[0], reverse=True)
    return {
        "jobs": [item[1] for item in rows[:MAX_LIST_JOBS]],
        "limits": {
            "max_scan": MAX_JOB_SCAN,
            "max_persisted_jobs": MAX_PERSISTED_JOBS,
            "max_list_jobs": MAX_LIST_JOBS,
            "max_job_metadata_bytes": MAX_JOB_META_BYTES,
        },
    }
