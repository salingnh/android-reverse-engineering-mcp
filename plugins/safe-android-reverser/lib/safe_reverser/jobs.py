from __future__ import annotations

import secrets
import time
from pathlib import Path
from typing import Any

from .paths import PathPolicyError, atomic_write_json, ensure_private_child, read_json_file

MAX_JOB_META = 128 * 1024
MAX_LIST_JOBS = 100
MAX_JOB_SCAN = 10_000


class JobStoreError(RuntimeError):
    pass


class AnalysisJobStore:
    def __init__(self, data_root: Path, capability_id: str) -> None:
        self.data_root = data_root.resolve()
        safe_id = capability_id.replace("/", "-")
        if not safe_id or safe_id in {".", ".."}:
            raise JobStoreError("invalid capability id for job store")
        try:
            capability_root = ensure_private_child(self.data_root, safe_id)
            self.root = ensure_private_child(capability_root, "jobs")
        except PathPolicyError as exc:
            raise JobStoreError(str(exc)) from exc

    def create(
        self, *, artifact: str, profile: str, controller_version: str
    ) -> tuple[str, Path, dict[str, Any]]:
        for _ in range(32):
            job_id = secrets.token_hex(6)
            job = self.root / job_id
            try:
                job.mkdir(mode=0o700)
            except FileExistsError:
                continue
            meta = {
                "job_id": job_id,
                "artifact": artifact,
                "profile": profile,
                "controller_version": controller_version,
                "created_at_epoch": int(time.time()),
                "status": "created",
            }
            self.write(job, meta)
            return job_id, job, meta
        raise JobStoreError("unable to allocate analysis job")

    def get(self, job_id: str) -> Path:
        if len(job_id) != 12 or any(ch not in "0123456789abcdef" for ch in job_id):
            raise JobStoreError("invalid analysis job id")
        path = self.root / job_id
        if path.is_symlink() or not path.is_dir() or path.resolve().parent != self.root:
            raise JobStoreError("analysis job not found")
        return path.resolve()

    def write(self, job: Path, payload: dict[str, Any]) -> None:
        try:
            atomic_write_json(job, "job.json", payload, max_bytes=MAX_JOB_META)
        except PathPolicyError as exc:
            raise JobStoreError(str(exc)) from exc

    def read(self, job: Path) -> dict[str, Any]:
        try:
            payload = read_json_file(job, "job.json", max_bytes=MAX_JOB_META)
        except PathPolicyError as exc:
            raise JobStoreError(str(exc)) from exc
        if payload.get("job_id") != job.name:
            raise JobStoreError("analysis job metadata does not match directory")
        return payload

    def list(self) -> list[dict[str, Any]]:
        rows: list[tuple[float, dict[str, Any]]] = []
        scanned = 0
        for path in self.root.iterdir():
            scanned += 1
            if scanned > MAX_JOB_SCAN:
                raise JobStoreError(
                    f"analysis job directory exceeds scan budget of {MAX_JOB_SCAN} entries"
                )
            if path.is_symlink() or not path.is_dir():
                continue
            try:
                meta = self.read(path)
                stamp = path.stat().st_mtime
            except (JobStoreError, OSError):
                continue
            rows.append((stamp, meta))
        rows.sort(key=lambda item: item[0], reverse=True)
        return [item[1] for item in rows[:MAX_LIST_JOBS]]
