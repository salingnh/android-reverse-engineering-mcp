from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .contracts import SandboxPolicy

IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{1,255}:[A-Za-z0-9_.-]{1,128}$")
MEMORY_RE = re.compile(r"^[1-9][0-9]*[kKmMgG]?$|^0\.[0-9]*[1-9][0-9]*[kKmMgG]$")
CPU_RE = re.compile(r"^(?:[1-9][0-9]*(?:\.[0-9]+)?|0\.[0-9]*[1-9][0-9]*)$")
MAX_LOG_BYTES = 512 * 1024


class RuntimeErrorSafe(RuntimeError):
    pass


@dataclass(frozen=True)
class RunResult:
    exit_code: int
    timed_out: bool
    stdout: str
    stderr: str


class ContainerRuntime:
    def __init__(
        self,
        runtime: str,
        *,
        host_uid: int,
        host_gid: int,
        auto_pull: bool = True,
    ) -> None:
        if runtime not in {"docker", "podman"}:
            raise RuntimeErrorSafe("container runtime must be docker or podman")
        if host_uid < 0 or host_gid < 0:
            raise RuntimeErrorSafe("invalid host uid/gid")
        self.runtime = runtime
        self.host_uid = host_uid
        self.host_gid = host_gid
        self.auto_pull = bool(auto_pull)

    @staticmethod
    def validate_policy(policy: SandboxPolicy) -> None:
        if not MEMORY_RE.fullmatch(policy.memory):
            raise RuntimeErrorSafe("invalid sandbox memory limit")
        if not CPU_RE.fullmatch(policy.cpus):
            raise RuntimeErrorSafe("invalid sandbox CPU limit")
        if not MEMORY_RE.fullmatch(policy.tmpfs_tmp) or not MEMORY_RE.fullmatch(policy.tmpfs_work):
            raise RuntimeErrorSafe("invalid sandbox tmpfs limit")
        if policy.network != "none":
            raise RuntimeErrorSafe("static capability runtime network must be disabled")

    def _tail(self, handle, limit: int = MAX_LOG_BYTES) -> str:
        handle.flush()
        size = handle.tell()
        handle.seek(max(0, size - limit))
        return handle.read(limit).decode("utf-8", "replace")

    def run_host(self, argv: list[str], *, timeout: int) -> RunResult:
        if not argv or any(not isinstance(item, str) or "\x00" in item for item in argv):
            raise RuntimeErrorSafe("invalid container-runtime argv")
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                proc = subprocess.run(
                    [self.runtime, *argv],
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=max(1, min(int(timeout), 3600)),
                    check=False,
                )
                code = proc.returncode
                timed_out = False
            except subprocess.TimeoutExpired:
                code = 124
                timed_out = True
            return RunResult(code, timed_out, self._tail(stdout), self._tail(stderr))

    def image_info(self, image: str) -> dict[str, Any] | None:
        self._validate_image(image)
        run = self.run_host(["image", "inspect", image], timeout=60)
        if run.exit_code != 0:
            return None
        try:
            payload = json.loads(run.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeErrorSafe(f"cannot parse image metadata for {image}") from exc
        if not isinstance(payload, list) or not payload or not isinstance(payload[0], dict):
            raise RuntimeErrorSafe(f"invalid image metadata for {image}")
        return payload[0]

    @staticmethod
    def labels(image_info: dict[str, Any]) -> dict[str, str]:
        config = image_info.get("Config") if isinstance(image_info.get("Config"), dict) else {}
        labels = config.get("Labels") if isinstance(config.get("Labels"), dict) else None
        if labels is None and isinstance(image_info.get("Labels"), dict):
            labels = image_info.get("Labels")
        return {str(k): str(v) for k, v in (labels or {}).items()}

    def ensure_image(self, image: str, *, required_labels: dict[str, str]) -> dict[str, str]:
        self._validate_image(image)
        info = self.image_info(image)
        if info is None:
            if not self.auto_pull:
                raise RuntimeErrorSafe(f"capability image is not installed: {image}")
            pull = self.run_host(["pull", image], timeout=1800)
            if pull.exit_code != 0:
                detail = (pull.stderr or pull.stdout or "pull failed")[-4000:]
                raise RuntimeErrorSafe(f"failed to pull capability image {image}: {detail}")
            info = self.image_info(image)
        if info is None:
            raise RuntimeErrorSafe(f"capability image unavailable after pull: {image}")
        labels = self.labels(info)
        for key, expected in required_labels.items():
            if labels.get(key) != expected:
                raise RuntimeErrorSafe(
                    f"capability image provenance mismatch for {key}: expected={expected!r} actual={labels.get(key)!r}"
                )
        return labels

    def volume(self, host: Path, target: str, mode: str) -> str:
        if mode not in {"ro", "rw"}:
            raise RuntimeErrorSafe("volume mode must be ro or rw")
        suffix = f"{mode},z" if self.runtime == "podman" else mode
        return f"--volume={host}:{target}:{suffix}"

    def locked_args(self, policy: SandboxPolicy) -> list[str]:
        self.validate_policy(policy)
        args = [
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            f"--pids-limit={policy.pids_limit}",
            f"--memory={policy.memory}",
            f"--cpus={policy.cpus}",
            f"--tmpfs=/tmp:rw,nosuid,nodev,size={policy.tmpfs_tmp}",
            f"--tmpfs=/work:rw,nosuid,nodev,size={policy.tmpfs_work}",
            f"--user={self.host_uid}:{self.host_gid}",
        ]
        if self.runtime == "podman":
            args.insert(2, "--userns=keep-id")
        return args

    def run_container(
        self,
        *,
        image: str,
        policy: SandboxPolicy,
        mounts: list[tuple[Path, str, str]],
        command: list[str],
        timeout: int,
        tmpfs: list[str] | None = None,
        env: dict[str, str] | None = None,
        stdin_lines: list[dict[str, Any]] | None = None,
    ) -> RunResult:
        self._validate_image(image)
        args = self.locked_args(policy)
        for spec in tmpfs or []:
            if "\x00" in spec or not spec.startswith("/"):
                raise RuntimeErrorSafe("invalid extra tmpfs specification")
            args.append(f"--tmpfs={spec}")
        for host, target, mode in mounts:
            if not Path(host).is_absolute() or not target.startswith("/"):
                raise RuntimeErrorSafe("container mounts require absolute paths")
            args.append(self.volume(Path(host), target, mode))
        for key, value in (env or {}).items():
            if not re.fullmatch(r"[A-Z0-9_]{1,128}", key) or "\x00" in value:
                raise RuntimeErrorSafe("invalid container environment")
            args.append(f"--env={key}={value}")
        args.append(image)
        args.extend(command)

        if stdin_lines is None:
            return self.run_host(args, timeout=timeout)

        with tempfile.TemporaryFile() as stdin, tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            for item in stdin_lines:
                stdin.write((json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8"))
            stdin.seek(0)
            try:
                proc = subprocess.run(
                    [self.runtime, *args],
                    stdin=stdin,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=max(1, min(int(timeout), 3600)),
                    check=False,
                )
                code = proc.returncode
                timed_out = False
            except subprocess.TimeoutExpired:
                code = 124
                timed_out = True
            return RunResult(code, timed_out, self._tail(stdout), self._tail(stderr))

    @staticmethod
    def parse_json_tail(run: RunResult) -> dict[str, Any]:
        for line in reversed(run.stdout.splitlines()):
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                return payload
        detail = (run.stderr or run.stdout or "container command failed")[-4000:]
        raise RuntimeErrorSafe(f"capability worker did not return JSON: {detail}")

    @staticmethod
    def _validate_image(image: str) -> None:
        if not isinstance(image, str) or not IMAGE_RE.fullmatch(image):
            raise RuntimeErrorSafe("invalid capability image reference")
