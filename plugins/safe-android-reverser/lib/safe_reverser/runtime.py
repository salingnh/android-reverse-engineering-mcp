from __future__ import annotations

import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .contracts import SandboxPolicy

IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{1,255}:[A-Za-z0-9_.-]{1,128}$")
IMAGE_ID_RE = re.compile(r"^(?:sha256:)?([0-9a-f]{64})$")
MEMORY_RE = re.compile(r"^[1-9][0-9]*[kKmMgG]?$|^0\.[0-9]*[1-9][0-9]*[kKmMgG]$")
CPU_RE = re.compile(r"^(?:[1-9][0-9]*(?:\.[0-9]+)?|0\.[0-9]*[1-9][0-9]*)$")
TMPFS_SPEC_RE = re.compile(
    r"^/[A-Za-z0-9._/-]{1,255}:rw,nosuid,nodev,size=([1-9][0-9]*[kKmMgG]?|0\.[0-9]*[1-9][0-9]*[kKmMgG])$"
)
MOUNT_TARGET_RE = re.compile(r"^/[A-Za-z0-9._/-]{0,255}$")
ENV_KEY_RE = re.compile(r"^[A-Z0-9_]{1,128}$")
MAX_LOG_BYTES = 512 * 1024
MAX_RUNTIME_ARGV = 256
MAX_RUNTIME_ARG_LENGTH = 8192
MAX_MOUNTS = 16
MAX_ENV_VARS = 64
MAX_ENV_VALUE = 8192
MAX_COMMAND_ARGS = 64
MAX_STDIN_LINES = 16
MAX_STDIN_BYTES = 4 * 1024 * 1024


class RuntimeErrorSafe(RuntimeError):
    pass


@dataclass(frozen=True)
class RunResult:
    exit_code: int
    timed_out: bool
    stdout: str
    stderr: str


@dataclass(frozen=True)
class VerifiedImage:
    requested_ref: str
    immutable_ref: str
    labels: dict[str, str]

    def get(self, key: str, default: Any = None) -> Any:
        return self.labels.get(key, default)


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
        if not MEMORY_RE.fullmatch(policy.tmpfs_tmp) or not MEMORY_RE.fullmatch(
            policy.tmpfs_work
        ):
            raise RuntimeErrorSafe("invalid sandbox tmpfs limit")
        if policy.network != "none":
            raise RuntimeErrorSafe("static capability runtime network must be disabled")

    @staticmethod
    def validate_tmpfs_spec(spec: str) -> None:
        if not isinstance(spec, str) or not TMPFS_SPEC_RE.fullmatch(spec):
            raise RuntimeErrorSafe("invalid extra tmpfs specification")

    @staticmethod
    def _validate_arg_list(
        values: list[str], *, field: str, max_items: int
    ) -> None:
        if not isinstance(values, list) or len(values) > max_items:
            raise RuntimeErrorSafe(f"{field} exceeds bounded argument count")
        for item in values:
            if (
                not isinstance(item, str)
                or "\x00" in item
                or len(item.encode("utf-8", "replace")) > MAX_RUNTIME_ARG_LENGTH
            ):
                raise RuntimeErrorSafe(f"invalid {field} argument")

    @staticmethod
    def _validate_mount(host: Path, target: str, mode: str) -> Path:
        if mode not in {"ro", "rw"}:
            raise RuntimeErrorSafe("volume mode must be ro or rw")
        source = Path(host)
        if not source.is_absolute() or not source.exists() or source.is_symlink():
            raise RuntimeErrorSafe("container mount source must be an existing absolute non-symlink path")
        resolved = source.resolve()
        if resolved != source:
            raise RuntimeErrorSafe("container mount source must already be canonical")
        source_text = str(source)
        if any(ch in source_text for ch in (":", "\x00", "\n", "\r")):
            raise RuntimeErrorSafe("container mount source contains unsupported delimiter characters")
        if not isinstance(target, str) or not MOUNT_TARGET_RE.fullmatch(target):
            raise RuntimeErrorSafe("invalid container mount target")
        if "//" in target or any(part in {".", ".."} for part in Path(target).parts):
            raise RuntimeErrorSafe("container mount target must be canonical")
        return resolved

    def _tail(self, handle, limit: int = MAX_LOG_BYTES) -> str:
        handle.flush()
        size = handle.tell()
        handle.seek(max(0, size - limit))
        return handle.read(limit).decode("utf-8", "replace")

    def run_host(self, argv: list[str], *, timeout: int) -> RunResult:
        self._validate_arg_list(argv, field="container-runtime argv", max_items=MAX_RUNTIME_ARGV)
        if not argv:
            raise RuntimeErrorSafe("container-runtime argv must not be empty")
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
            return RunResult(
                code, timed_out, self._tail(stdout), self._tail(stderr)
            )

    def image_info(self, image: str) -> dict[str, Any] | None:
        self._validate_image(image)
        run = self.run_host(["image", "inspect", image], timeout=60)
        if run.exit_code != 0:
            return None
        try:
            payload = json.loads(run.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeErrorSafe(f"cannot parse image metadata for {image}") from exc
        if (
            not isinstance(payload, list)
            or not payload
            or not isinstance(payload[0], dict)
        ):
            raise RuntimeErrorSafe(f"invalid image metadata for {image}")
        return payload[0]

    @staticmethod
    def labels(image_info: dict[str, Any]) -> dict[str, str]:
        config = (
            image_info.get("Config")
            if isinstance(image_info.get("Config"), dict)
            else {}
        )
        labels = (
            config.get("Labels") if isinstance(config.get("Labels"), dict) else None
        )
        if labels is None and isinstance(image_info.get("Labels"), dict):
            labels = image_info.get("Labels")
        return {str(k): str(v) for k, v in (labels or {}).items()}

    @staticmethod
    def immutable_image_ref(image_info: dict[str, Any]) -> str:
        raw = str(image_info.get("Id") or image_info.get("ID") or "").strip().lower()
        match = IMAGE_ID_RE.fullmatch(raw)
        if match is None:
            raise RuntimeErrorSafe("container runtime did not return a canonical image ID")
        return f"sha256:{match.group(1)}"

    def ensure_image(
        self, image: str, *, required_labels: dict[str, str]
    ) -> VerifiedImage:
        self._validate_image(image)
        info = self.image_info(image)
        if info is None:
            if not self.auto_pull:
                raise RuntimeErrorSafe(f"capability image is not installed: {image}")
            pull = self.run_host(["pull", image], timeout=1800)
            if pull.exit_code != 0:
                detail = (pull.stderr or pull.stdout or "pull failed")[-4000:]
                raise RuntimeErrorSafe(
                    f"failed to pull capability image {image}: {detail}"
                )
            info = self.image_info(image)
        if info is None:
            raise RuntimeErrorSafe(
                f"capability image unavailable after pull: {image}"
            )
        labels = self.labels(info)
        for key, expected in required_labels.items():
            if labels.get(key) != expected:
                raise RuntimeErrorSafe(
                    f"capability image provenance mismatch for {key}: "
                    f"expected={expected!r} actual={labels.get(key)!r}"
                )
        return VerifiedImage(
            requested_ref=image,
            immutable_ref=self.immutable_image_ref(info),
            labels=labels,
        )

    def volume(self, host: Path, target: str, mode: str) -> str:
        source = self._validate_mount(host, target, mode)
        suffix = f"{mode},z" if self.runtime == "podman" else mode
        return f"--volume={source}:{target}:{suffix}"

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
        self._validate_arg_list(command, field="worker command", max_items=MAX_COMMAND_ARGS)
        if not isinstance(mounts, list) or len(mounts) > MAX_MOUNTS:
            raise RuntimeErrorSafe("container mounts exceed bounded count")
        if env is not None and (not isinstance(env, dict) or len(env) > MAX_ENV_VARS):
            raise RuntimeErrorSafe("container environment exceeds bounded count")
        if stdin_lines is not None and (
            not isinstance(stdin_lines, list) or len(stdin_lines) > MAX_STDIN_LINES
        ):
            raise RuntimeErrorSafe("container stdin messages exceed bounded count")

        args = self.locked_args(policy)
        if stdin_lines is not None:
            args.append("--interactive")
        for spec in tmpfs or []:
            self.validate_tmpfs_spec(spec)
            args.append(f"--tmpfs={spec}")
        for item in mounts:
            if not isinstance(item, tuple) or len(item) != 3:
                raise RuntimeErrorSafe("invalid container mount descriptor")
            host, target, mode = item
            args.append(self.volume(Path(host), target, mode))
        for key, value in (env or {}).items():
            if (
                not isinstance(key, str)
                or not ENV_KEY_RE.fullmatch(key)
                or not isinstance(value, str)
                or "\x00" in value
                or len(value.encode("utf-8", "replace")) > MAX_ENV_VALUE
            ):
                raise RuntimeErrorSafe("invalid container environment")
            args.append(f"--env={key}={value}")
        args.append(image)
        args.extend(command)

        if stdin_lines is None:
            return self.run_host(args, timeout=timeout)

        encoded_lines: list[bytes] = []
        total_stdin = 0
        for item in stdin_lines:
            if not isinstance(item, dict):
                raise RuntimeErrorSafe("container stdin messages must be JSON objects")
            try:
                encoded = (
                    json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n"
                ).encode("utf-8")
            except (TypeError, ValueError) as exc:
                raise RuntimeErrorSafe("container stdin message is not JSON serializable") from exc
            total_stdin += len(encoded)
            if total_stdin > MAX_STDIN_BYTES:
                raise RuntimeErrorSafe("container stdin exceeds bounded byte budget")
            encoded_lines.append(encoded)

        with tempfile.TemporaryFile() as stdin, tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            for encoded in encoded_lines:
                stdin.write(encoded)
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
            return RunResult(
                code, timed_out, self._tail(stdout), self._tail(stderr)
            )

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
