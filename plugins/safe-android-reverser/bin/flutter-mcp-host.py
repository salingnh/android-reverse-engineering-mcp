#!/usr/bin/env python3
"""Host-side MCP controller for the isolated Flutter capability profile.

The controller never analyzes application bytes itself. It validates paths and
selects immutable capability images, while all untrusted artifact parsing and
Blutter execution happen inside locked, network-disabled containers.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

SERVER_NAME = "safe-android-reverser-flutter"
SERVER_VERSION = str(os.environ.get("SAFE_REVERSER_PLUGIN_VERSION", "unknown")).strip()
RUNTIME = str(os.environ.get("SAFE_REVERSER_RUNTIME", "")).strip()
PROJECT_DIR = Path(os.environ.get("SAFE_REVERSER_PROJECT_DIR", ".")).resolve()
DATA_DIR = Path(os.environ.get("SAFE_REVERSER_DATA_DIR", ".")).resolve()
FLUTTER_DATA = DATA_DIR / "flutter"
FLUTTER_REPOSITORY = str(
    os.environ.get(
        "SAFE_REVERSER_FLUTTER_REPOSITORY",
        "ghcr.io/salingnh/safe-android-reverser-flutter",
    )
).strip()
BASE_IMAGE = str(
    os.environ.get(
        "SAFE_REVERSER_FLUTTER_IMAGE",
        f"{FLUTTER_REPOSITORY}:{SERVER_VERSION}",
    )
).strip()
AUTO_PULL = os.environ.get("SAFE_REVERSER_AUTO_PULL", "1") == "1"
HOST_UID = str(os.environ.get("SAFE_REVERSER_HOST_UID", os.getuid()))
HOST_GID = str(os.environ.get("SAFE_REVERSER_HOST_GID", os.getgid()))
MEMORY = str(os.environ.get("SAFE_REVERSER_FLUTTER_MEMORY", "6g")).strip()
CPUS = str(os.environ.get("SAFE_REVERSER_FLUTTER_CPUS", "2")).strip()
PIDS = str(os.environ.get("SAFE_REVERSER_PIDS_LIMIT", "256")).strip()
RUNTIME_CACHE_SCHEMA = 2
OUTPUT_TMPFS_SIZE = str(os.environ.get("SAFE_REVERSER_FLUTTER_OUTPUT_TMPFS", "4g")).strip()
MAX_TOOL_TEXT = 300_000
MAX_RUNTIME_LOG = 512_000
MAX_JOB_META = 128 * 1024
MAX_QUERY_TEXT = 512
MAX_SYMBOL_TEXT = 1024
MAX_QUERY_LIMIT = 200
ALLOWED_ARTIFACT_EXTS = {".apk", ".xapk", ".apks", ".apkm"}
JOB_ID_RE = re.compile(r"^[0-9a-f]{12}$")
TAG_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{1,199}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SNAPSHOT_RE = re.compile(r"^[0-9a-f]{32,64}$")
MEMORY_RE = re.compile(r"^[1-9][0-9]*[kKmMgG]?$|^0\.[0-9]*[1-9][0-9]*[kKmMgG]$")
CPU_RE = re.compile(r"^(?:[1-9][0-9]*(?:\.[0-9]+)?|0\.[0-9]*[1-9][0-9]*)$")


class ControllerError(Exception):
    pass


def _json_text(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)
    if len(text) > MAX_TOOL_TEXT:
        text = text[:MAX_TOOL_TEXT] + "\n... [truncated]"
    return text


def _flutter_data_root(*, create: bool = True) -> Path:
    root = FLUTTER_DATA
    if root.is_symlink():
        raise ControllerError("Flutter data directory must not be a symlink")
    if create:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not root.exists() or not root.is_dir():
        raise ControllerError("Flutter data directory is unavailable")
    resolved = root.resolve()
    if resolved.parent != DATA_DIR:
        raise ControllerError("Flutter data directory escapes plugin data root")
    return resolved


def _validate_config() -> None:
    if RUNTIME not in {"docker", "podman"}:
        raise ControllerError("SAFE_REVERSER_RUNTIME must be docker or podman")
    if not SERVER_VERSION or SERVER_VERSION == "unknown":
        raise ControllerError("SAFE_REVERSER_PLUGIN_VERSION is missing")
    if not PROJECT_DIR.is_dir():
        raise ControllerError("project directory does not exist")
    if not DATA_DIR.is_dir():
        raise ControllerError("plugin data directory does not exist")
    _flutter_data_root(create=False) if FLUTTER_DATA.exists() else None
    if not REPOSITORY_RE.fullmatch(FLUTTER_REPOSITORY):
        raise ControllerError("invalid Flutter image repository")
    if not BASE_IMAGE.startswith(FLUTTER_REPOSITORY + ":"):
        raise ControllerError("Flutter base image must use the configured repository")
    tag = BASE_IMAGE.rsplit(":", 1)[-1]
    if not TAG_RE.fullmatch(tag):
        raise ControllerError("invalid Flutter base image tag")
    if not HOST_UID.isdigit() or not HOST_GID.isdigit():
        raise ControllerError("invalid host uid/gid")
    if not PIDS.isdigit() or int(PIDS) < 16 or int(PIDS) > 4096:
        raise ControllerError("invalid PID limit")
    if not MEMORY_RE.fullmatch(MEMORY):
        raise ControllerError("invalid SAFE_REVERSER_FLUTTER_MEMORY")
    if not MEMORY_RE.fullmatch(OUTPUT_TMPFS_SIZE):
        raise ControllerError("invalid SAFE_REVERSER_FLUTTER_OUTPUT_TMPFS")
    if not CPU_RE.fullmatch(CPUS):
        raise ControllerError("invalid SAFE_REVERSER_FLUTTER_CPUS")


def _safe_relative(root: Path, value: str, *, must_exist: bool = True) -> Path:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ControllerError("path must be a non-empty relative string")
    raw = Path(value)
    if raw.is_absolute():
        raise ControllerError("absolute paths are not allowed")
    lexical = Path(os.path.abspath(root / raw))
    root_abs = Path(os.path.abspath(root))
    if lexical != root_abs and root_abs not in lexical.parents:
        raise ControllerError("path escapes the allowed root")
    current = root_abs
    if lexical != root_abs:
        for part in lexical.relative_to(root_abs).parts:
            current = current / part
            if current.is_symlink():
                raise ControllerError("symlinked path components are not allowed")
    resolved = lexical.resolve()
    if resolved != root and root not in resolved.parents:
        raise ControllerError("resolved path escapes the allowed root")
    if must_exist and not resolved.exists():
        raise ControllerError("path does not exist")
    return resolved


def _artifact(value: str) -> tuple[Path, str]:
    path = _safe_relative(PROJECT_DIR, value)
    if path.is_symlink() or not path.is_file():
        raise ControllerError("artifact must be a regular project file")
    if path.suffix.lower() not in ALLOWED_ARTIFACT_EXTS:
        raise ControllerError(f"unsupported artifact type: {path.suffix}")
    return path, path.relative_to(PROJECT_DIR).as_posix()


def _jobs_root() -> Path:
    flutter_root = _flutter_data_root()
    root = flutter_root / "jobs"
    if root.is_symlink():
        raise ControllerError("Flutter jobs directory must not be a symlink")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved = root.resolve()
    if resolved.parent != flutter_root:
        raise ControllerError("invalid Flutter jobs directory")
    return resolved


def _new_job() -> tuple[str, Path]:
    root = _jobs_root()
    for _ in range(32):
        job_id = secrets.token_hex(6)
        job = root / job_id
        try:
            job.mkdir(mode=0o700)
            return job_id, job
        except FileExistsError:
            continue
    raise ControllerError("unable to allocate a Flutter job id")


def _job(job_id: str) -> Path:
    if not JOB_ID_RE.fullmatch(str(job_id or "")):
        raise ControllerError("invalid Flutter job_id")
    root = _jobs_root()
    path = root / job_id
    if path.is_symlink() or not path.is_dir() or path.resolve().parent != root:
        raise ControllerError("Flutter job not found")
    return path.resolve()


def _write_job(job: Path, payload: dict[str, Any]) -> None:
    target = job / "job.json"
    if target.is_symlink():
        raise ControllerError("Flutter job metadata must not be a symlink")
    encoded = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_JOB_META:
        raise ControllerError("Flutter job metadata exceeds safe size")
    temp: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=job, prefix=".job.", suffix=".tmp", delete=False
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


def _read_job(job: Path) -> dict[str, Any]:
    path = job / "job.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JOB_META:
        raise ControllerError("Flutter job metadata is unavailable or invalid")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ControllerError("Flutter job metadata is invalid") from exc
    if not isinstance(payload, dict) or payload.get("job_id") != job.name:
        raise ControllerError("Flutter job metadata does not match its directory")
    return payload


def _remove_prepared_input(job: Path) -> None:
    path = job / "input"
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or path.resolve().parent != job:
        raise ControllerError("prepared Flutter input path is unsafe")
    if not path.is_dir():
        raise ControllerError("prepared Flutter input is not a directory")
    shutil.rmtree(path)


def _tail(handle, limit: int) -> str:
    handle.flush()
    size = handle.tell()
    handle.seek(max(0, size - limit))
    return handle.read(limit).decode("utf-8", "replace")


def _run_runtime(args: list[str], *, timeout: int) -> dict[str, Any]:
    if not args or any(not isinstance(item, str) or "\x00" in item for item in args):
        raise ControllerError("invalid container-runtime argv")
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            proc = subprocess.run(
                [RUNTIME, *args],
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                timeout=max(1, min(int(timeout), 3600)),
                check=False,
            )
            timed_out = False
            code = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            code = 124
        return {
            "exit_code": code,
            "timed_out": timed_out,
            "stdout": _tail(stdout, MAX_RUNTIME_LOG),
            "stderr": _tail(stderr, MAX_RUNTIME_LOG),
        }


def _parse_payload(run: dict[str, Any]) -> dict[str, Any]:
    for line in reversed(str(run.get("stdout") or "").splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    detail = (run.get("stderr") or run.get("stdout") or "container command failed")[-4000:]
    raise ControllerError(f"Flutter capability did not return JSON: {detail}")


def _volume(host: Path, target: str, mode: str) -> str:
    suffix = f"{mode},z" if RUNTIME == "podman" else mode
    return f"--volume={host}:{target}:{suffix}"


def _common_container_args() -> list[str]:
    args = [
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--pids-limit={PIDS}",
        f"--memory={MEMORY}",
        f"--cpus={CPUS}",
        "--tmpfs=/tmp:rw,nosuid,nodev,size=1g",
        "--tmpfs=/work:rw,nosuid,nodev,size=512m",
        f"--user={HOST_UID}:{HOST_GID}",
    ]
    if RUNTIME == "podman":
        args.insert(2, "--userns=keep-id")
    return args


def _inspect_image(image: str) -> dict[str, Any] | None:
    run = _run_runtime(["image", "inspect", image], timeout=60)
    if run["exit_code"] != 0:
        return None
    try:
        payload = json.loads(run["stdout"])
    except json.JSONDecodeError as exc:
        raise ControllerError(f"cannot parse image metadata for {image}") from exc
    if not isinstance(payload, list) or not payload or not isinstance(payload[0], dict):
        raise ControllerError(f"invalid image metadata for {image}")
    return payload[0]


def _labels(image_info: dict[str, Any]) -> dict[str, str]:
    config = image_info.get("Config") if isinstance(image_info.get("Config"), dict) else {}
    labels = config.get("Labels") if isinstance(config.get("Labels"), dict) else None
    if labels is None and isinstance(image_info.get("Labels"), dict):
        labels = image_info.get("Labels")
    return {str(k): str(v) for k, v in (labels or {}).items()}


def _pull_image(image: str) -> tuple[bool, str]:
    if not AUTO_PULL:
        return False, "automatic image pull is disabled"
    run = _run_runtime(["pull", image], timeout=1800)
    if run["exit_code"] != 0:
        detail = (run["stderr"] or run["stdout"] or "pull failed")[-4000:]
        return False, detail
    return True, "pulled"


def _ensure_base_image() -> dict[str, str]:
    info = _inspect_image(BASE_IMAGE)
    if info is None:
        ok, reason = _pull_image(BASE_IMAGE)
        if not ok:
            raise ControllerError(f"Flutter capability image is unavailable: {reason}")
        info = _inspect_image(BASE_IMAGE)
    if info is None:
        raise ControllerError("Flutter capability image is unavailable after pull")
    labels = _labels(info)
    if labels.get("org.opencontainers.image.version") != SERVER_VERSION:
        raise ControllerError(
            "Flutter capability image/plugin version mismatch: "
            f"plugin={SERVER_VERSION} image={labels.get('org.opencontainers.image.version')}"
        )
    commit = labels.get("io.safe-reverser.blutter.commit", "").lower()
    if not COMMIT_RE.fullmatch(commit):
        raise ControllerError("Flutter capability image has invalid Blutter provenance")
    return labels


def _runtime_image_reference(
    prepared: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    runtime = prepared.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("identity_status") != "identified":
        raise ControllerError("Flutter runtime identity is incomplete")
    tag = str(runtime.get("cache_tag") or "")
    if not TAG_RE.fullmatch(tag):
        raise ControllerError("Flutter runtime cache tag is invalid")
    expected = f"{FLUTTER_REPOSITORY}:{tag}"
    if (
        prepared.get("recommended_image") != expected
        or runtime.get("recommended_image") != expected
    ):
        raise ControllerError(
            "Flutter capability returned an unexpected runtime image reference"
        )
    if runtime.get("arch") != "arm64" or runtime.get("os") != "android":
        raise ControllerError("Flutter runtime architecture/OS is unsupported")
    snapshot = str(runtime.get("snapshot_hash") or "").lower()
    if not SNAPSHOT_RE.fullmatch(snapshot):
        raise ControllerError("Flutter runtime snapshot hash is invalid")
    return expected, runtime


def _ensure_runtime_image(
    image: str, runtime: dict[str, Any], blutter_commit: str
) -> tuple[bool, str]:
    info = _inspect_image(image)
    if info is None:
        ok, reason = _pull_image(image)
        if not ok:
            return False, reason
        info = _inspect_image(image)
    if info is None:
        return False, "runtime cache image is unavailable after pull"
    labels = _labels(info)
    expected = {
        "io.safe-reverser.runtime-cache.schema": str(RUNTIME_CACHE_SCHEMA),
        "io.safe-reverser.blutter.commit": blutter_commit,
        "io.safe-reverser.dart.version": str(runtime.get("dart_version") or ""),
        "io.safe-reverser.dart.snapshot": str(runtime.get("snapshot_hash") or ""),
        "io.safe-reverser.dart.arch": "arm64",
        "io.safe-reverser.dart.compressed-pointers": (
            "true" if bool(runtime.get("compressed_pointers")) else "false"
        ),
    }
    for key, value in expected.items():
        if labels.get(key) != value:
            raise ControllerError(
                f"runtime cache image provenance mismatch for {key}: "
                f"expected={value!r} actual={labels.get(key)!r}"
            )
    return True, "ready"


def _prepare(job: Path, artifact_rel: str) -> dict[str, Any]:
    args = _common_container_args()
    args.extend(
        [
            _volume(PROJECT_DIR, "/workspace", "ro"),
            _volume(job, "/output", "rw"),
            BASE_IMAGE,
            "prepare_artifact",
            artifact_rel,
            "input",
        ]
    )
    run = _run_runtime(args, timeout=600)
    payload = _parse_payload(run)
    if run["timed_out"]:
        raise ControllerError("Flutter artifact preparation timed out")
    if run["exit_code"] != 0 and payload.get("status") == "error":
        raise ControllerError(
            str(payload.get("error") or "Flutter artifact preparation failed")
        )
    return payload


def _execute_analysis(
    job: Path,
    image: str,
    *,
    timeout_seconds: int,
) -> dict[str, Any]:
    input_dir = job / "input"
    if input_dir.is_symlink() or not input_dir.is_dir():
        raise ControllerError("prepared Flutter input is missing")
    args = _common_container_args()
    args.extend(
        [
            f"--tmpfs=/output:rw,nosuid,nodev,size={OUTPUT_TMPFS_SIZE}",
            _volume(input_dir, "/input", "ro"),
            _volume(job, "/export", "rw"),
            image,
            "analyze_export",
            ".",
            "analysis",
            "--timeout",
            str(timeout_seconds),
        ]
    )
    run = _run_runtime(args, timeout=min(3600, timeout_seconds + 120))
    payload = _parse_payload(run)
    if run["timed_out"]:
        return {"status": "timeout", "executed": True, "exit_code": 124}
    if run["exit_code"] != 0 and payload.get("status") == "error":
        raise ControllerError(
            str(payload.get("error") or "Flutter AOT analysis failed")
        )
    return payload


def _analysis_dir(job: Path) -> Path:
    path = job / "analysis"
    if path.is_symlink() or not path.is_dir() or path.resolve().parent != job:
        raise ControllerError("Flutter semantic analysis output is unavailable")
    index = path / "flutter-index.sqlite"
    if (
        index.is_symlink()
        or not index.is_file()
        or index.resolve().parent != path.resolve()
    ):
        raise ControllerError("Flutter semantic index is unavailable")
    return path.resolve()


def _query_text(value: Any, field: str, limit: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit or "\x00" in text:
        raise ControllerError(f"{field} must be 1..{limit} characters")
    return text


def _query_limit(value: Any, default: int) -> int:
    try:
        parsed = int(default if value is None else value)
    except (TypeError, ValueError) as exc:
        raise ControllerError("limit must be an integer") from exc
    return max(1, min(parsed, MAX_QUERY_LIMIT))


def _run_semantic(
    job: Path, command: str, argv: list[str], *, timeout: int = 120
) -> dict[str, Any]:
    analysis = _analysis_dir(job)
    args = _common_container_args()
    args.extend(
        [
            _volume(analysis, "/output", "ro"),
            BASE_IMAGE,
            command,
            ".",
            *argv,
        ]
    )
    run = _run_runtime(args, timeout=timeout)
    payload = _parse_payload(run)
    if run["timed_out"]:
        raise ControllerError(f"{command} timed out")
    if run["exit_code"] != 0 or payload.get("status") == "error":
        raise ControllerError(str(payload.get("error") or f"{command} failed"))
    payload["job_id"] = job.name
    return payload


def health(_args: dict[str, Any]) -> dict[str, Any]:
    labels = _ensure_base_image()
    return {
        "server": SERVER_NAME,
        "version": SERVER_VERSION,
        "profile": "framework-flutter",
        "controller": "host-container-dispatch",
        "runtime": RUNTIME,
        "base_image": BASE_IMAGE,
        "base_image_version": labels.get("org.opencontainers.image.version"),
        "blutter_commit": labels.get("io.safe-reverser.blutter.commit"),
        "runtime_cache_schema": RUNTIME_CACHE_SCHEMA,
        "network_inside_analysis": "disabled",
        "runtime_socket_mounted_into_sandbox": False,
        "analyzer_runs_on_host": False,
        "runtime_cache_pull_location": "host-controller",
        "runtime_cache_build_on_demand": False,
        "output_tmpfs": OUTPUT_TMPFS_SIZE,
        "semantic_operations": [
            "find_dart_symbols",
            "find_dart_strings",
            "find_dart_xrefs",
            "map_dart_to_native",
            "extract_flutter_network_model",
        ],
    }


def analyze_flutter_aot(args: dict[str, Any]) -> dict[str, Any]:
    _, artifact_rel = _artifact(str(args.get("artifact") or ""))
    timeout = max(30, min(int(args.get("timeout_seconds", 900)), 3480))
    _ensure_base_image()
    job_id, job = _new_job()
    meta: dict[str, Any] = {
        "job_id": job_id,
        "artifact": artifact_rel,
        "created_at_epoch": int(time.time()),
        "profile": "framework-flutter",
        "controller_version": SERVER_VERSION,
        "status": "preparing",
    }
    _write_job(job, meta)
    prepared_created = False
    try:
        prepared = _prepare(job, artifact_rel)
        prepared_created = (job / "input").is_dir()
        meta["prepare"] = prepared
        meta["status"] = str(prepared.get("status") or "unknown")
        _write_job(job, meta)

        if prepared.get("status") == "unsupported":
            return {"job_id": job_id, **prepared}
        runtime = prepared.get("runtime")
        if not isinstance(runtime, dict) or runtime.get("identity_status") != "identified":
            return {
                "job_id": job_id,
                **prepared,
                "executed": False,
                "limitation": (
                    "exact Dart runtime identity is required before AOT analysis"
                ),
            }

        image, runtime = _runtime_image_reference(prepared)
        blutter_commit = str(prepared.get("blutter_commit") or "").lower()
        if not COMMIT_RE.fullmatch(blutter_commit):
            raise ControllerError(
                "prepared Flutter evidence has invalid Blutter commit"
            )
        ready, reason = _ensure_runtime_image(image, runtime, blutter_commit)
        if not ready:
            meta["status"] = "runtime_cache_unavailable"
            meta["runtime_image"] = image
            meta["runtime_cache_reason"] = reason[-4000:]
            _write_job(job, meta)
            return {
                "job_id": job_id,
                "status": "runtime_cache_unavailable",
                "executed": False,
                "runtime": runtime,
                "recommended_image": image,
                "cache_tag": runtime.get("cache_tag"),
                "reason": reason[-4000:],
                "next_action": (
                    "build/publish the exact runtime cache through the controlled "
                    "GitHub workflow; analysis stays offline"
                ),
            }

        analysis = _execute_analysis(job, image, timeout_seconds=timeout)
        meta["runtime_image"] = image
        meta["analysis"] = analysis
        meta["status"] = str(analysis.get("status") or "unknown")
        _write_job(job, meta)
        return {"job_id": job_id, **analysis}
    except Exception:
        meta["status"] = "error"
        try:
            _write_job(job, meta)
        except Exception:
            pass
        raise
    finally:
        if prepared_created:
            _remove_prepared_input(job)


def find_dart_symbols(args: dict[str, Any]) -> dict[str, Any]:
    job = _job(str(args.get("job_id") or ""))
    query = _query_text(args.get("query"), "query", MAX_QUERY_TEXT)
    limit = _query_limit(args.get("limit"), 50)
    return _run_semantic(job, "find_dart_symbols", [query, "--limit", str(limit)])


def find_dart_strings(args: dict[str, Any]) -> dict[str, Any]:
    job = _job(str(args.get("job_id") or ""))
    query = _query_text(args.get("query"), "query", MAX_QUERY_TEXT)
    limit = _query_limit(args.get("limit"), 50)
    return _run_semantic(job, "find_dart_strings", [query, "--limit", str(limit)])


def find_dart_xrefs(args: dict[str, Any]) -> dict[str, Any]:
    job = _job(str(args.get("job_id") or ""))
    symbol = _query_text(args.get("symbol"), "symbol", MAX_SYMBOL_TEXT)
    direction = str(args.get("direction") or "both")
    if direction not in {"incoming", "outgoing", "both"}:
        raise ControllerError("direction must be incoming, outgoing, or both")
    limit = _query_limit(args.get("limit"), 100)
    return _run_semantic(
        job,
        "find_dart_xrefs",
        [symbol, "--direction", direction, "--limit", str(limit)],
    )


def map_dart_to_native(args: dict[str, Any]) -> dict[str, Any]:
    job = _job(str(args.get("job_id") or ""))
    symbol = _query_text(args.get("symbol"), "symbol", MAX_SYMBOL_TEXT)
    return _run_semantic(job, "map_dart_to_native", [symbol])


def extract_flutter_network_model(args: dict[str, Any]) -> dict[str, Any]:
    job = _job(str(args.get("job_id") or ""))
    limit = _query_limit(args.get("limit"), 100)
    return _run_semantic(
        job,
        "extract_flutter_network_model",
        ["--limit", str(limit)],
        timeout=180,
    )


def list_flutter_jobs(_args: dict[str, Any]) -> dict[str, Any]:
    root = _jobs_root()
    jobs: list[dict[str, Any]] = []
    for path in sorted(root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if len(jobs) >= 100:
            break
        if path.is_symlink() or not path.is_dir() or not JOB_ID_RE.fullmatch(path.name):
            continue
        try:
            meta = _read_job(path)
        except ControllerError:
            continue
        jobs.append(
            {
                "job_id": path.name,
                "artifact": meta.get("artifact"),
                "status": meta.get("status"),
                "created_at_epoch": meta.get("created_at_epoch"),
                "runtime_image": meta.get("runtime_image"),
            }
        )
    return {"jobs": jobs}


TOOL_HANDLERS = {
    "health": health,
    "analyze_flutter_aot": analyze_flutter_aot,
    "find_dart_symbols": find_dart_symbols,
    "find_dart_strings": find_dart_strings,
    "find_dart_xrefs": find_dart_xrefs,
    "map_dart_to_native": map_dart_to_native,
    "extract_flutter_network_model": extract_flutter_network_model,
    "list_flutter_jobs": list_flutter_jobs,
}

TOOLS = [
    {
        "name": "health",
        "description": (
            "Check the host Flutter capability controller, pinned base image "
            "and trust-boundary configuration."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "analyze_flutter_aot",
        "description": (
            "Prepare a Flutter APK/bundle, identify its exact Dart AOT runtime, "
            "select a verified immutable runtime-cache image, run offline Blutter "
            "analysis, and persist a bounded semantic index. Returns an explicit "
            "cache-miss state when the exact prebuilt runtime is unavailable."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "artifact": {
                    "type": "string",
                    "description": (
                        "APK/XAPK/APKS/APKM path relative to the project root."
                    ),
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 30,
                    "maximum": 3480,
                    "default": 900,
                },
            },
            "required": ["artifact"],
            "additionalProperties": False,
        },
    },
    {
        "name": "find_dart_symbols",
        "description": (
            "Search the persisted bounded Flutter Dart semantic index for "
            "libraries, classes, functions and signatures."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "query": {"type": "string", "maxLength": MAX_QUERY_TEXT},
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                    "default": 50,
                },
            },
            "required": ["job_id", "query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "find_dart_strings",
        "description": (
            "Search bounded Dart AOT/object-pool string evidence in a Flutter "
            "analysis job."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "query": {"type": "string", "maxLength": MAX_QUERY_TEXT},
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                    "default": 50,
                },
            },
            "required": ["job_id", "query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "find_dart_xrefs",
        "description": (
            "Query bounded Dart call/XREF adjacency. XREFs are evidence of "
            "adjacency, not proof of value flow."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "symbol": {"type": "string", "maxLength": MAX_SYMBOL_TEXT},
                "direction": {
                    "type": "string",
                    "enum": ["incoming", "outgoing", "both"],
                    "default": "both",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                    "default": 100,
                },
            },
            "required": ["job_id", "symbol"],
            "additionalProperties": False,
        },
    },
    {
        "name": "map_dart_to_native",
        "description": (
            "Map a uniquely resolved Dart function to its libapp.so-relative "
            "native offset with provenance."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "symbol": {"type": "string", "maxLength": MAX_SYMBOL_TEXT},
            },
            "required": ["job_id", "symbol"],
            "additionalProperties": False,
        },
    },
    {
        "name": "extract_flutter_network_model",
        "description": (
            "Reconstruct bounded Flutter host/endpoint/client/header/auth/signing/"
            "crypto evidence from the Dart semantic index without claiming value flow."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                    "default": 100,
                },
            },
            "required": ["job_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_flutter_jobs",
        "description": "List recent Flutter capability jobs and their coarse status.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
]


def _send(payload: dict[str, Any]) -> None:
    sys.stdout.write(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
    )
    sys.stdout.flush()


def _tool_result(data: Any, *, is_error: bool = False) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": _json_text(data)}],
        "isError": is_error,
    }


def _handle(req: dict[str, Any]) -> dict[str, Any] | None:
    method = req.get("method")
    request_id = req.get("id")
    params = req.get("params") or {}
    if method == "initialize":
        protocol = params.get("protocolVersion") or "2025-06-18"
        result = {
            "protocolVersion": protocol,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": (
                "Flutter/Dart AOT capability controller. It selects verified "
                "capability images on the host; all artifact parsing and analyzer "
                "execution stay inside network-disabled containers."
            ),
        }
    elif method in {"notifications/initialized", "notifications/cancelled"}:
        return None
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        handler = TOOL_HANDLERS.get(name)
        if handler is None:
            result = _tool_result({"error": f"unknown tool: {name}"}, is_error=True)
        elif not isinstance(arguments, dict):
            result = _tool_result(
                {"error": "tool arguments must be an object"}, is_error=True
            )
        else:
            try:
                result = _tool_result(handler(arguments))
            except (ControllerError, ValueError, OSError) as exc:
                result = _tool_result({"error": str(exc)}, is_error=True)
    else:
        if request_id is None:
            return None
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": f"method not found: {method}"},
        }
    if request_id is None:
        return None
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def main() -> int:
    try:
        _validate_config()
        _flutter_data_root()
    except (ControllerError, OSError) as exc:
        print(f"safe-android-reverser-flutter: {exc}", file=sys.stderr)
        return 2
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        req: dict[str, Any] | None = None
        try:
            decoded = json.loads(raw)
            if not isinstance(decoded, dict):
                raise ValueError("request must be a JSON object")
            req = decoded
            response = _handle(req)
            if response is not None:
                _send(response)
        except json.JSONDecodeError as exc:
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"parse error: {exc.msg}"},
                }
            )
        except Exception as exc:
            request_id = req.get("id") if isinstance(req, dict) else None
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32603, "message": str(exc)},
                }
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
