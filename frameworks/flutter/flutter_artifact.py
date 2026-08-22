#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Iterator

import safe_blutter_adapter as adapter

WORKSPACE = Path(os.environ.get("SAFE_FLUTTER_WORKSPACE", "/workspace")).resolve()
ALLOWED_ARTIFACT_EXTS = {".apk", ".xapk", ".apks", ".apkm"}
SUPPORTED_ABI = "arm64-v8a"
MAX_OUTER_ENTRIES = 20_000
MAX_APK_ENTRIES = 200_000
MAX_NESTED_APKS = 128
MAX_NESTED_APK_BYTES = 512 * 1024 * 1024
MAX_TOTAL_NESTED_APK_BYTES = 768 * 1024 * 1024
MAX_LIBRARY_BYTES = 512 * 1024 * 1024
MAX_TOTAL_LIBRARY_BYTES = 1024 * 1024 * 1024
MAX_MEMBER_NAME = 4096
MAX_AVAILABLE_ABIS = 64
LIB_RE = re.compile(r"^lib/([^/]{1,128})/(libapp|libflutter)\.so$")


class FlutterArtifactError(adapter.AdapterError):
    pass


def _lexical_under_without_symlinks(root: Path, value: str) -> Path:
    root = Path(os.path.abspath(root))
    raw = Path(value)
    candidate = Path(os.path.abspath(raw if raw.is_absolute() else root / raw))
    if candidate != root and root not in candidate.parents:
        raise FlutterArtifactError(f"path escapes allowed root: {value}")
    current = root
    if candidate != root:
        for part in candidate.relative_to(root).parts:
            current = current / part
            if current.is_symlink():
                raise FlutterArtifactError(f"symlinked path component is not allowed: {value}")
    return candidate


def _artifact(value: str) -> Path:
    path = _lexical_under_without_symlinks(WORKSPACE, value)
    if path.is_symlink() or not path.is_file():
        raise FlutterArtifactError("artifact must be a regular file under /workspace")
    if path.suffix.lower() not in ALLOWED_ARTIFACT_EXTS:
        raise FlutterArtifactError(f"unsupported artifact type: {path.suffix}")
    return path


def _fresh_output(value: str) -> Path:
    root = adapter.OUTPUT_ROOT.resolve()
    path = _lexical_under_without_symlinks(root, value)
    if path == root:
        raise FlutterArtifactError("prepared input must be a dedicated child under /output")
    if path.exists() or path.is_symlink():
        raise FlutterArtifactError("prepared input path already exists; use a fresh job")
    if path.parent != root:
        raise FlutterArtifactError("prepared input must be a direct child under /output")
    return path


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_bounded(src, dest: Path, *, max_bytes: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    written = 0
    with dest.open("xb") as handle:
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > max_bytes:
                raise FlutterArtifactError(f"archive member exceeds {max_bytes} bytes")
            digest.update(chunk)
            handle.write(chunk)
        handle.flush()
        os.fsync(handle.fileno())
    return written, digest.hexdigest()


def _bounded_infos(zf: zipfile.ZipFile, limit: int, label: str) -> list[zipfile.ZipInfo]:
    infos = zf.infolist()
    if len(infos) > limit:
        raise FlutterArtifactError(f"{label} contains more than {limit} ZIP entries")
    for info in infos:
        if len(info.filename) > MAX_MEMBER_NAME:
            raise FlutterArtifactError(f"{label} contains an oversized member name")
    return infos


def _iter_apks(artifact: Path) -> Iterator[tuple[str, zipfile.ZipFile]]:
    ext = artifact.suffix.lower()
    if ext == ".apk":
        try:
            with zipfile.ZipFile(artifact) as zf:
                yield artifact.name, zf
        except zipfile.BadZipFile as exc:
            raise FlutterArtifactError("invalid APK ZIP") from exc
        return

    try:
        with zipfile.ZipFile(artifact) as outer:
            infos = _bounded_infos(outer, MAX_OUTER_ENTRIES, "bundle")
            nested_count = 0
            total_nested = 0
            for info in infos:
                if info.is_dir() or not info.filename.lower().endswith(".apk"):
                    continue
                nested_count += 1
                if nested_count > MAX_NESTED_APKS:
                    raise FlutterArtifactError("bundle contains too many nested APKs")
                if info.file_size > MAX_NESTED_APK_BYTES:
                    raise FlutterArtifactError("nested APK exceeds extraction budget")
                total_nested += info.file_size
                if total_nested > MAX_TOTAL_NESTED_APK_BYTES:
                    raise FlutterArtifactError("nested APK aggregate exceeds extraction budget")
                temp_path: Path | None = None
                try:
                    fd, name = tempfile.mkstemp(prefix="safe-flutter-apk-", suffix=".apk")
                    os.close(fd)
                    temp_path = Path(name)
                    temp_path.unlink()
                    with outer.open(info) as src:
                        copied, _ = _copy_bounded(
                            src, temp_path, max_bytes=MAX_NESTED_APK_BYTES
                        )
                    if copied != info.file_size:
                        raise FlutterArtifactError(
                            "nested APK size does not match ZIP metadata"
                        )
                    try:
                        with zipfile.ZipFile(temp_path) as nested:
                            yield info.filename, nested
                    except zipfile.BadZipFile as exc:
                        raise FlutterArtifactError(
                            f"invalid nested APK: {info.filename}"
                        ) from exc
                finally:
                    if temp_path is not None:
                        temp_path.unlink(missing_ok=True)
    except zipfile.BadZipFile as exc:
        raise FlutterArtifactError("invalid APK bundle ZIP") from exc


def _extract_candidate(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    stage: Path,
    logical_name: str,
    state: dict[str, Any],
) -> None:
    if info.file_size > MAX_LIBRARY_BYTES:
        raise FlutterArtifactError(f"{logical_name}.so exceeds extraction budget")
    state["declared_library_bytes"] += info.file_size
    if state["declared_library_bytes"] > MAX_TOTAL_LIBRARY_BYTES:
        raise FlutterArtifactError("Flutter library aggregate exceeds extraction budget")

    temp = stage / f".{logical_name}.{state['candidate_count']}.tmp"
    state["candidate_count"] += 1
    try:
        with zf.open(info) as src:
            copied, digest = _copy_bounded(src, temp, max_bytes=MAX_LIBRARY_BYTES)
        if copied != info.file_size:
            raise FlutterArtifactError(
                f"{logical_name}.so size does not match ZIP metadata"
            )
        destination = stage / f"{logical_name}.so"
        if destination.exists():
            existing = state["digests"].get(logical_name) or _hash_file(destination)
            if existing != digest or destination.stat().st_size != copied:
                raise FlutterArtifactError(
                    f"ambiguous duplicate {logical_name}.so for {SUPPORTED_ABI}"
                )
            return
        os.replace(temp, destination)
        state["digests"][logical_name] = digest
        state["sizes"][logical_name] = copied
    finally:
        temp.unlink(missing_ok=True)


def prepare_artifact(artifact_value: str, output_value: str) -> dict[str, Any]:
    artifact = _artifact(artifact_value)
    target = _fresh_output(output_value)
    target.parent.mkdir(parents=True, exist_ok=True)
    stage: Path | None = Path(
        tempfile.mkdtemp(prefix=".safe-flutter-input-", dir=target.parent)
    )
    available_abis: set[str] = set()
    sources: set[str] = set()
    state: dict[str, Any] = {
        "declared_library_bytes": 0,
        "candidate_count": 0,
        "digests": {},
        "sizes": {},
    }
    try:
        for apk_name, zf in _iter_apks(artifact):
            infos = _bounded_infos(zf, MAX_APK_ENTRIES, f"APK {apk_name}")
            for info in infos:
                if info.is_dir():
                    continue
                match = LIB_RE.fullmatch(info.filename)
                if not match:
                    continue
                abi, logical_name = match.groups()
                if len(available_abis) < MAX_AVAILABLE_ABIS:
                    available_abis.add(abi)
                if abi != SUPPORTED_ABI:
                    continue
                sources.add(apk_name)
                _extract_candidate(zf, info, stage, logical_name, state)

        libapp = stage / "libapp.so"
        libflutter = stage / "libflutter.so"
        if not libapp.is_file() or not libflutter.is_file():
            return {
                "status": "unsupported",
                "profile": "framework-flutter",
                "reason": f"a complete {SUPPORTED_ABI} libapp.so/libflutter.so pair was not found",
                "available_abis": sorted(available_abis),
                "supported_abi": SUPPORTED_ABI,
            }

        runtime = adapter._runtime_info(stage)
        for path in (libapp, libflutter):
            os.chmod(path, 0o444)
        os.replace(stage, target)
        stage = None

        if runtime.get("identity_status") != "identified":
            status = "runtime_identity_incomplete"
        elif runtime.get("binary_cached"):
            status = "ready"
        else:
            status = "runtime_cache_miss"
        return {
            "status": status,
            "profile": "framework-flutter",
            "artifact": str(artifact.relative_to(WORKSPACE)),
            "prepared_input": target.name,
            "abi": SUPPORTED_ABI,
            "source_apks": sorted(sources)[:MAX_NESTED_APKS],
            "available_abis": sorted(available_abis),
            "libraries": {
                "libapp.so": {
                    "sha256": state["digests"]["libapp"],
                    "size": state["sizes"]["libapp"],
                },
                "libflutter.so": {
                    "sha256": state["digests"]["libflutter"],
                    "size": state["sizes"]["libflutter"],
                },
            },
            "runtime": runtime,
            "blutter_commit": adapter.BLUTTER_COMMIT,
            "limits": {
                "max_outer_entries": MAX_OUTER_ENTRIES,
                "max_apk_entries": MAX_APK_ENTRIES,
                "max_nested_apks": MAX_NESTED_APKS,
                "max_nested_apk_bytes": MAX_NESTED_APK_BYTES,
                "max_total_nested_apk_bytes": MAX_TOTAL_NESTED_APK_BYTES,
                "max_library_bytes": MAX_LIBRARY_BYTES,
                "max_total_library_bytes": MAX_TOTAL_LIBRARY_BYTES,
            },
        }
    finally:
        if stage is not None and stage.exists():
            shutil.rmtree(stage, ignore_errors=True)
