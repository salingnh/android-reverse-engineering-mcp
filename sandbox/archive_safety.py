from __future__ import annotations

import os
import tempfile
import zipfile
from pathlib import Path
from typing import Iterable

MAX_OUTER_ENTRIES = 20_000
MAX_APK_ENTRIES = 200_000
MAX_NESTED_APKS = 128
MAX_NESTED_APK_BYTES = 512 * 1024 * 1024
MAX_TOTAL_NESTED_APK_BYTES = 768 * 1024 * 1024
MAX_APK_MEMBER_BYTES = 1024 * 1024 * 1024
MAX_APK_DECLARED_BYTES = 2 * 1024 * 1024 * 1024
MAX_MEMBER_NAME = 4096
COPY_CHUNK = 1024 * 1024


class ArchiveSafetyError(ValueError):
    pass


def _validate_infos(
    zf: zipfile.ZipFile,
    *,
    max_entries: int,
    max_declared_bytes: int,
    label: str,
) -> list[zipfile.ZipInfo]:
    infos = zf.infolist()
    if len(infos) > max_entries:
        raise ArchiveSafetyError(f"{label} contains more than {max_entries} ZIP entries")
    declared = 0
    for info in infos:
        if len(info.filename) > MAX_MEMBER_NAME:
            raise ArchiveSafetyError(f"{label} contains an oversized member name")
        if info.file_size < 0 or info.file_size > MAX_APK_MEMBER_BYTES:
            raise ArchiveSafetyError(f"{label} contains an oversized ZIP member")
        if not info.is_dir():
            declared += info.file_size
            if declared > max_declared_bytes:
                raise ArchiveSafetyError(
                    f"{label} declared uncompressed bytes exceed {max_declared_bytes}"
                )
    return infos


def _copy_member_bounded(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    destination: Path,
    *,
    max_bytes: int,
) -> int:
    written = 0
    with zf.open(info) as src, destination.open("xb") as dst:
        while True:
            chunk = src.read(COPY_CHUNK)
            if not chunk:
                break
            written += len(chunk)
            if written > max_bytes:
                raise ArchiveSafetyError(
                    f"nested APK exceeds extraction budget of {max_bytes} bytes"
                )
            dst.write(chunk)
        dst.flush()
        os.fsync(dst.fileno())
    if written != info.file_size:
        raise ArchiveSafetyError("nested APK size does not match ZIP metadata")
    return written


def _validated_apk(path: Path, label: str) -> zipfile.ZipFile:
    try:
        zf = zipfile.ZipFile(path)
        _validate_infos(
            zf,
            max_entries=MAX_APK_ENTRIES,
            max_declared_bytes=MAX_APK_DECLARED_BYTES,
            label=label,
        )
        return zf
    except zipfile.BadZipFile as exc:
        raise ArchiveSafetyError(f"invalid APK ZIP: {label}") from exc
    except Exception:
        try:
            zf.close()  # type: ignore[possibly-undefined]
        except Exception:
            pass
        raise


def nested_apks(artifact: Path) -> Iterable[tuple[str, zipfile.ZipFile]]:
    """Yield validated APK ZIPs with hard nested-bundle and declared-size budgets."""

    ext = artifact.suffix.lower()
    if ext == ".apk":
        zf = _validated_apk(artifact, artifact.name)
        try:
            yield artifact.name, zf
        finally:
            zf.close()
        return
    if ext not in {".xapk", ".apks", ".apkm"}:
        return

    try:
        with zipfile.ZipFile(artifact) as outer, tempfile.TemporaryDirectory(
            prefix="safe-rev-apks-"
        ) as tmp:
            outer_infos = _validate_infos(
                outer,
                max_entries=MAX_OUTER_ENTRIES,
                max_declared_bytes=MAX_TOTAL_NESTED_APK_BYTES,
                label="bundle",
            )
            tmpdir = Path(tmp)
            nested_count = 0
            total_nested = 0
            for info in outer_infos:
                if info.is_dir() or not info.filename.lower().endswith(".apk"):
                    continue
                nested_count += 1
                if nested_count > MAX_NESTED_APKS:
                    raise ArchiveSafetyError(
                        f"bundle contains more than {MAX_NESTED_APKS} nested APKs"
                    )
                if info.file_size > MAX_NESTED_APK_BYTES:
                    raise ArchiveSafetyError("nested APK exceeds extraction budget")
                total_nested += info.file_size
                if total_nested > MAX_TOTAL_NESTED_APK_BYTES:
                    raise ArchiveSafetyError(
                        "nested APK aggregate exceeds extraction budget"
                    )
                destination = tmpdir / f"{nested_count:03d}.apk"
                _copy_member_bounded(
                    outer,
                    info,
                    destination,
                    max_bytes=MAX_NESTED_APK_BYTES,
                )
                nested = _validated_apk(destination, info.filename)
                try:
                    yield info.filename, nested
                finally:
                    nested.close()
    except zipfile.BadZipFile as exc:
        raise ArchiveSafetyError("invalid APK bundle ZIP") from exc
