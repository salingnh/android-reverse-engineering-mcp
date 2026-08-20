#!/usr/bin/env python3
"""Shared bounded helpers for Safe Android Reverser program-understanding modules."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any, Iterable

MAX_METHODS = 200_000
MAX_EDGES = 500_000
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_BUNDLE_APK_BYTES = 512 * 1024 * 1024
MAX_BUNDLE_TOTAL_BYTES = 900 * 1024 * 1024
MAX_BUNDLE_COMPRESSION_RATIO = 500
MAX_BUNDLE_ENTRIES = 20_000

CLASS_RE = re.compile(r"\b(?:class|interface|enum|object)\s+([A-Za-z_$][\w$]*)")
RETROFIT_RE = re.compile(r"@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP)\s*\(\s*\"([^\"]+)\"", re.I)
URL_RE = re.compile(r"https?://(?:[A-Za-z0-9.-]+|\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?(?:/[^\s\"'<>]*)?", re.I)
AUTH_RE = re.compile(r"\b(Authorization|Bearer|access[_-]?token|refresh[_-]?token|api[_-]?key|X-API-Key|signature|HMAC|Mac\.getInstance)\b", re.I)
TYPE_RE = re.compile(r"\b([A-Z][A-Za-z0-9_$]*(?:<[^>]+>)?)\b")


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _save(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _artifact(job: Path, workspace: Path) -> Path:
    rel = _load(job / "job.json")["artifact"]
    if not isinstance(rel, str) or not rel:
        raise ValueError("job artifact path is invalid")
    path = (workspace / rel).resolve()
    if path != workspace and workspace not in path.parents:
        raise ValueError("job artifact escapes workspace")
    if not path.is_file():
        raise ValueError("job artifact no longer exists")
    return path


def _sources(job: Path) -> Iterable[Path]:
    seen: set[Path] = set()
    for root in (job / "jadx" / "sources", job / "jadx", job / "vineflower"):
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".java", ".kt"}:
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            if len(seen) > 150_000:
                raise ValueError("source tree exceeds safe file-count limit")
            yield path


def _text(path: Path) -> str:
    if path.stat().st_size > MAX_SOURCE_BYTES:
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _source_meta(text: str, path: Path) -> tuple[str, str]:
    package = re.search(r"(?m)^\s*package\s+([\w.]+)", text)
    clazz = CLASS_RE.search(text)
    class_name = clazz.group(1) if clazz else path.stem
    return (package.group(1) if package else "", class_name)


def _apks(artifact: Path, temp_root: Path) -> list[tuple[str, Path]]:
    if artifact.suffix.lower() == ".apk":
        if artifact.stat().st_size > MAX_BUNDLE_APK_BYTES:
            raise ValueError("APK exceeds semantic-analysis size limit")
        return [(artifact.name, artifact)]
    if artifact.suffix.lower() not in {".xapk", ".apks", ".apkm"}:
        return []

    output: list[tuple[str, Path]] = []
    total = 0
    try:
        archive = zipfile.ZipFile(artifact)
    except zipfile.BadZipFile as exc:
        raise ValueError(f"invalid APK bundle ZIP: {exc}") from exc

    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_BUNDLE_ENTRIES:
            raise ValueError("bundle contains too many ZIP entries")
        for info in infos:
            if info.is_dir() or not info.filename.lower().endswith(".apk"):
                continue
            if len(output) >= 128:
                raise ValueError("bundle contains more than 128 APK members")
            if info.file_size > MAX_BUNDLE_APK_BYTES:
                raise ValueError(f"bundle APK member exceeds size limit: {info.filename}")
            if (
                info.compress_size
                and info.file_size > 16 * 1024 * 1024
                and info.file_size / info.compress_size > MAX_BUNDLE_COMPRESSION_RATIO
            ):
                raise ValueError(f"bundle APK member has suspicious compression ratio: {info.filename}")
            total += info.file_size
            if total > MAX_BUNDLE_TOTAL_BYTES:
                raise ValueError("bundle APK members exceed total semantic-analysis size limit")
            dest = temp_root / f"{len(output):03d}-{Path(info.filename).name}"
            with archive.open(info) as src, dest.open("wb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
            output.append((info.filename, dest))
    if not output:
        raise ValueError("bundle does not contain an APK member")
    return output


def capabilities() -> dict[str, Any]:
    """Compatibility capability probe; v2 uses a deeper Androguard import check."""
    apkid = shutil.which("apkid")
    result = {
        "androguard": False,
        "apkid": bool(apkid),
        "versions": {"androguard": None, "apkid": "external-cli" if apkid else None},
    }
    try:
        import androguard  # type: ignore
        result["androguard"] = True
        result["versions"]["androguard"] = getattr(androguard, "__version__", "installed")
    except Exception:
        pass
    return result


def identify_protector(artifact: Path, *, timeout: int = 10) -> dict[str, Any]:
    """Use APKiD only as an optional external CLI analyzer."""
    binary = shutil.which("apkid")
    timeout = max(1, min(int(timeout), 60))
    if not binary:
        return {
            "artifact": artifact.name,
            "available": False,
            "analyzer": "apkid-external",
            "matches": [],
            "error": "APKiD CLI is not installed in this sandbox profile",
        }
    try:
        process = subprocess.run(
            [binary, "-j", "-t", str(timeout), str(artifact)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=timeout + 15,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "artifact": artifact.name,
            "available": True,
            "analyzer": "apkid-external",
            "matches": [],
            "error": "APKiD timed out",
        }
    if process.returncode != 0:
        return {
            "artifact": artifact.name,
            "available": True,
            "analyzer": "apkid-external",
            "matches": [],
            "error": process.stderr[-4000:],
        }
    try:
        payload = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        return {
            "artifact": artifact.name,
            "available": True,
            "analyzer": "apkid-external",
            "matches": [],
            "error": f"invalid APKiD JSON: {exc}",
        }

    signal_tags = {
        "packer", "protector", "obfuscator", "anti_vm", "anti_disassembly",
        "anti_debug", "anti_root", "dropper", "manipulator", "compiler",
    }
    matches = []
    for file_result in payload.get("files", []):
        if not isinstance(file_result, dict):
            continue
        for tag_text, descriptions in (file_result.get("matches") or {}).items():
            tags = sorted(tag.strip() for tag in str(tag_text).split(",") if tag.strip())
            if not set(tags) & signal_tags:
                continue
            if not isinstance(descriptions, list):
                descriptions = [descriptions]
            for description in descriptions:
                matches.append(
                    {
                        "member": file_result.get("filename"),
                        "tags": tags,
                        "description": str(description),
                    }
                )
                if len(matches) >= 500:
                    break
            if len(matches) >= 500:
                break
        if len(matches) >= 500:
            break

    if any(set(match["tags"]) & {"packer", "protector", "dropper"} for match in matches):
        route = "protected-dex-native"
    elif any("obfuscator" in match["tags"] for match in matches):
        route = "semantic-dex"
    else:
        route = "standard-static"
    return {
        "artifact": artifact.name,
        "available": True,
        "analyzer": {"name": "apkid-external", "version": payload.get("apkid_version")},
        "rules_sha256": payload.get("rules_sha256"),
        "matches": matches,
        "recommended_route": route,
        "confidence": 0.95 if matches else 0.5,
    }
