from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator
from zipfile import BadZipFile, ZipFile, ZipInfo

import peg_schema

ANALYZER_NAME = "safe-flutter-inspector"
ANALYZER_VERSION = "1"
MAX_LIBRARY_SCAN_BYTES = 128 * 1024 * 1024
MAX_TOTAL_LIBRARY_SCAN_BYTES = 256 * 1024 * 1024
MAX_ASSET_COUNT = 20_000
MAX_ASSET_PREVIEW_BYTES = 64 * 1024
MAX_ASSET_PREVIEWS = 50
MAX_BUNDLE_APK_BYTES = 512 * 1024 * 1024
MAX_BUNDLE_TOTAL_APK_BYTES = 768 * 1024 * 1024
MAX_BUNDLE_APK_COUNT = 128
MAX_OUTER_ZIP_ENTRIES = 20_000
MAX_APK_ZIP_ENTRIES = 200_000
MAX_TOTAL_APK_ZIP_ENTRIES = 500_000
MAX_MEMBER_NAME_CHARS = 4096

DART_VERSION_RE = re.compile(
    rb"Dart VM version:\s*([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?)",
    re.IGNORECASE,
)
FLUTTER_LIB_RE = re.compile(r"^lib/([^/]+)/(libapp|libflutter)\.so$")
TEXT_ASSET_RE = re.compile(
    r"\.(?:json|yaml|yml|txt|xml|properties|env|pem|crt|cer|graphql|gql)$",
    re.IGNORECASE,
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _analysis_id(artifact_sha256: str, operation: str) -> str:
    return f"{operation}:v{ANALYZER_VERSION}:{artifact_sha256}"


def _member_name(value: str) -> str:
    if not value or len(value) > MAX_MEMBER_NAME_CHARS:
        raise ValueError(
            f"ZIP member name must be 1..{MAX_MEMBER_NAME_CHARS} characters"
        )
    return value


def _evidence(
    artifact_sha256: str,
    *,
    operation: str,
    state: str,
    apk_member: str,
    member_path: str,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    return peg_schema.evidence(
        analysis_id=_analysis_id(artifact_sha256, operation),
        artifact_sha256=artifact_sha256,
        analyzer_name=ANALYZER_NAME,
        analyzer_version=ANALYZER_VERSION,
        state=state,
        location={
            "apk_member": _member_name(apk_member),
            "member": _member_name(member_path),
        },
        image_version=os.environ.get("SAFE_REVERSER_IMAGE_VERSION") or None,
        build_commit=os.environ.get("SAFE_REVERSER_BUILD_COMMIT") or None,
        config_schema_version=1,
        limitations=limitations,
    )


def _validate_container_budget(artifact: Path) -> None:
    if artifact.suffix.lower() not in {".xapk", ".apks", ".apkm"}:
        return
    try:
        with ZipFile(artifact) as outer:
            infos = outer.infolist()
            if len(infos) > MAX_OUTER_ZIP_ENTRIES:
                raise ValueError(
                    f"bundle contains too many ZIP entries: {len(infos)} > {MAX_OUTER_ZIP_ENTRIES}"
                )
            apk_count = 0
            total_apk_bytes = 0
            for info in infos:
                if info.is_dir() or not info.filename.lower().endswith(".apk"):
                    continue
                _member_name(info.filename)
                apk_count += 1
                if apk_count > MAX_BUNDLE_APK_COUNT:
                    raise ValueError(
                        f"bundle contains too many APK entries: {apk_count} > {MAX_BUNDLE_APK_COUNT}"
                    )
                if info.file_size > MAX_BUNDLE_APK_BYTES:
                    raise ValueError(
                        f"nested APK exceeds safe extraction budget: {info.filename} ({info.file_size} bytes)"
                    )
                total_apk_bytes += info.file_size
                if total_apk_bytes > MAX_BUNDLE_TOTAL_APK_BYTES:
                    raise ValueError(
                        "bundle nested APKs exceed the total safe extraction budget"
                    )
    except BadZipFile as exc:
        raise ValueError(f"invalid APK bundle ZIP: {exc}") from exc


def _nested_apk_iter(
    artifact: Path,
    nested_apks: Callable[[Path], Iterable[tuple[str, ZipFile]]],
) -> Iterator[tuple[str, ZipFile]]:
    try:
        yield from nested_apks(artifact)
    except BadZipFile as exc:
        raise ValueError(f"invalid APK/bundle ZIP: {exc}") from exc


def _bounded_infos(zf: ZipFile, *, running_total: int) -> tuple[list[ZipInfo], int]:
    infos = zf.infolist()
    if len(infos) > MAX_APK_ZIP_ENTRIES:
        raise ValueError(
            f"APK contains too many ZIP entries: {len(infos)} > {MAX_APK_ZIP_ENTRIES}"
        )
    running_total += len(infos)
    if running_total > MAX_TOTAL_APK_ZIP_ENTRIES:
        raise ValueError(
            "artifact contains too many ZIP entries across APK splits for safe analysis"
        )
    for info in infos:
        _member_name(info.filename)
    return infos, running_total


def _scan_binary_markers(
    zf: ZipFile,
    info: ZipInfo,
    *,
    max_bytes: int,
) -> dict[str, Any]:
    """Stream a Flutter engine library and recover direct Dart version evidence.

    Snapshot hashes are deliberately not inferred with a raw byte regex here.
    The exact Flutter AOT profile performs ELF-aware snapshot extraction from
    libapp.so. This inspector only reports a Dart version when the engine itself
    contains the directly observable version marker.
    """

    scan_limit = max(0, min(info.file_size, MAX_LIBRARY_SCAN_BYTES, max_bytes))
    scanned = 0
    overlap = b""
    version = None
    with zf.open(info) as stream:
        while scanned < scan_limit:
            remaining = min(1024 * 1024, scan_limit - scanned)
            chunk = stream.read(remaining)
            if not chunk:
                break
            scanned += len(chunk)
            window = overlap + chunk
            match = DART_VERSION_RE.search(window)
            if match:
                version = match.group(1).decode("utf-8", "replace").strip(" \x00")
                break
            overlap = window[-256:]
    return {
        "bytes_scanned": scanned,
        "truncated": info.file_size > scanned,
        "dart_vm_version": version,
    }


def _preview_asset(zf: ZipFile, info: ZipInfo) -> dict[str, Any]:
    with zf.open(info) as stream:
        data = stream.read(MAX_ASSET_PREVIEW_BYTES + 1)
    truncated = info.file_size > MAX_ASSET_PREVIEW_BYTES or len(data) > MAX_ASSET_PREVIEW_BYTES
    data = data[:MAX_ASSET_PREVIEW_BYTES]
    return {
        "size": info.file_size,
        "truncated": truncated,
        "text": data.decode("utf-8", "replace"),
    }


def inspect_flutter(
    artifact: Path,
    nested_apks: Callable[[Path], Iterable[tuple[str, ZipFile]]],
    *,
    max_assets: int = 5000,
) -> dict[str, Any]:
    _validate_container_budget(artifact)
    max_assets = max(1, min(int(max_assets), MAX_ASSET_COUNT))
    artifact_sha256 = _sha256(artifact)
    operation = "flutter-inspect"
    libraries: list[dict[str, Any]] = []
    assets: list[dict[str, Any]] = []
    manifests: list[dict[str, Any]] = []
    apk_members: list[str] = []
    runtime_candidates: list[dict[str, Any]] = []
    asset_total = 0
    asset_truncated = False
    entries_seen = 0
    scan_remaining = MAX_TOTAL_LIBRARY_SCAN_BYTES
    scan_budget_exhausted = False

    for apk_member, zf in _nested_apk_iter(artifact, nested_apks):
        apk_member = _member_name(apk_member)
        apk_members.append(apk_member)
        infos, entries_seen = _bounded_infos(zf, running_total=entries_seen)
        for info in infos:
            if info.is_dir():
                continue
            match = FLUTTER_LIB_RE.fullmatch(info.filename)
            if match:
                abi, lib_name = match.groups()
                record = {
                    "apk_member": apk_member,
                    "path": info.filename,
                    "abi": abi,
                    "name": f"{lib_name}.so",
                    "size": info.file_size,
                    "evidence": _evidence(
                        artifact_sha256,
                        operation=operation,
                        state="observed",
                        apk_member=apk_member,
                        member_path=info.filename,
                    ),
                }
                libraries.append(record)
                if lib_name == "libflutter":
                    if scan_remaining <= 0:
                        scan_budget_exhausted = True
                    else:
                        markers = _scan_binary_markers(
                            zf,
                            info,
                            max_bytes=scan_remaining,
                        )
                        scan_remaining -= markers["bytes_scanned"]
                        if scan_remaining <= 0 and markers["truncated"]:
                            scan_budget_exhausted = True
                        if markers["dart_vm_version"]:
                            runtime_candidates.append(
                                {
                                    "apk_member": apk_member,
                                    "path": info.filename,
                                    **markers,
                                    "evidence": _evidence(
                                        artifact_sha256,
                                        operation=operation,
                                        state="observed",
                                        apk_member=apk_member,
                                        member_path=info.filename,
                                    ),
                                }
                            )
                continue

            if not info.filename.startswith("assets/flutter_assets/"):
                continue
            asset_total += 1
            if len(assets) >= max_assets:
                asset_truncated = True
                continue
            asset = {
                "apk_member": apk_member,
                "path": info.filename,
                "size": info.file_size,
            }
            assets.append(asset)
            basename = info.filename.rsplit("/", 1)[-1]
            if basename.startswith(("AssetManifest", "FontManifest", "NOTICES")):
                manifests.append(asset)

    libapp = [item for item in libraries if item["name"] == "libapp.so"]
    libflutter = [item for item in libraries if item["name"] == "libflutter.so"]
    if not libflutter:
        raise ValueError("artifact does not contain lib/<abi>/libflutter.so")

    versions = sorted(
        {
            item["dart_vm_version"]
            for item in runtime_candidates
            if item.get("dart_vm_version")
        }
    )
    runtime_status = "identified" if versions else "unknown"
    limitations = []
    if not libapp:
        limitations.append("libapp.so was not found in the inspected APK splits")
    if runtime_status == "unknown":
        limitations.append(
            "No bounded Dart VM version marker was observed in libflutter.so; runtime identity remains unknown"
        )
    limitations.append(
        "Snapshot hash extraction is deferred to the ELF-aware framework-flutter AOT profile; this inspector does not infer it from raw strings"
    )
    if scan_budget_exhausted:
        limitations.append(
            "The aggregate Flutter engine scan budget was exhausted before every libflutter.so could be scanned completely"
        )

    return {
        "artifact": artifact.name,
        "artifact_sha256": artifact_sha256,
        "analysis_id": _analysis_id(artifact_sha256, operation),
        "framework": "flutter",
        "apk_members": apk_members,
        "abis": sorted({item["abi"] for item in libraries}),
        "libraries": {
            "libapp": libapp,
            "libflutter": libflutter,
        },
        "assets": {
            "count": asset_total,
            "items": assets,
            "truncated": asset_truncated,
            "manifests": manifests,
        },
        "dart_runtime": {
            "status": runtime_status,
            "versions": versions,
            "snapshot_hashes": [],
            "candidates": runtime_candidates,
            "scan": {
                "bytes_scanned": MAX_TOTAL_LIBRARY_SCAN_BYTES - scan_remaining,
                "max_total_bytes": MAX_TOTAL_LIBRARY_SCAN_BYTES,
                "budget_exhausted": scan_budget_exhausted,
            },
        },
        "capability": {
            "profile": "framework-flutter",
            "status": "partial",
            "available": [
                "artifact-inventory",
                "asset-inventory",
                "bounded-runtime-marker-scan",
            ],
            "planned": [
                "dart-aot-index",
                "dart-xrefs",
                "dart-to-native-map",
                "flutter-network-model",
            ],
        },
        "limits": {
            "max_assets": max_assets,
            "max_total_library_scan_bytes": MAX_TOTAL_LIBRARY_SCAN_BYTES,
            "max_total_apk_zip_entries": MAX_TOTAL_APK_ZIP_ENTRIES,
            "max_bundle_total_apk_bytes": MAX_BUNDLE_TOTAL_APK_BYTES,
        },
        "limitations": limitations,
    }


def identify_dart_runtime(
    artifact: Path,
    nested_apks: Callable[[Path], Iterable[tuple[str, ZipFile]]],
) -> dict[str, Any]:
    result = inspect_flutter(artifact, nested_apks, max_assets=1)
    operation = "dart-runtime-identify"
    return {
        "artifact": result["artifact"],
        "artifact_sha256": result["artifact_sha256"],
        "analysis_id": _analysis_id(result["artifact_sha256"], operation),
        "dart_runtime": result["dart_runtime"],
        "limitations": result["limitations"],
    }


def extract_flutter_assets(
    artifact: Path,
    nested_apks: Callable[[Path], Iterable[tuple[str, ZipFile]]],
    *,
    max_items: int = 1000,
    max_previews: int = 20,
) -> dict[str, Any]:
    _validate_container_budget(artifact)
    max_items = max(1, min(int(max_items), MAX_ASSET_COUNT))
    max_previews = max(0, min(int(max_previews), MAX_ASSET_PREVIEWS))
    artifact_sha256 = _sha256(artifact)
    operation = "flutter-assets"
    items: list[dict[str, Any]] = []
    previews: list[dict[str, Any]] = []
    total = 0
    truncated = False
    entries_seen = 0
    flutter_marker_seen = False

    for apk_member, zf in _nested_apk_iter(artifact, nested_apks):
        apk_member = _member_name(apk_member)
        infos, entries_seen = _bounded_infos(zf, running_total=entries_seen)
        for info in infos:
            if info.is_dir():
                continue
            match = FLUTTER_LIB_RE.fullmatch(info.filename)
            if match and match.group(2) == "libflutter":
                flutter_marker_seen = True
            if not info.filename.startswith("assets/flutter_assets/"):
                continue
            total += 1
            if len(items) < max_items:
                items.append(
                    {
                        "apk_member": apk_member,
                        "path": info.filename,
                        "size": info.file_size,
                    }
                )
            else:
                truncated = True
            if (
                len(previews) < max_previews
                and (
                    TEXT_ASSET_RE.search(info.filename)
                    or info.filename.rsplit("/", 1)[-1].startswith(
                        ("AssetManifest", "FontManifest", "NOTICES")
                    )
                )
            ):
                preview = _preview_asset(zf, info)
                previews.append(
                    {
                        "apk_member": apk_member,
                        "path": info.filename,
                        **preview,
                        "evidence": _evidence(
                            artifact_sha256,
                            operation=operation,
                            state="observed",
                            apk_member=apk_member,
                            member_path=info.filename,
                        ),
                    }
                )

    if not flutter_marker_seen:
        raise ValueError("artifact does not contain lib/<abi>/libflutter.so")
    if total == 0:
        raise ValueError("artifact contains no assets/flutter_assets entries")
    return {
        "artifact": artifact.name,
        "artifact_sha256": artifact_sha256,
        "analysis_id": _analysis_id(artifact_sha256, operation),
        "count": total,
        "items": items,
        "truncated": truncated,
        "previews": previews,
        "limits": {
            "max_items": max_items,
            "max_previews": max_previews,
            "max_preview_bytes": MAX_ASSET_PREVIEW_BYTES,
            "max_total_apk_zip_entries": MAX_TOTAL_APK_ZIP_ENTRIES,
            "max_bundle_total_apk_bytes": MAX_BUNDLE_TOTAL_APK_BYTES,
        },
    }
