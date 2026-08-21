from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Callable, Iterable
from zipfile import ZipFile, ZipInfo

import peg_schema

MAX_LIBRARY_SCAN_BYTES = 256 * 1024 * 1024
MAX_ASSET_COUNT = 20_000
MAX_ASSET_PREVIEW_BYTES = 64 * 1024
MAX_ASSET_PREVIEWS = 50

DART_VERSION_RE = re.compile(
    rb"Dart VM version:\s*([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?)",
    re.IGNORECASE,
)
SNAPSHOT_HASH_RE = re.compile(
    rb"(?:snapshot(?:[_ ]?hash)?|SnapshotHash)[^0-9a-fA-F]{0,48}([0-9a-fA-F]{32,64})",
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


def _analysis_id(artifact_sha256: str) -> str:
    return f"flutter-inspect:{artifact_sha256[:16]}"


def _evidence(
    artifact_sha256: str,
    *,
    state: str,
    apk_member: str,
    member_path: str,
    analyzer: str = "safe-flutter-inspector",
    analyzer_version: str = "1",
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    return peg_schema.evidence(
        analysis_id=_analysis_id(artifact_sha256),
        artifact_sha256=artifact_sha256,
        analyzer_name=analyzer,
        analyzer_version=analyzer_version,
        state=state,
        location={"apk_member": apk_member, "member": member_path},
        limitations=limitations,
    )


def _scan_binary_markers(zf: ZipFile, info: ZipInfo) -> dict[str, Any]:
    """Stream a native library and recover bounded runtime markers.

    This does not attempt to parse Dart AOT snapshots. It only records strings
    directly observed in the engine/native library so unsupported runtime
    identification remains explicit rather than guessed.
    """

    scanned = 0
    overlap = b""
    version = None
    snapshot_hash = None
    with zf.open(info) as stream:
        while scanned < min(info.file_size, MAX_LIBRARY_SCAN_BYTES):
            remaining = min(1024 * 1024, MAX_LIBRARY_SCAN_BYTES - scanned)
            chunk = stream.read(remaining)
            if not chunk:
                break
            scanned += len(chunk)
            window = overlap + chunk
            if version is None:
                match = DART_VERSION_RE.search(window)
                if match:
                    version = match.group(1).decode("utf-8", "replace").strip(" \x00")
            if snapshot_hash is None:
                match = SNAPSHOT_HASH_RE.search(window)
                if match:
                    snapshot_hash = match.group(1).decode("ascii", "ignore").lower()
            if version and snapshot_hash:
                break
            overlap = window[-512:]
    return {
        "bytes_scanned": scanned,
        "truncated": info.file_size > scanned,
        "dart_vm_version": version,
        "snapshot_hash": snapshot_hash,
    }


def _preview_asset(zf: ZipFile, info: ZipInfo) -> dict[str, Any]:
    data = zf.read(info, pwd=None)[:MAX_ASSET_PREVIEW_BYTES]
    return {
        "size": info.file_size,
        "truncated": info.file_size > len(data),
        "text": data.decode("utf-8", "replace"),
    }


def inspect_flutter(
    artifact: Path,
    nested_apks: Callable[[Path], Iterable[tuple[str, ZipFile]]],
    *,
    max_assets: int = 5000,
) -> dict[str, Any]:
    max_assets = max(1, min(int(max_assets), MAX_ASSET_COUNT))
    artifact_sha256 = _sha256(artifact)
    libraries: list[dict[str, Any]] = []
    assets: list[dict[str, Any]] = []
    manifests: list[dict[str, Any]] = []
    apk_members: list[str] = []
    runtime_candidates: list[dict[str, Any]] = []
    asset_total = 0
    asset_truncated = False

    for apk_member, zf in nested_apks(artifact):
        apk_members.append(apk_member)
        infos = [item for item in zf.infolist() if not item.is_dir()]
        for info in infos:
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
                        state="observed",
                        apk_member=apk_member,
                        member_path=info.filename,
                    ),
                }
                libraries.append(record)
                if lib_name == "libflutter":
                    markers = _scan_binary_markers(zf, info)
                    if markers["dart_vm_version"] or markers["snapshot_hash"]:
                        runtime_candidates.append(
                            {
                                "apk_member": apk_member,
                                "path": info.filename,
                                **markers,
                                "evidence": _evidence(
                                    artifact_sha256,
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
    if not (libapp or libflutter or asset_total):
        raise ValueError("artifact does not contain recognized Flutter markers")

    versions = sorted(
        {
            item["dart_vm_version"]
            for item in runtime_candidates
            if item.get("dart_vm_version")
        }
    )
    snapshot_hashes = sorted(
        {
            item["snapshot_hash"]
            for item in runtime_candidates
            if item.get("snapshot_hash")
        }
    )
    runtime_status = "identified" if versions or snapshot_hashes else "unknown"
    limitations = []
    if not libapp:
        limitations.append("libapp.so was not found in the inspected APK splits")
    if not libflutter:
        limitations.append("libflutter.so was not found; Dart runtime markers could not be scanned")
    if runtime_status == "unknown":
        limitations.append(
            "No bounded Dart VM version/snapshot hash marker was observed; AOT analyzer selection requires a later runtime-identification backend"
        )

    return {
        "artifact": artifact.name,
        "artifact_sha256": artifact_sha256,
        "analysis_id": _analysis_id(artifact_sha256),
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
            "snapshot_hashes": snapshot_hashes,
            "candidates": runtime_candidates,
        },
        "capability": {
            "profile": "framework-flutter",
            "status": "partial",
            "available": ["artifact-inventory", "asset-inventory", "bounded-runtime-marker-scan"],
            "planned": ["dart-aot-index", "dart-xrefs", "dart-to-native-map", "flutter-network-model"],
        },
        "limitations": limitations,
    }


def identify_dart_runtime(
    artifact: Path,
    nested_apks: Callable[[Path], Iterable[tuple[str, ZipFile]]],
) -> dict[str, Any]:
    result = inspect_flutter(artifact, nested_apks, max_assets=1)
    return {
        "artifact": result["artifact"],
        "artifact_sha256": result["artifact_sha256"],
        "analysis_id": result["analysis_id"],
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
    max_items = max(1, min(int(max_items), MAX_ASSET_COUNT))
    max_previews = max(0, min(int(max_previews), MAX_ASSET_PREVIEWS))
    artifact_sha256 = _sha256(artifact)
    items: list[dict[str, Any]] = []
    previews: list[dict[str, Any]] = []
    total = 0
    truncated = False

    for apk_member, zf in nested_apks(artifact):
        for info in zf.infolist():
            if info.is_dir() or not info.filename.startswith("assets/flutter_assets/"):
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
                and info.file_size <= 4 * 1024 * 1024
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
                            state="observed",
                            apk_member=apk_member,
                            member_path=info.filename,
                        ),
                    }
                )

    if total == 0:
        raise ValueError("artifact contains no assets/flutter_assets entries")
    return {
        "artifact": artifact.name,
        "artifact_sha256": artifact_sha256,
        "analysis_id": _analysis_id(artifact_sha256),
        "count": total,
        "items": items,
        "truncated": truncated,
        "previews": previews,
        "limits": {
            "max_items": max_items,
            "max_previews": max_previews,
            "max_preview_bytes": MAX_ASSET_PREVIEW_BYTES,
        },
    }
