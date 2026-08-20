#!/usr/bin/env python3
"""Bounded semantic program-analysis helpers for Safe Android Reverser."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator

MAX_METHODS = 200_000
MAX_EDGES = 500_000
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_BUNDLE_APK_BYTES = 512 * 1024 * 1024
MAX_BUNDLE_TOTAL_BYTES = 900 * 1024 * 1024
METHOD_RE = re.compile(r"(?m)^\s*(?:@[\w$.()\"', ={}]+\s*)*(?:(?:public|protected|private|static|final|abstract|synchronized|native|default|open|internal|suspend|override|inline|operator|infix|tailrec|external)\s+)*(?:fun\s+)?(?:<[^>]+>\s*)?(?:[\w$.<>?\[\], ]+\s+)?([A-Za-z_$][\w$]*)\s*\(([^)]*)\)")
CLASS_RE = re.compile(r"\b(?:class|interface|enum|object)\s+([A-Za-z_$][\w$]*)")
RETROFIT_RE = re.compile(r"@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP)\s*\(\s*\"([^\"]+)\"", re.I)
URL_RE = re.compile(r"https?://(?:[A-Za-z0-9.-]+|\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?(?:/[^\s\"'<>]*)?", re.I)
AUTH_RE = re.compile(r"\b(Authorization|Bearer|access[_-]?token|refresh[_-]?token|api[_-]?key|X-API-Key|signature|HMAC|Mac\.getInstance)\b", re.I)
TYPE_RE = re.compile(r"\b([A-Z][A-Za-z0-9_$]*(?:<[^>]+>)?)\b")


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _save(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def capabilities() -> dict[str, Any]:
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


def _artifact(job: Path, workspace: Path) -> Path:
    rel = _load(job / "job.json")["artifact"]
    path = (workspace / rel).resolve()
    if path != workspace and workspace not in path.parents:
        raise ValueError("job artifact escapes workspace")
    if not path.is_file():
        raise ValueError("job artifact no longer exists")
    return path


def _sources(job: Path) -> Iterable[Path]:
    seen = set()
    for root in (job / "jadx" / "sources", job / "jadx", job / "vineflower"):
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            resolved = path.resolve()
            if path.is_file() and path.suffix.lower() in {".java", ".kt"} and resolved not in seen:
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


def _methods(text: str) -> list[tuple[int, str, str]]:
    output = []
    seen = set()
    for match in METHOD_RE.finditer(text):
        name = match.group(1)
        if name in {"if", "for", "while", "switch", "catch", "when"}:
            continue
        line = text.count("\n", 0, match.start()) + 1
        if (line, name) not in seen:
            seen.add((line, name))
            output.append((line, name, match.group(2).strip()))
    return sorted(output)


def _source_index(job: Path, max_methods: int) -> dict[str, Any]:
    methods = []
    for path in _sources(job):
        text = _text(path)
        if not text:
            continue
        package, clazz = _source_meta(text, path)
        fqn = f"{package}.{clazz}" if package else clazz
        for line, name, params in _methods(text):
            methods.append({
                "id": f"{fqn}#{name}@{line}",
                "class": fqn,
                "name": name,
                "descriptor": params,
                "external": False,
                "source": {"file": str(path.relative_to(job)), "line": line},
            })
            if len(methods) >= max_methods:
                break
        if len(methods) >= max_methods:
            break
    return {
        "schema_version": 1,
        "analysis_kind": "source-fallback",
        "analyzer": {"name": "safe-source-index", "version": "1"},
        "created_at_epoch": int(time.time()),
        "methods": methods,
        "call_edges": [],
        "truncated": {"methods": len(methods) >= max_methods, "edges": False},
    }


def _apks(artifact: Path, temp_root: Path) -> list[tuple[str, Path]]:
    if artifact.suffix.lower() == ".apk":
        if artifact.stat().st_size > MAX_BUNDLE_APK_BYTES:
            raise ValueError("APK exceeds semantic-analysis size limit")
        return [(artifact.name, artifact)]
    if artifact.suffix.lower() not in {".xapk", ".apks", ".apkm"}:
        return []

    output = []
    total = 0
    with zipfile.ZipFile(artifact) as archive:
        for info in archive.infolist():
            if info.is_dir() or not info.filename.lower().endswith(".apk"):
                continue
            if len(output) >= 128:
                raise ValueError("bundle contains more than 128 APK members")
            if info.file_size > MAX_BUNDLE_APK_BYTES:
                raise ValueError(f"bundle APK member exceeds size limit: {info.filename}")
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


@contextmanager
def _androguard_analysis(artifact: Path) -> Iterator[tuple[Any, dict[str, str]]]:
    """Build one Analysis object across all APK members so split-to-split XREFs can resolve."""
    from androguard.core import apk as ag_apk  # type: ignore
    from androguard.core import dex as ag_dex  # type: ignore
    from androguard.core.analysis.analysis import Analysis  # type: ignore

    with tempfile.TemporaryDirectory(prefix="safe-pu-") as temp_dir:
        analysis = Analysis()
        class_members: dict[str, str] = {}
        dex_count = 0
        for member, apk_path in _apks(artifact, Path(temp_dir)):
            parsed = ag_apk.APK(str(apk_path))
            target_sdk = parsed.get_target_sdk_version()
            for dex_bytes in parsed.get_all_dex():
                dex_count += 1
                if dex_count > 256:
                    raise ValueError("artifact contains more than 256 DEX files")
                vm = ag_dex.DEX(dex_bytes, using_api=target_sdk)
                analysis.add(vm)
                for clazz in vm.get_classes():
                    try:
                        descriptor = str(clazz.get_name())
                    except Exception:
                        continue
                    class_members.setdefault(descriptor, member)
        if dex_count == 0:
            raise ValueError("artifact contains no DEX code")
        analysis.create_xref()
        yield analysis, class_members


def _method_record(method: Any, class_members: dict[str, str]) -> dict[str, Any]:
    raw = method.get_method() if hasattr(method, "get_method") else method
    class_name = getattr(method, "class_name", None) or getattr(raw, "get_class_name", lambda: "")()
    name = getattr(method, "name", None) or getattr(raw, "get_name", lambda: "")()
    descriptor = getattr(method, "descriptor", None) or getattr(raw, "get_descriptor", lambda: "")()
    full_name = getattr(method, "full_name", None) or f"{class_name} {name} {descriptor}"
    member = class_members.get(str(class_name), "external-or-unknown")
    return {
        "id": str(full_name),
        "class": str(class_name).strip("L;").replace("/", "."),
        "name": str(name),
        "descriptor": str(descriptor),
        "external": bool(method.is_external()) if hasattr(method, "is_external") else False,
        "source": {"apk_member": member},
    }


def _dex_index(artifact: Path, max_methods: int, max_edges: int) -> dict[str, Any]:
    import androguard  # type: ignore

    methods = []
    edges = []
    seen = set()
    method_truncated = False
    edge_truncated = False
    with _androguard_analysis(artifact) as (analysis, class_members):
        for method in analysis.get_methods():
            record = _method_record(method, class_members)
            if record["id"] not in seen:
                if len(methods) >= max_methods:
                    method_truncated = True
                else:
                    seen.add(record["id"])
                    methods.append(record)

            if len(edges) >= max_edges:
                edge_truncated = True
                continue
            for _, callee, offset in (method.get_xref_to() if hasattr(method, "get_xref_to") else []):
                if len(edges) >= max_edges:
                    edge_truncated = True
                    break
                edges.append({
                    "from": record["id"],
                    "to": _method_record(callee, class_members)["id"],
                    "offset": int(offset),
                    "confidence": 0.98,
                    "kind": "dex-xref",
                })

    return {
        "schema_version": 1,
        "analysis_kind": "dex-xref",
        "analyzer": {"name": "androguard", "version": getattr(androguard, "__version__", "unknown")},
        "created_at_epoch": int(time.time()),
        "methods": methods,
        "call_edges": edges,
        "truncated": {"methods": method_truncated, "edges": edge_truncated},
    }


def build_program_index(job: Path, workspace: Path, *, max_methods: int = 100_000, max_edges: int = 250_000, force: bool = False) -> dict[str, Any]:
    max_methods = max(100, min(int(max_methods), MAX_METHODS))
    max_edges = max(100, min(int(max_edges), MAX_EDGES))
    index_path = job / "program-index.json"
    if index_path.exists() and not force:
        index = _load(index_path)
        return {
            "job_id": job.name,
            "cached": True,
            "analysis_kind": index.get("analysis_kind"),
            "method_count": len(index.get("methods", [])),
            "edge_count": len(index.get("call_edges", [])),
            "truncated": index.get("truncated", {}),
            "analyzer": index.get("analyzer", {}),
        }

    artifact = _artifact(job, workspace)
    try:
        index = _dex_index(artifact, max_methods, max_edges)
    except Exception as exc:
        index = _source_index(job, max_methods)
        index["fallback_reason"] = f"Androguard unavailable/failed: {type(exc).__name__}: {exc}"
    index.update({"job_id": job.name, "artifact": str(artifact.relative_to(workspace))})
    _save(index_path, index)
    return {
        "job_id": job.name,
        "cached": False,
        "analysis_kind": index["analysis_kind"],
        "method_count": len(index["methods"]),
        "edge_count": len(index["call_edges"]),
        "truncated": index["truncated"],
        "analyzer": index["analyzer"],
        "fallback_reason": index.get("fallback_reason"),
    }


def _index(job: Path, workspace: Path) -> dict[str, Any]:
    if not (job / "program-index.json").exists():
        build_program_index(job, workspace)
    return _load(job / "program-index.json")


def find_symbols(job: Path, workspace: Path, query: str, *, limit: int = 100) -> dict[str, Any]:
    if not query or len(query) > 512:
        raise ValueError("query must be 1..512 characters")
    index = _index(job, workspace)
    needle = query.lower()
    output = []
    cap = max(1, min(int(limit), 500))
    for method in index.get("methods", []):
        haystack = f"{method.get('class','')} {method.get('name','')} {method.get('descriptor','')} {method.get('id','')}".lower()
        if needle in haystack:
            output.append(method)
            if len(output) >= cap:
                break
    return {"job_id": job.name, "query": query, "analysis_kind": index.get("analysis_kind"), "matches": output}


def find_xrefs(job: Path, workspace: Path, query: str, *, direction: str = "both", limit: int = 200) -> dict[str, Any]:
    if direction not in {"incoming", "outgoing", "both"}:
        raise ValueError("invalid direction")
    index = _index(job, workspace)
    needle = query.lower()
    ids = {
        method["id"]
        for method in index.get("methods", [])
        if needle in f"{method.get('class','')} {method.get('name','')} {method.get('descriptor','')} {method.get('id','')}".lower()
    }
    output = []
    cap = max(1, min(int(limit), 1000))
    for edge in index.get("call_edges", []):
        incoming = direction in {"incoming", "both"} and edge.get("to") in ids
        outgoing = direction in {"outgoing", "both"} and edge.get("from") in ids
        if incoming or outgoing:
            output.append(edge)
            if len(output) >= cap:
                break
    return {
        "job_id": job.name,
        "query": query,
        "direction": direction,
        "matched_symbols": sorted(ids)[:200],
        "xrefs": output,
        "analysis_kind": index.get("analysis_kind"),
    }


def get_cfg(job: Path, workspace: Path, query: str, *, max_blocks: int = 500) -> dict[str, Any]:
    artifact = _artifact(job, workspace)
    needle = query.lower()
    matches = []
    cap = max(1, min(int(max_blocks), 10_000))
    with _androguard_analysis(artifact) as (analysis, class_members):
        for method in analysis.get_methods():
            record = _method_record(method, class_members)
            haystack = f"{record['class']} {record['name']} {record['descriptor']} {record['id']}".lower()
            if needle not in haystack or (hasattr(method, "is_external") and method.is_external()):
                continue
            blocks = []
            for block in method.get_basic_blocks():
                successors = []
                for child in block.get_next():
                    target = child[-1] if isinstance(child, (tuple, list)) and child else child
                    try:
                        successors.append(int(target.get_start()))
                    except Exception:
                        pass
                blocks.append({
                    "start": int(block.get_start()),
                    "end": int(block.get_end()),
                    "name": str(block.get_name()),
                    "successors": successors,
                })
                if len(blocks) >= cap:
                    break
            matches.append({"method": record, "blocks": blocks, "truncated": len(blocks) >= cap})
            if len(matches) >= 20:
                break
    return {"job_id": job.name, "query": query, "matches": matches, "analyzer": "androguard", "confidence": 0.98}


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
        return {"artifact": artifact.name, "available": True, "analyzer": "apkid-external", "matches": [], "error": "APKiD timed out"}
    if process.returncode != 0:
        return {"artifact": artifact.name, "available": True, "analyzer": "apkid-external", "matches": [], "error": process.stderr[-4000:]}
    try:
        payload = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        return {"artifact": artifact.name, "available": True, "analyzer": "apkid-external", "matches": [], "error": f"invalid APKiD JSON: {exc}"}

    signal_tags = {
        "packer", "protector", "obfuscator", "anti_vm", "anti_disassembly",
        "anti_debug", "anti_root", "dropper", "manipulator", "compiler",
    }
    matches = []
    for file_result in payload.get("files", []):
        for tag_text, descriptions in (file_result.get("matches") or {}).items():
            tags = sorted(tag.strip() for tag in tag_text.split(",") if tag.strip())
            if not set(tags) & signal_tags:
                continue
            for description in descriptions:
                matches.append({"member": file_result.get("filename"), "tags": tags, "description": str(description)})
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


def _ranges(text: str) -> list[tuple[int, int, str, str]]:
    methods = _methods(text)
    line_count = len(text.splitlines())
    output = []
    for index, (start, name, params) in enumerate(methods):
        end = methods[index + 1][0] - 1 if index + 1 < len(methods) else line_count
        output.append((start, end, name, params))
    return output


def _context(ranges: list[tuple[int, int, str, str]], line: int) -> tuple[str | None, str | None]:
    for start, end, name, params in ranges:
        if start <= line <= end:
            return name, params
    return None, None


def extract_network_model(job: Path, workspace: Path, *, max_items: int = 500) -> dict[str, Any]:
    cap = max(20, min(int(max_items), 2000))
    index = _index(job, workspace)
    by_name: dict[str, list[str]] = {}
    for method in index.get("methods", []):
        by_name.setdefault(method.get("name", ""), []).append(method.get("id", ""))

    endpoints = []
    urls = []
    auth = []
    models = set()
    scanned = 0
    for path in _sources(job):
        text = _text(path)
        if not text:
            continue
        scanned += 1
        relative = str(path.relative_to(job))
        package, clazz = _source_meta(text, path)
        fqn = f"{package}.{clazz}" if package else clazz
        ranges = _ranges(text)
        lines = text.splitlines()

        for match in RETROFIT_RE.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            name, params = _context(ranges, line)
            if name is None:
                for start, _, candidate, candidate_params in ranges:
                    if line <= start <= line + 8:
                        name, params = candidate, candidate_params
                        break
            nearby = "\n".join(lines[max(0, line - 4):min(len(lines), line + 12)])
            for type_name in TYPE_RE.findall(nearby)[:10]:
                models.add(type_name)
            ids = set(by_name.get(name or "", []))
            callers = []
            for edge in index.get("call_edges", []):
                if edge.get("to") in ids and edge.get("from") not in callers:
                    callers.append(edge.get("from"))
                if len(callers) >= 20:
                    break
            endpoints.append({
                "http_method": match.group(1).upper(),
                "path": match.group(2),
                "kind": "retrofit",
                "declaring_class": fqn,
                "declaring_method": name,
                "parameter_signature": params,
                "callers": callers,
                "auth_signals": sorted(set(signal.group(1) for signal in AUTH_RE.finditer(nearby))),
                "evidence": {
                    "file": relative,
                    "line": line,
                    "analyzer": "source+program-index",
                    "confidence": 0.93 if index.get("analysis_kind") == "dex-xref" else 0.75,
                },
            })
            if len(endpoints) >= cap:
                break

        for match in URL_RE.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            name, _ = _context(ranges, line)
            urls.append({
                "url": match.group(0).rstrip(".,);]"),
                "declaring_class": fqn,
                "declaring_method": name,
                "evidence": {"file": relative, "line": line, "confidence": 0.9},
            })
            if len(urls) >= cap:
                break

        for match in AUTH_RE.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            name, _ = _context(ranges, line)
            auth.append({
                "signal": match.group(1),
                "declaring_class": fqn,
                "declaring_method": name,
                "evidence": {"file": relative, "line": line, "confidence": 0.75},
            })
            if len(auth) >= cap:
                break

    report = {
        "schema_version": 1,
        "job_id": job.name,
        "source_files_scanned": scanned,
        "program_index_kind": index.get("analysis_kind"),
        "endpoints": endpoints[:cap],
        "urls": urls[:cap],
        "auth_evidence": auth[:cap],
        "candidate_models": sorted(models)[:cap],
        "notes": [
            "Caller links use one cross-split DEX XREF graph when Androguard is available.",
            "Auth evidence reports signal names/locations, not secret values.",
            "Model candidates remain lexical hints until dedicated data-flow analysis is added.",
        ],
    }
    _save(job / "network-model.json", report)
    return report
