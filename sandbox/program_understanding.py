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
from pathlib import Path
from typing import Any, Iterable

MAX_METHODS = 200_000
MAX_EDGES = 500_000
MAX_SOURCE_BYTES = 4 * 1024 * 1024
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
    av = {"androguard": False, "apkid": bool(shutil.which("apkid")), "versions": {"androguard": None, "apkid": "external-cli" if shutil.which("apkid") else None}}
    try:
        import androguard  # type: ignore
        av["androguard"] = True
        av["versions"]["androguard"] = getattr(androguard, "__version__", "installed")
    except Exception:
        pass
    return av


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
        for p in root.rglob("*"):
            if p.is_file() and p.suffix.lower() in {".java", ".kt"} and p.resolve() not in seen:
                seen.add(p.resolve())
                if len(seen) > 150_000:
                    raise ValueError("source tree exceeds safe file-count limit")
                yield p


def _text(path: Path) -> str:
    return "" if path.stat().st_size > MAX_SOURCE_BYTES else path.read_text(encoding="utf-8", errors="replace")


def _source_meta(text: str, path: Path) -> tuple[str, str]:
    pm = re.search(r"(?m)^\s*package\s+([\w.]+)", text)
    cm = CLASS_RE.search(text)
    cls = cm.group(1) if cm else path.stem
    return (pm.group(1) if pm else "", cls)


def _methods(text: str) -> list[tuple[int, str, str]]:
    out, seen = [], set()
    for m in METHOD_RE.finditer(text):
        name = m.group(1)
        if name in {"if", "for", "while", "switch", "catch", "when"}:
            continue
        line = text.count("\n", 0, m.start()) + 1
        if (line, name) not in seen:
            seen.add((line, name))
            out.append((line, name, m.group(2).strip()))
    return sorted(out)


def _source_index(job: Path, max_methods: int) -> dict[str, Any]:
    methods = []
    for p in _sources(job):
        text = _text(p)
        if not text:
            continue
        pkg, cls = _source_meta(text, p)
        fqn = f"{pkg}.{cls}" if pkg else cls
        for line, name, params in _methods(text):
            methods.append({"id": f"{fqn}#{name}@{line}", "class": fqn, "name": name, "descriptor": params, "external": False, "source": {"file": str(p.relative_to(job)), "line": line}})
            if len(methods) >= max_methods:
                break
        if len(methods) >= max_methods:
            break
    return {"schema_version": 1, "analysis_kind": "source-fallback", "analyzer": {"name": "safe-source-index", "version": "1"}, "created_at_epoch": int(time.time()), "methods": methods, "call_edges": [], "truncated": {"methods": len(methods) >= max_methods, "edges": False}}


def _apks(artifact: Path, tmp: Path) -> list[tuple[str, Path]]:
    if artifact.suffix.lower() == ".apk":
        return [(artifact.name, artifact)]
    if artifact.suffix.lower() not in {".xapk", ".apks", ".apkm"}:
        return []
    out = []
    with zipfile.ZipFile(artifact) as zf:
        for info in zf.infolist():
            if info.is_dir() or not info.filename.lower().endswith(".apk"):
                continue
            if len(out) >= 128:
                break
            dest = tmp / f"{len(out):03d}-{Path(info.filename).name}"
            with zf.open(info) as src, dest.open("wb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
            out.append((info.filename, dest))
    return out


def _method_record(m: Any, member: str) -> dict[str, Any]:
    raw = m.get_method() if hasattr(m, "get_method") else m
    cls = getattr(m, "class_name", None) or getattr(raw, "get_class_name", lambda: "")()
    name = getattr(m, "name", None) or getattr(raw, "get_name", lambda: "")()
    desc = getattr(m, "descriptor", None) or getattr(raw, "get_descriptor", lambda: "")()
    full = getattr(m, "full_name", None) or f"{cls} {name} {desc}"
    return {"id": str(full), "class": str(cls).strip("L;").replace("/", "."), "name": str(name), "descriptor": str(desc), "external": bool(m.is_external()) if hasattr(m, "is_external") else False, "source": {"apk_member": member}}


def _dex_index(artifact: Path, max_methods: int, max_edges: int) -> dict[str, Any]:
    import androguard  # type: ignore
    from androguard.misc import AnalyzeAPK  # type: ignore
    methods, edges, seen = [], [], set()
    method_truncated = edge_truncated = False
    with tempfile.TemporaryDirectory(prefix="safe-pu-") as td:
        for member, apk in _apks(artifact, Path(td)):
            _, _, dx = AnalyzeAPK(str(apk))
            for m in dx.get_methods():
                rec = _method_record(m, member)
                if rec["id"] not in seen:
                    if len(methods) >= max_methods:
                        method_truncated = True
                    else:
                        seen.add(rec["id"])
                        methods.append(rec)
                if len(edges) < max_edges:
                    for _, callee, offset in (m.get_xref_to() if hasattr(m, "get_xref_to") else []):
                        if len(edges) >= max_edges:
                            edge_truncated = True
                            break
                        edges.append({"from": rec["id"], "to": _method_record(callee, member)["id"], "offset": int(offset), "confidence": 0.98, "kind": "dex-xref"})
                else:
                    edge_truncated = True
            if method_truncated and edge_truncated:
                break
    return {"schema_version": 1, "analysis_kind": "dex-xref", "analyzer": {"name": "androguard", "version": getattr(androguard, "__version__", "unknown")}, "created_at_epoch": int(time.time()), "methods": methods, "call_edges": edges, "truncated": {"methods": method_truncated, "edges": edge_truncated}}


def build_program_index(job: Path, workspace: Path, *, max_methods: int = 100_000, max_edges: int = 250_000, force: bool = False) -> dict[str, Any]:
    max_methods = max(100, min(int(max_methods), MAX_METHODS))
    max_edges = max(100, min(int(max_edges), MAX_EDGES))
    path = job / "program-index.json"
    if path.exists() and not force:
        idx = _load(path)
        return {"job_id": job.name, "cached": True, "analysis_kind": idx.get("analysis_kind"), "method_count": len(idx.get("methods", [])), "edge_count": len(idx.get("call_edges", [])), "truncated": idx.get("truncated", {}), "analyzer": idx.get("analyzer", {})}
    artifact = _artifact(job, workspace)
    try:
        idx = _dex_index(artifact, max_methods, max_edges)
    except Exception as exc:
        idx = _source_index(job, max_methods)
        idx["fallback_reason"] = f"Androguard unavailable/failed: {type(exc).__name__}: {exc}"
    idx.update({"job_id": job.name, "artifact": str(artifact.relative_to(workspace))})
    _save(path, idx)
    return {"job_id": job.name, "cached": False, "analysis_kind": idx["analysis_kind"], "method_count": len(idx["methods"]), "edge_count": len(idx["call_edges"]), "truncated": idx["truncated"], "analyzer": idx["analyzer"], "fallback_reason": idx.get("fallback_reason")}


def _index(job: Path, workspace: Path) -> dict[str, Any]:
    if not (job / "program-index.json").exists():
        build_program_index(job, workspace)
    return _load(job / "program-index.json")


def find_symbols(job: Path, workspace: Path, query: str, *, limit: int = 100) -> dict[str, Any]:
    if not query or len(query) > 512:
        raise ValueError("query must be 1..512 characters")
    idx, q, out = _index(job, workspace), query.lower(), []
    cap = max(1, min(int(limit), 500))
    for m in idx.get("methods", []):
        if q in f"{m.get('class','')} {m.get('name','')} {m.get('descriptor','')} {m.get('id','')}".lower():
            out.append(m)
            if len(out) >= cap:
                break
    return {"job_id": job.name, "query": query, "analysis_kind": idx.get("analysis_kind"), "matches": out}


def find_xrefs(job: Path, workspace: Path, query: str, *, direction: str = "both", limit: int = 200) -> dict[str, Any]:
    if direction not in {"incoming", "outgoing", "both"}:
        raise ValueError("invalid direction")
    idx, q = _index(job, workspace), query.lower()
    ids = {m["id"] for m in idx.get("methods", []) if q in f"{m.get('class','')} {m.get('name','')} {m.get('descriptor','')} {m.get('id','')}".lower()}
    out, cap = [], max(1, min(int(limit), 1000))
    for e in idx.get("call_edges", []):
        if (direction in {"incoming", "both"} and e.get("to") in ids) or (direction in {"outgoing", "both"} and e.get("from") in ids):
            out.append(e)
            if len(out) >= cap:
                break
    return {"job_id": job.name, "query": query, "direction": direction, "matched_symbols": sorted(ids)[:200], "xrefs": out, "analysis_kind": idx.get("analysis_kind")}


def get_cfg(job: Path, workspace: Path, query: str, *, max_blocks: int = 500) -> dict[str, Any]:
    from androguard.misc import AnalyzeAPK  # type: ignore
    artifact, q, matches = _artifact(job, workspace), query.lower(), []
    cap = max(1, min(int(max_blocks), 10_000))
    with tempfile.TemporaryDirectory(prefix="safe-cfg-") as td:
        for member, apk in _apks(artifact, Path(td)):
            _, _, dx = AnalyzeAPK(str(apk))
            for m in dx.get_methods():
                rec = _method_record(m, member)
                if q not in f"{rec['class']} {rec['name']} {rec['descriptor']} {rec['id']}".lower() or (hasattr(m, "is_external") and m.is_external()):
                    continue
                blocks = []
                for bb in m.get_basic_blocks():
                    succ = []
                    for child in bb.get_next():
                        target = child[-1] if isinstance(child, (tuple, list)) and child else child
                        try:
                            succ.append(int(target.get_start()))
                        except Exception:
                            pass
                    blocks.append({"start": int(bb.get_start()), "end": int(bb.get_end()), "name": str(bb.get_name()), "successors": succ})
                    if len(blocks) >= cap:
                        break
                matches.append({"method": rec, "blocks": blocks, "truncated": len(blocks) >= cap})
                if len(matches) >= 20:
                    break
            if len(matches) >= 20:
                break
    return {"job_id": job.name, "query": query, "matches": matches, "analyzer": "androguard", "confidence": 0.98}


def identify_protector(artifact: Path, *, timeout: int = 10) -> dict[str, Any]:
    """Use APKiD only as an optional external CLI analyzer."""
    binary = shutil.which("apkid")
    timeout = max(1, min(int(timeout), 60))
    if not binary:
        return {"artifact": artifact.name, "available": False, "analyzer": "apkid-external", "matches": [], "error": "APKiD CLI is not installed in this sandbox profile"}
    try:
        p = subprocess.run([binary, "-j", "-t", str(timeout), str(artifact)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace", timeout=timeout + 15, check=False)
    except subprocess.TimeoutExpired:
        return {"artifact": artifact.name, "available": True, "analyzer": "apkid-external", "matches": [], "error": "APKiD timed out"}
    if p.returncode != 0:
        return {"artifact": artifact.name, "available": True, "analyzer": "apkid-external", "matches": [], "error": p.stderr[-4000:]}
    try:
        payload = json.loads(p.stdout)
    except json.JSONDecodeError as exc:
        return {"artifact": artifact.name, "available": True, "analyzer": "apkid-external", "matches": [], "error": f"invalid APKiD JSON: {exc}"}
    signal = {"packer", "protector", "obfuscator", "anti_vm", "anti_disassembly", "anti_debug", "anti_root", "dropper", "manipulator", "compiler"}
    matches = []
    for f in payload.get("files", []):
        for tag_text, descriptions in (f.get("matches") or {}).items():
            tags = sorted(t.strip() for t in tag_text.split(",") if t.strip())
            if not set(tags) & signal:
                continue
            for desc in descriptions:
                matches.append({"member": f.get("filename"), "tags": tags, "description": str(desc)})
                if len(matches) >= 500:
                    break
    route = "protected-dex-native" if any(set(m["tags"]) & {"packer", "protector", "dropper"} for m in matches) else "semantic-dex" if any("obfuscator" in m["tags"] for m in matches) else "standard-static"
    return {"artifact": artifact.name, "available": True, "analyzer": {"name": "apkid-external", "version": payload.get("apkid_version")}, "rules_sha256": payload.get("rules_sha256"), "matches": matches, "recommended_route": route, "confidence": 0.95 if matches else 0.5}


def _ranges(text: str) -> list[tuple[int, int, str, str]]:
    ms, lines = _methods(text), text.splitlines()
    out = []
    for i, (start, name, params) in enumerate(ms):
        out.append((start, ms[i + 1][0] - 1 if i + 1 < len(ms) else len(lines), name, params))
    return out


def _context(ranges: list[tuple[int, int, str, str]], line: int) -> tuple[str | None, str | None]:
    for start, end, name, params in ranges:
        if start <= line <= end:
            return name, params
    return None, None


def extract_network_model(job: Path, workspace: Path, *, max_items: int = 500) -> dict[str, Any]:
    cap = max(20, min(int(max_items), 2000))
    idx = _index(job, workspace)
    by_name: dict[str, list[str]] = {}
    for m in idx.get("methods", []):
        by_name.setdefault(m.get("name", ""), []).append(m.get("id", ""))
    endpoints, urls, auth, models = [], [], [], set()
    scanned = 0
    for p in _sources(job):
        text = _text(p)
        if not text:
            continue
        scanned += 1
        rel = str(p.relative_to(job))
        pkg, cls = _source_meta(text, p)
        fqn = f"{pkg}.{cls}" if pkg else cls
        ranges = _ranges(text)
        lines = text.splitlines()
        for m in RETROFIT_RE.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            name, params = _context(ranges, line)
            if name is None:
                for start, _, cand, cp in ranges:
                    if line <= start <= line + 8:
                        name, params = cand, cp
                        break
            nearby = "\n".join(lines[max(0, line - 4):min(len(lines), line + 12)])
            for t in TYPE_RE.findall(nearby)[:10]:
                models.add(t)
            ids, callers = set(by_name.get(name or "", [])), []
            for e in idx.get("call_edges", []):
                if e.get("to") in ids and e.get("from") not in callers:
                    callers.append(e.get("from"))
                if len(callers) >= 20:
                    break
            endpoints.append({"http_method": m.group(1).upper(), "path": m.group(2), "kind": "retrofit", "declaring_class": fqn, "declaring_method": name, "parameter_signature": params, "callers": callers, "auth_signals": sorted(set(x.group(1) for x in AUTH_RE.finditer(nearby))), "evidence": {"file": rel, "line": line, "analyzer": "source+program-index", "confidence": 0.93 if idx.get("analysis_kind") == "dex-xref" else 0.75}})
            if len(endpoints) >= cap:
                break
        for m in URL_RE.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            name, _ = _context(ranges, line)
            urls.append({"url": m.group(0).rstrip(".,);]"), "declaring_class": fqn, "declaring_method": name, "evidence": {"file": rel, "line": line, "confidence": 0.9}})
            if len(urls) >= cap:
                break
        for m in AUTH_RE.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            name, _ = _context(ranges, line)
            auth.append({"signal": m.group(1), "declaring_class": fqn, "declaring_method": name, "evidence": {"file": rel, "line": line, "confidence": 0.75}})
            if len(auth) >= cap:
                break
    report = {"schema_version": 1, "job_id": job.name, "source_files_scanned": scanned, "program_index_kind": idx.get("analysis_kind"), "endpoints": endpoints[:cap], "urls": urls[:cap], "auth_evidence": auth[:cap], "candidate_models": sorted(models)[:cap], "notes": ["Caller links use DEX XREFs when Androguard is available.", "Auth evidence reports signal names/locations, not secret values.", "Model candidates remain lexical hints until dedicated data-flow analysis is added."]}
    _save(job / "network-model.json", report)
    return report
