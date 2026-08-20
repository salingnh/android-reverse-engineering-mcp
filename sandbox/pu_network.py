from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import program_understanding as legacy
from pu_index import connect, ensure_index, meta_get
from pu_source import MODEL_NOISE, context, declaration_after, declarations, ranges, source_meta, sources, text


def resolve_method(conn: sqlite3.Connection, class_name: str, method_name: str, arity: int | None) -> dict[str, Any]:
    if not method_name:
        return {"status": "unresolved", "resolved_symbol_id": None, "candidates": []}

    def fetch(expr: str, values: tuple[Any, ...], use_arity: bool) -> list[str]:
        if use_arity and arity is not None:
            rows = conn.execute(
                f"SELECT id FROM methods WHERE {expr} AND name=? AND parameter_count=? ORDER BY external LIMIT 25",
                (*values, method_name, arity),
            ).fetchall()
        else:
            rows = conn.execute(
                f"SELECT id FROM methods WHERE {expr} AND name=? ORDER BY external LIMIT 25",
                (*values, method_name),
            ).fetchall()
        return [row["id"] for row in rows]

    candidates = fetch("class=?", (class_name,), True)
    strategy = "class+method+arity"
    if not candidates:
        candidates = fetch("class=?", (class_name,), False)
        strategy = "class+method"
    if not candidates:
        simple = class_name.rsplit(".", 1)[-1]
        suffix_expr = "(class=? OR substr(class, -(length(?) + 1)) = '.' || ?)"
        candidates = fetch(suffix_expr, (simple, simple, simple), True)
        strategy = "simple-class+method+arity"
    if not candidates:
        simple = class_name.rsplit(".", 1)[-1]
        suffix_expr = "(class=? OR substr(class, -(length(?) + 1)) = '.' || ?)"
        candidates = fetch(suffix_expr, (simple, simple, simple), False)
        strategy = "simple-class+method"
    if len(candidates) == 1:
        return {"status": "resolved", "strategy": strategy, "resolved_symbol_id": candidates[0], "candidates": candidates}
    if candidates:
        return {"status": "ambiguous", "strategy": strategy, "resolved_symbol_id": None, "candidates": candidates}
    return {"status": "unresolved", "strategy": strategy, "resolved_symbol_id": None, "candidates": []}


def callers(conn: sqlite3.Connection, callee: str, limit=20) -> list[str]:
    return [row["caller"] for row in conn.execute(
        "SELECT DISTINCT caller FROM call_edges WHERE callee=? ORDER BY caller LIMIT ?",
        (callee, limit),
    )]


def extract_network_model(job: Path, workspace: Path, caps: dict[str, Any], *, max_items=500):
    cap = max(20, min(int(max_items), 2000))
    ensure_index(job, workspace, caps)
    endpoints: list[dict[str, Any]] = []
    urls: list[dict[str, Any]] = []
    auth: list[dict[str, Any]] = []
    models: set[str] = set()
    scanned = 0
    with connect(job) as conn:
        kind = meta_get(conn, "analysis_kind")
        for path in sources(job):
            value = text(path)
            if not value:
                continue
            scanned += 1
            relative = str(path.relative_to(job))
            package, clazz = source_meta(value, path)
            fqn = f"{package}.{clazz}" if package else clazz
            items = declarations(value, clazz)
            method_ranges = ranges(items, len(value.splitlines()))
            lines = value.splitlines()

            if len(endpoints) < cap:
                for match in legacy.RETROFIT_RE.finditer(value):
                    line = value.count("\n", 0, match.start()) + 1
                    declaration = declaration_after(items, line)
                    nearby = "\n".join(lines[max(0, line - 3):min(len(lines), line + 12)])
                    for model in legacy.TYPE_RE.findall(nearby):
                        if model not in MODEL_NOISE and len(model) <= 128:
                            models.add(model)
                    resolution = resolve_method(
                        conn, fqn,
                        declaration["name"] if declaration else "",
                        declaration["parameter_count"] if declaration else None,
                    )
                    resolved = resolution.get("resolved_symbol_id")
                    confidence = 0.93 if kind == "dex-xref" and resolved else 0.72 if declaration else 0.55
                    endpoints.append({
                        "http_method": match.group(1).upper(),
                        "path": match.group(2),
                        "kind": "retrofit",
                        "declaring_class": fqn,
                        "declaring_method": declaration["name"] if declaration else None,
                        "parameter_signature": declaration["params"] if declaration else None,
                        "parameter_count": declaration["parameter_count"] if declaration else None,
                        "symbol_resolution": resolution,
                        "callers": callers(conn, resolved) if resolved else [],
                        "auth_signals": sorted({signal.group(1) for signal in legacy.AUTH_RE.finditer(nearby)}),
                        "evidence": {"file": relative, "line": line, "analyzer": "source+program-index", "confidence": confidence},
                    })
                    if len(endpoints) >= cap:
                        break

            if len(urls) < cap:
                for match in legacy.URL_RE.finditer(value):
                    line = value.count("\n", 0, match.start()) + 1
                    declaration = context(method_ranges, line)
                    urls.append({
                        "url": match.group(0).rstrip(".,);]"),
                        "declaring_class": fqn,
                        "declaring_method": declaration["name"] if declaration else None,
                        "evidence": {"file": relative, "line": line, "confidence": 0.9},
                    })
                    if len(urls) >= cap:
                        break

            if len(auth) < cap:
                for match in legacy.AUTH_RE.finditer(value):
                    line = value.count("\n", 0, match.start()) + 1
                    declaration = context(method_ranges, line) or declaration_after(items, line, 4)
                    auth.append({
                        "signal": match.group(1),
                        "declaring_class": fqn,
                        "declaring_method": declaration["name"] if declaration else None,
                        "evidence": {"file": relative, "line": line, "confidence": 0.75},
                    })
                    if len(auth) >= cap:
                        break
    report = {
        "schema_version": 2,
        "job_id": job.name,
        "source_files_scanned": scanned,
        "program_index_kind": kind,
        "program_index_storage": "sqlite",
        "endpoints": endpoints,
        "urls": urls,
        "auth_evidence": auth,
        "candidate_models": sorted(models)[:cap],
        "notes": [
            "Endpoint callers require unique class+method(+arity) resolution; ambiguous methods are never silently unioned.",
            "Simple-class fallback uses literal suffix matching rather than SQL wildcard matching.",
            "Cross-split XREFs use one Androguard Analysis graph when available.",
            "Auth evidence reports signal names/locations, not secret values.",
            "Model candidates remain lexical hints until data-flow analysis is added.",
        ],
    }
    legacy._save(job / "network-model.json", report)
    return report
