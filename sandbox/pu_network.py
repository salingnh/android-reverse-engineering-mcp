from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import program_understanding as legacy
import pu_ownership
from pu_index import connect, ensure_index, meta_get
from pu_source import (
    MODEL_NOISE,
    class_name_at_line,
    class_scopes,
    context,
    declaration_after,
    declarations,
    ranges,
    source_meta,
    sources,
    text,
)


def _fqn(package: str, class_name: str) -> str:
    return f"{package}.{class_name}" if package else class_name


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


def _allowed(
    classifier: pu_ownership.CodeOwnershipClassifier,
    class_name: str,
    scope: str,
) -> tuple[bool, dict[str, Any]]:
    decision = classifier.classify(class_name)
    return pu_ownership.scope_accepts(decision, scope), decision


def extract_network_model(
    job: Path,
    workspace: Path,
    caps: dict[str, Any],
    *,
    scope: str = "application",
    max_items=500,
):
    scope = pu_ownership.validate_query_scope(scope)
    cap = max(20, min(int(max_items), 2000))
    ensure_index(job, workspace, caps)
    classifier = pu_ownership.CodeOwnershipClassifier.for_job(job)
    endpoints: list[dict[str, Any]] = []
    urls: list[dict[str, Any]] = []
    auth: list[dict[str, Any]] = []
    models: set[str] = set()
    scanned = 0
    skipped_by_scope = 0
    with connect(job) as conn:
        kind = meta_get(conn, "analysis_kind")
        for path in sources(job):
            value = text(path)
            if not value:
                continue
            package, default_class = source_meta(value, path)
            scopes = class_scopes(value, default_class)
            source_classes = {
                _fqn(package, str(item.get("class_name") or ""))
                for item in scopes
                if item.get("class_name")
            }
            if not source_classes and default_class:
                source_classes.add(_fqn(package, default_class))
            if source_classes and not any(
                _allowed(classifier, class_name, scope)[0]
                for class_name in source_classes
            ):
                skipped_by_scope += 1
                continue
            scanned += 1
            relative = str(path.relative_to(job))
            items = declarations(value, default_class)
            method_ranges = ranges(items, len(value.splitlines()), scopes)
            lines = value.splitlines()

            if len(endpoints) < cap:
                for match in legacy.RETROFIT_RE.finditer(value):
                    line = value.count("\n", 0, match.start()) + 1
                    annotation_owner = class_name_at_line(scopes, line, default_class)
                    declaration = declaration_after(items, line, class_name=annotation_owner)
                    owner = declaration.get("class_name", annotation_owner) if declaration else annotation_owner
                    declaring_class = _fqn(package, owner)
                    allowed, decision = _allowed(classifier, declaring_class, scope)
                    if not allowed:
                        continue
                    nearby = "\n".join(lines[max(0, line - 3):min(len(lines), line + 12)])
                    for model in legacy.TYPE_RE.findall(nearby):
                        if model not in MODEL_NOISE and len(model) <= 128:
                            models.add(model)
                    resolution = resolve_method(
                        conn,
                        declaring_class,
                        declaration["name"] if declaration else "",
                        declaration["parameter_count"] if declaration else None,
                    )
                    resolved = resolution.get("resolved_symbol_id")
                    confidence = 0.93 if kind == "dex-xref" and resolved else 0.72 if declaration else 0.55
                    endpoints.append({
                        "http_method": match.group(1).upper(),
                        "path": match.group(2),
                        "kind": "retrofit",
                        "declaring_class": declaring_class,
                        "declaring_method": declaration["name"] if declaration else None,
                        "parameter_signature": declaration["params"] if declaration else None,
                        "parameter_count": declaration["parameter_count"] if declaration else None,
                        "symbol_resolution": resolution,
                        "callers": callers(conn, resolved) if resolved else [],
                        "auth_signals": sorted({signal.group(1) for signal in legacy.AUTH_RE.finditer(nearby)}),
                        "ownership": decision,
                        "evidence": {"file": relative, "line": line, "analyzer": "source+program-index", "confidence": confidence},
                    })
                    if len(endpoints) >= cap:
                        break

            if len(urls) < cap:
                for match in legacy.URL_RE.finditer(value):
                    line = value.count("\n", 0, match.start()) + 1
                    owner = class_name_at_line(scopes, line, default_class)
                    declaring_class = _fqn(package, owner)
                    allowed, decision = _allowed(classifier, declaring_class, scope)
                    if not allowed:
                        continue
                    declaration = context(method_ranges, line, owner)
                    urls.append({
                        "url": match.group(0).rstrip(".,);]"),
                        "declaring_class": declaring_class,
                        "declaring_method": declaration["name"] if declaration else None,
                        "ownership": decision,
                        "evidence": {"file": relative, "line": line, "confidence": 0.9},
                    })
                    if len(urls) >= cap:
                        break

            if len(auth) < cap:
                for match in legacy.AUTH_RE.finditer(value):
                    line = value.count("\n", 0, match.start()) + 1
                    owner = class_name_at_line(scopes, line, default_class)
                    declaring_class = _fqn(package, owner)
                    allowed, decision = _allowed(classifier, declaring_class, scope)
                    if not allowed:
                        continue
                    declaration = context(method_ranges, line, owner) or declaration_after(
                        items, line, 4, owner
                    )
                    auth.append({
                        "signal": match.group(1),
                        "declaring_class": declaring_class,
                        "declaring_method": declaration["name"] if declaration else None,
                        "ownership": decision,
                        "evidence": {"file": relative, "line": line, "confidence": 0.75},
                    })
                    if len(auth) >= cap:
                        break
    report = {
        "schema_version": 3,
        "job_id": job.name,
        "scope": scope,
        "source_files_scanned": scanned,
        "source_files_skipped_by_scope": skipped_by_scope,
        "program_index_kind": kind,
        "program_index_storage": "sqlite",
        "ownership_model": classifier.descriptor(),
        "endpoints": endpoints,
        "urls": urls,
        "auth_evidence": auth,
        "candidate_models": sorted(models)[:cap],
        "notes": [
            "Endpoint callers require unique class+method(+arity) resolution; ambiguous methods are never silently unioned.",
            "Source evidence is attributed to lexical top-level/nested class scopes; nested JVM names use Outer$Inner.",
            "Default application scope scans FIRST_PARTY and UNKNOWN lexical classes only; a mixed decompiler file is retained whenever at least one class is eligible.",
            "Ownership classification is evidence-based; short/obfuscated namespaces remain UNKNOWN unless stronger evidence exists.",
            "Simple-class fallback uses literal suffix matching rather than SQL wildcard matching.",
            "Cross-split XREFs use one Androguard Analysis graph when available.",
            "Auth evidence reports signal names/locations, not secret values.",
            "Model candidates remain lexical hints until data-flow analysis is added.",
        ],
    }
    legacy._save(job / "network-model.json", report)
    return report
