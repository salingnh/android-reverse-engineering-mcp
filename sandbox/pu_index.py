from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import tempfile
import time
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import program_understanding as legacy
from pu_source import declarations, dex_parameter_count, sources, source_meta, text

SCHEMA_VERSION = 2
BUILDER_VERSION = 4
MAX_DEX_BYTES = 512 * 1024 * 1024
MAX_DEX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 500


def artifact(job: Path, workspace: Path) -> Path:
    return legacy._artifact(job, workspace)


def db_path(job: Path) -> Path:
    return job / "program-index.sqlite3"


def connect(job: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path(job)), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    DROP TABLE IF EXISTS metadata;
    DROP TABLE IF EXISTS methods;
    DROP TABLE IF EXISTS call_edges;
    CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE methods (
      id TEXT PRIMARY KEY, class TEXT NOT NULL, name TEXT NOT NULL,
      descriptor TEXT NOT NULL, parameter_count INTEGER,
      external INTEGER NOT NULL, source_json TEXT NOT NULL
    );
    CREATE TABLE call_edges (
      caller TEXT NOT NULL, callee TEXT NOT NULL, offset INTEGER NOT NULL,
      confidence REAL NOT NULL, kind TEXT NOT NULL
    );
    CREATE INDEX idx_methods_class_name_params ON methods(class, name, parameter_count);
    CREATE INDEX idx_methods_name ON methods(name);
    CREATE INDEX idx_edges_callee ON call_edges(callee);
    CREATE INDEX idx_edges_caller ON call_edges(caller);
    """)


def meta_set(conn: sqlite3.Connection, key: str, value: Any) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO metadata(key,value) VALUES (?,?)",
        (key, json.dumps(value, ensure_ascii=False, sort_keys=True)),
    )


def meta_get(conn: sqlite3.Connection, key: str, default: Any = None) -> Any:
    row = conn.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
    return json.loads(row["value"]) if row else default


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_stat(path: Path) -> dict[str, int]:
    stat = path.stat()
    return {"size": int(stat.st_size), "mtime_ns": int(stat.st_mtime_ns)}


def _summary(job: Path, conn: sqlite3.Connection, cached: bool) -> dict[str, Any]:
    methods = conn.execute("SELECT COUNT(*) n FROM methods").fetchone()["n"]
    edges = conn.execute("SELECT COUNT(*) n FROM call_edges").fetchone()["n"]
    return {
        "job_id": job.name,
        "cached": cached,
        "analysis_kind": meta_get(conn, "analysis_kind"),
        "method_count": int(methods),
        "edge_count": int(edges),
        "truncated": meta_get(conn, "truncated", {}),
        "analyzer": meta_get(conn, "analyzer", {}),
        "fallback_reason": meta_get(conn, "fallback_reason"),
        "storage": "sqlite",
        "schema_version": SCHEMA_VERSION,
        "builder_version": BUILDER_VERSION,
    }


def _source_index(conn: sqlite3.Connection, job: Path, max_methods: int) -> dict[str, bool]:
    count = 0
    truncated = False
    for path in sources(job):
        value = text(path)
        if not value:
            continue
        package, default_class = source_meta(value, path)
        for item in declarations(value, default_class):
            if count >= max_methods:
                truncated = True
                break
            owner = item.get("class_name") or default_class
            fqn = f"{package}.{owner}" if package else owner
            conn.execute(
                "INSERT OR IGNORE INTO methods VALUES (?,?,?,?,?,?,?)",
                (
                    f"{fqn}#{item['name']}@{item['line']}",
                    fqn,
                    item["name"],
                    item["params"],
                    item["parameter_count"],
                    0,
                    json.dumps(
                        {"file": str(path.relative_to(job)), "line": item["line"]},
                        sort_keys=True,
                    ),
                ),
            )
            count += 1
        if truncated:
            break
    return {"methods": truncated, "edges": False}


def _dex_blobs(apk_path: Path) -> Iterator[bytes]:
    total = 0
    with zipfile.ZipFile(apk_path) as archive:
        infos = [
            item
            for item in archive.infolist()
            if not item.is_dir() and re.fullmatch(r"classes\d*\.dex", item.filename)
        ]
        infos.sort(key=lambda item: item.filename)
        for info in infos:
            if info.file_size > MAX_DEX_BYTES:
                raise ValueError(f"DEX exceeds size limit: {info.filename}")
            if (
                info.compress_size
                and info.file_size > 16 * 1024 * 1024
                and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO
            ):
                raise ValueError(f"DEX has suspicious compression ratio: {info.filename}")
            total += info.file_size
            if total > MAX_DEX_TOTAL_BYTES:
                raise ValueError("APK DEX payload exceeds size limit")
            yield archive.read(info)


@contextmanager
def androguard_analysis(input_artifact: Path):
    from androguard.core import dex as ag_dex  # type: ignore
    from androguard.core.analysis.analysis import Analysis  # type: ignore

    with tempfile.TemporaryDirectory(prefix="safe-pu-") as temp_dir:
        analysis = Analysis()
        class_members: dict[str, str] = {}
        dex_count = 0
        for member, apk_path in legacy._apks(input_artifact, Path(temp_dir)):
            for dex_bytes in _dex_blobs(apk_path):
                dex_count += 1
                if dex_count > 256:
                    raise ValueError("artifact contains more than 256 DEX files")
                vm = ag_dex.DEX(dex_bytes)
                analysis.add(vm)
                for clazz in vm.get_classes():
                    try:
                        class_members.setdefault(str(clazz.get_name()), member)
                    except Exception:
                        pass
        if dex_count == 0:
            raise ValueError("artifact contains no DEX code")
        analysis.create_xref()
        yield analysis, class_members


def normalize_class_descriptor(value: Any) -> str:
    class_name = str(value)
    if class_name.startswith("L") and class_name.endswith(";"):
        class_name = class_name[1:-1]
    return class_name.replace("/", ".")


def method_record(method: Any, class_members: dict[str, str]) -> dict[str, Any]:
    raw = method.get_method() if hasattr(method, "get_method") else method
    class_name = getattr(method, "class_name", None) or getattr(
        raw, "get_class_name", lambda: ""
    )()
    name = getattr(method, "name", None) or getattr(raw, "get_name", lambda: "")()
    descriptor = str(
        getattr(method, "descriptor", None)
        or getattr(raw, "get_descriptor", lambda: "")()
    )
    full_name = getattr(method, "full_name", None) or f"{class_name} {name} {descriptor}"
    return {
        "id": str(full_name),
        "class": normalize_class_descriptor(class_name),
        "name": str(name),
        "descriptor": descriptor,
        "parameter_count": dex_parameter_count(descriptor),
        "external": bool(method.is_external()) if hasattr(method, "is_external") else False,
        "source": {
            "apk_member": class_members.get(str(class_name), "external-or-unknown")
        },
    }


def _dex_index(
    conn: sqlite3.Connection,
    input_artifact: Path,
    max_methods: int,
    max_edges: int,
):
    import androguard  # type: ignore

    stored: set[str] = set()
    methods_truncated = False
    edges_truncated = False
    with androguard_analysis(input_artifact) as (analysis, class_members):
        all_methods = list(analysis.get_methods())
        all_methods.sort(
            key=lambda method: bool(method.is_external())
            if hasattr(method, "is_external")
            else False
        )
        for method in all_methods:
            record = method_record(method, class_members)
            if record["id"] in stored:
                continue
            if len(stored) >= max_methods:
                methods_truncated = True
                break
            conn.execute(
                "INSERT OR IGNORE INTO methods VALUES (?,?,?,?,?,?,?)",
                (
                    record["id"],
                    record["class"],
                    record["name"],
                    record["descriptor"],
                    record["parameter_count"],
                    1 if record["external"] else 0,
                    json.dumps(record["source"], sort_keys=True),
                ),
            )
            stored.add(record["id"])

        edge_count = 0
        for method in all_methods:
            caller = method_record(method, class_members)
            if caller["id"] not in stored:
                continue
            for _, callee, offset in (
                method.get_xref_to() if hasattr(method, "get_xref_to") else []
            ):
                if edge_count >= max_edges:
                    edges_truncated = True
                    break
                target = method_record(callee, class_members)
                conn.execute(
                    "INSERT INTO call_edges VALUES (?,?,?,?,?)",
                    (
                        caller["id"],
                        target["id"],
                        int(offset),
                        0.98,
                        "dex-xref",
                    ),
                )
                edge_count += 1
            if edges_truncated:
                break
    return (
        {"methods": methods_truncated, "edges": edges_truncated},
        {
            "name": "androguard",
            "version": getattr(androguard, "__version__", "unknown"),
        },
    )


def _backend_upgrade_needed(
    conn: sqlite3.Connection, caps: dict[str, Any]
) -> bool:
    if meta_get(conn, "analysis_kind") != "source-fallback":
        return False
    current_available = bool(caps.get("androguard"))
    built_available = bool(meta_get(conn, "androguard_available_at_build", False))
    if not built_available and current_available:
        return True
    built_version = meta_get(conn, "androguard_version_at_build")
    current_version = (caps.get("versions") or {}).get("androguard")
    return (
        current_available
        and built_available
        and bool(built_version)
        and bool(current_version)
        and built_version != current_version
    )


def _cache_ok(
    conn: sqlite3.Connection,
    input_artifact: Path,
    max_methods: int,
    max_edges: int,
    caps: dict[str, Any],
) -> bool:
    if (
        meta_get(conn, "schema_version") != SCHEMA_VERSION
        or meta_get(conn, "builder_version") != BUILDER_VERSION
    ):
        return False
    if meta_get(conn, "artifact_stat") != artifact_stat(input_artifact):
        return False
    if meta_get(conn, "artifact_sha256") != sha256(input_artifact):
        return False
    limits = meta_get(conn, "limits", {})
    truncated = meta_get(conn, "truncated", {})
    if truncated.get("methods") and int(limits.get("max_methods", 0)) < max_methods:
        return False
    if truncated.get("edges") and int(limits.get("max_edges", 0)) < max_edges:
        return False
    if _backend_upgrade_needed(conn, caps):
        return False
    return True


def build_program_index(
    job: Path,
    workspace: Path,
    caps: dict[str, Any],
    *,
    max_methods=100_000,
    max_edges=250_000,
    force=False,
):
    max_methods = max(100, min(int(max_methods), legacy.MAX_METHODS))
    max_edges = max(100, min(int(max_edges), legacy.MAX_EDGES))
    input_artifact = artifact(job, workspace)

    if db_path(job).exists() and not force:
        try:
            with connect(job) as conn:
                if _cache_ok(conn, input_artifact, max_methods, max_edges, caps):
                    return _summary(job, conn, True)
        except sqlite3.DatabaseError:
            pass

    if db_path(job).exists():
        db_path(job).unlink()

    with connect(job) as conn:
        init_db(conn)
        fallback = None
        try:
            truncated, analyzer = _dex_index(
                conn, input_artifact, max_methods, max_edges
            )
            kind = "dex-xref"
        except Exception as exc:
            conn.execute("DELETE FROM methods")
            conn.execute("DELETE FROM call_edges")
            truncated = _source_index(conn, job, max_methods)
            analyzer = {"name": "safe-source-index", "version": "4"}
            kind = "source-fallback"
            fallback = (
                f"Androguard unavailable/failed: {type(exc).__name__}: {exc}"
            )

        versions = caps.get("versions") or {}
        for key, value in {
            "schema_version": SCHEMA_VERSION,
            "builder_version": BUILDER_VERSION,
            "analysis_kind": kind,
            "analyzer": analyzer,
            "created_at_epoch": int(time.time()),
            "truncated": truncated,
            "limits": {"max_methods": max_methods, "max_edges": max_edges},
            "artifact": str(input_artifact.relative_to(workspace)),
            "artifact_stat": artifact_stat(input_artifact),
            "artifact_sha256": sha256(input_artifact),
            "androguard_available_at_build": bool(caps.get("androguard")),
            "androguard_version_at_build": versions.get("androguard"),
        }.items():
            meta_set(conn, key, value)
        if fallback:
            meta_set(conn, "fallback_reason", fallback)
        conn.commit()
        summary = _summary(job, conn, False)

    legacy._save(job / "program-index.json", summary)
    return summary


def ensure_index(job: Path, workspace: Path, caps: dict[str, Any]) -> None:
    input_artifact = artifact(job, workspace)
    if not db_path(job).exists():
        build_program_index(job, workspace, caps)
        return
    try:
        with connect(job) as conn:
            limits = meta_get(
                conn,
                "limits",
                {"max_methods": 100_000, "max_edges": 250_000},
            )
            max_methods = max(
                100,
                min(int(limits.get("max_methods", 100_000)), legacy.MAX_METHODS),
            )
            max_edges = max(
                100,
                min(int(limits.get("max_edges", 250_000)), legacy.MAX_EDGES),
            )
            valid = _cache_ok(
                conn, input_artifact, max_methods, max_edges, caps
            )
        if not valid:
            build_program_index(
                job,
                workspace,
                caps,
                max_methods=max_methods,
                max_edges=max_edges,
                force=True,
            )
    except (sqlite3.DatabaseError, ValueError, TypeError):
        build_program_index(job, workspace, caps, force=True)


def method_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "class": row["class"],
        "name": row["name"],
        "descriptor": row["descriptor"],
        "parameter_count": row["parameter_count"],
        "external": bool(row["external"]),
        "source": json.loads(row["source_json"]),
    }


def find_symbols(
    job: Path,
    workspace: Path,
    caps: dict[str, Any],
    query: str,
    *,
    limit=100,
):
    if not query or len(query) > 512:
        raise ValueError("query must be 1..512 characters")
    ensure_index(job, workspace, caps)
    with connect(job) as conn:
        rows = conn.execute(
            "SELECT * FROM methods "
            "WHERE instr(lower(class||' '||name||' '||descriptor||' '||id), ?) > 0 "
            "ORDER BY external,class,name LIMIT ?",
            (query.lower(), max(1, min(int(limit), 500))),
        ).fetchall()
        kind = meta_get(conn, "analysis_kind")
    return {
        "job_id": job.name,
        "query": query,
        "analysis_kind": kind,
        "matches": [method_row(row) for row in rows],
    }


def find_xrefs(
    job: Path,
    workspace: Path,
    caps: dict[str, Any],
    query: str,
    *,
    direction="both",
    limit=200,
):
    if not query or len(query) > 512:
        raise ValueError("query must be 1..512 characters")
    if direction not in {"incoming", "outgoing", "both"}:
        raise ValueError("invalid direction")
    ensure_index(job, workspace, caps)
    cap = max(1, min(int(limit), 1000))
    with connect(job) as conn:
        ids = [
            row["id"]
            for row in conn.execute(
                "SELECT id FROM methods "
                "WHERE instr(lower(class||' '||name||' '||descriptor||' '||id), ?) > 0 "
                "ORDER BY external LIMIT 200",
                (query.lower(),),
            )
        ]
        edges = []
        if ids:
            marks = ",".join("?" for _ in ids)
            if direction == "incoming":
                sql = f"SELECT * FROM call_edges WHERE callee IN ({marks}) LIMIT ?"
                params = [*ids, cap]
            elif direction == "outgoing":
                sql = f"SELECT * FROM call_edges WHERE caller IN ({marks}) LIMIT ?"
                params = [*ids, cap]
            else:
                sql = (
                    f"SELECT * FROM call_edges "
                    f"WHERE callee IN ({marks}) OR caller IN ({marks}) LIMIT ?"
                )
                params = [*ids, *ids, cap]
            for row in conn.execute(sql, params):
                edges.append(
                    {
                        "from": row["caller"],
                        "to": row["callee"],
                        "offset": row["offset"],
                        "confidence": row["confidence"],
                        "kind": row["kind"],
                    }
                )
        kind = meta_get(conn, "analysis_kind")
    return {
        "job_id": job.name,
        "query": query,
        "direction": direction,
        "matched_symbols": ids,
        "xrefs": edges,
        "analysis_kind": kind,
    }


def get_cfg(
    job: Path,
    workspace: Path,
    query: str,
    *,
    max_blocks=500,
):
    if not query or len(query) > 512:
        raise ValueError("query must be 1..512 characters")
    input_artifact = artifact(job, workspace)
    remaining = max(1, min(int(max_blocks), 10_000))
    needle = query.lower()
    matches = []
    with androguard_analysis(input_artifact) as (analysis, class_members):
        for method in analysis.get_methods():
            record = method_record(method, class_members)
            haystack = (
                f"{record['class']} {record['name']} "
                f"{record['descriptor']} {record['id']}"
            ).lower()
            if needle not in haystack:
                continue
            if hasattr(method, "is_external") and method.is_external():
                continue
            blocks = []
            for block in method.get_basic_blocks():
                if remaining <= 0:
                    break
                successors = []
                for child in block.get_next():
                    target = (
                        child[-1]
                        if isinstance(child, (tuple, list)) and child
                        else child
                    )
                    try:
                        successors.append(int(target.get_start()))
                    except Exception:
                        pass
                blocks.append(
                    {
                        "start": int(block.get_start()),
                        "end": int(block.get_end()),
                        "name": str(block.get_name()),
                        "successors": successors,
                    }
                )
                remaining -= 1
            matches.append(
                {
                    "method": record,
                    "blocks": blocks,
                    "truncated": remaining <= 0,
                }
            )
            if remaining <= 0 or len(matches) >= 20:
                break
    return {
        "job_id": job.name,
        "query": query,
        "matches": matches,
        "analyzer": "androguard",
        "confidence": 0.98,
        "truncated": remaining <= 0,
    }
