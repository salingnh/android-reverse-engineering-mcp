#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable

INDEX_SCHEMA_VERSION = 1
MAX_ASM_FILES = 10_000
MAX_SCAN_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 32 * 1024
MAX_FUNCTIONS = 250_000
MAX_CALL_EDGES = 1_000_000
MAX_STRINGS = 300_000
MAX_STRING_LENGTH = 4096
MAX_QUERY_LIMIT = 200
MAX_QUERY_TEXT = 512

LIB_RE = re.compile(r"^// lib:\s*(.*?),\s*url:\s*(.+?)\s*$")
CLASS_META_RE = re.compile(r"^// class id:\s*(\d+),\s*size:\s*(0x[0-9a-fA-F]+)")
CLASS_RE = re.compile(r"^(?:(?:abstract\s+)?class|enum|maybe_class)\s+([^\s{;]+)")
FUNCTION_ADDR_RE = re.compile(
    r"^\s*// \*\* addr:\s*(0x[0-9a-fA-F]+),\s*size:\s*(0x[0-9a-fA-F]+)\s*$"
)
CALL_TARGET_RE = re.compile(
    r"\[(?P<library>[^\]\r\n]{1,1024})\]\s+"
    r"(?P<class>[^:\r\n]{0,256})::"
    r"(?P<name>[^\r\n;]{1,512}?)(?=(?:\s+->|\s*$))"
)
QUOTED_RE = re.compile(r'''(?P<q>["'])(?P<value>(?:\\.|(?!\1).){1,4096})(?P=q)''')


class FlutterIndexError(Exception):
    pass


def _safe_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode("utf-8", "replace")).hexdigest()
    return f"{prefix}:{digest}"


def _bounded_text(value: Any, limit: int, field: str) -> str:
    text = str(value or "").strip()
    if len(text) > limit:
        raise FlutterIndexError(f"{field} exceeds {limit} characters")
    return text


def _query_limit(value: int) -> int:
    return max(1, min(int(value), MAX_QUERY_LIMIT))


def _query_text(value: str) -> str:
    value = _bounded_text(value, MAX_QUERY_TEXT, "query")
    if not value:
        raise FlutterIndexError("query must not be empty")
    return value


def _like(value: str) -> str:
    value = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{value}%"


def _relative(root: Path, path: Path) -> str:
    root = root.resolve()
    path = path.resolve()
    if path != root and root not in path.parents:
        raise FlutterIndexError("path escapes Flutter analysis output")
    return path.relative_to(root).as_posix()


def _iter_bounded_lines(path: Path) -> Iterable[tuple[int, str]]:
    with path.open("rb") as handle:
        line_no = 0
        while True:
            raw = handle.readline(MAX_LINE_BYTES + 1)
            if not raw:
                break
            line_no += 1
            if len(raw) > MAX_LINE_BYTES and not raw.endswith(b"\n"):
                raise FlutterIndexError(
                    f"oversized line in {path.name} at line {line_no}"
                )
            yield line_no, raw.decode("utf-8", "replace").rstrip("\r\n")


def _discover_source_files(source: Path) -> tuple[list[Path], list[Path], int]:
    source = source.resolve()
    asm = (source / "asm").resolve()
    if not asm.is_dir() or source not in asm.parents:
        raise FlutterIndexError("Blutter output is missing a valid asm/ directory")

    asm_files: list[Path] = []
    scan_files: list[Path] = []
    total_bytes = 0

    for dirpath, dirnames, filenames in os.walk(asm, followlinks=False):
        base = Path(dirpath)
        dirnames[:] = [name for name in dirnames if not (base / name).is_symlink()]
        for name in filenames:
            path = base / name
            if path.is_symlink() or path.suffix != ".dart":
                continue
            if len(asm_files) >= MAX_ASM_FILES:
                raise FlutterIndexError(f"asm file count exceeds {MAX_ASM_FILES}")
            size = path.stat().st_size
            if size > MAX_FILE_BYTES:
                raise FlutterIndexError(
                    f"asm file exceeds {MAX_FILE_BYTES} bytes: {path.name}"
                )
            total_bytes += size
            if total_bytes > MAX_SCAN_BYTES:
                raise FlutterIndexError(
                    f"semantic scan exceeds {MAX_SCAN_BYTES} bytes"
                )
            asm_files.append(path)
            scan_files.append(path)

    for name in ("pp.txt", "objs.txt"):
        path = source / name
        if not path.is_file() or path.is_symlink():
            continue
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise FlutterIndexError(f"{name} exceeds {MAX_FILE_BYTES} bytes")
        total_bytes += size
        if total_bytes > MAX_SCAN_BYTES:
            raise FlutterIndexError(f"semantic scan exceeds {MAX_SCAN_BYTES} bytes")
        scan_files.append(path)

    if not asm_files:
        raise FlutterIndexError("Blutter output contains no asm/*.dart files")
    return sorted(asm_files), scan_files, total_bytes


def _function_name(signature: str) -> str:
    text = signature.strip()
    if text.endswith("{"):
        text = text[:-1].rstrip()
    for prefix in ("[closure] ", "[ffi] "):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    paren = text.find("(")
    left = text[:paren].rstrip() if paren >= 0 else text
    if not left:
        return "<unknown>"
    token = left.split()[-1]
    if "<" in token and token.endswith(">"):
        token = token[: token.find("<")]
    return token[:512] or "<unknown>"


def _open_db(index_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(index_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        PRAGMA journal_mode=DELETE;
        PRAGMA synchronous=FULL;
        CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE libraries(
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            url TEXT NOT NULL UNIQUE,
            source_file TEXT NOT NULL,
            line INTEGER NOT NULL
        );
        CREATE TABLE classes(
            id TEXT PRIMARY KEY,
            library_id TEXT NOT NULL,
            name TEXT NOT NULL,
            class_id INTEGER,
            size INTEGER,
            declaration TEXT NOT NULL,
            source_file TEXT NOT NULL,
            line INTEGER NOT NULL,
            FOREIGN KEY(library_id) REFERENCES libraries(id)
        );
        CREATE TABLE functions(
            id TEXT PRIMARY KEY,
            library_id TEXT NOT NULL,
            class_id_ref TEXT NOT NULL,
            library_url TEXT NOT NULL,
            class_name TEXT NOT NULL,
            name TEXT NOT NULL,
            signature TEXT NOT NULL,
            native_offset INTEGER NOT NULL,
            size INTEGER NOT NULL,
            source_file TEXT NOT NULL,
            line INTEGER NOT NULL,
            FOREIGN KEY(library_id) REFERENCES libraries(id),
            FOREIGN KEY(class_id_ref) REFERENCES classes(id)
        );
        CREATE TABLE calls(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            caller_id TEXT NOT NULL,
            target_library_url TEXT NOT NULL,
            target_class_name TEXT NOT NULL,
            target_name TEXT NOT NULL,
            target_id TEXT,
            source_file TEXT NOT NULL,
            line INTEGER NOT NULL,
            FOREIGN KEY(caller_id) REFERENCES functions(id)
        );
        CREATE TABLE strings(
            id TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            source_kind TEXT NOT NULL,
            source_file TEXT NOT NULL,
            line INTEGER NOT NULL,
            function_id TEXT
        );
        CREATE INDEX idx_functions_name ON functions(name);
        CREATE INDEX idx_functions_library ON functions(library_url);
        CREATE INDEX idx_functions_offset ON functions(native_offset);
        CREATE INDEX idx_calls_caller ON calls(caller_id);
        CREATE INDEX idx_calls_target ON calls(target_id);
        CREATE INDEX idx_strings_value ON strings(value);
        """
    )


def build_flutter_index(
    source_dir: Path,
    index_path: Path,
    *,
    analysis_id: str,
    artifact_sha256: str,
    blutter_commit: str,
    runtime: dict[str, Any] | None = None,
) -> dict[str, Any]:
    source = source_dir.resolve()
    index_path = index_path.resolve()
    if index_path == source or source not in index_path.parents:
        raise FlutterIndexError(
            "index must be created inside the Blutter output directory"
        )
    if index_path.exists():
        raise FlutterIndexError(
            "index already exists; use a new output or remove the stale index"
        )
    index_path.parent.mkdir(parents=True, exist_ok=True)

    analysis_id = _bounded_text(analysis_id, 256, "analysis_id")
    artifact_sha256 = _bounded_text(artifact_sha256, 64, "artifact_sha256").lower()
    blutter_commit = _bounded_text(blutter_commit, 40, "blutter_commit").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", artifact_sha256):
        raise FlutterIndexError(
            "artifact_sha256 must be 64 lowercase hexadecimal characters"
        )
    if not re.fullmatch(r"[0-9a-f]{40}", blutter_commit):
        raise FlutterIndexError("blutter_commit must be a full 40-character Git SHA")

    asm_files, scan_files, scan_bytes = _discover_source_files(source)
    counts = {
        "libraries": 0,
        "classes": 0,
        "functions": 0,
        "calls": 0,
        "strings": 0,
    }
    conn = _open_db(index_path)
    try:
        _init_db(conn)
        metadata = {
            "schema_version": INDEX_SCHEMA_VERSION,
            "analysis_id": analysis_id,
            "artifact_sha256": artifact_sha256,
            "analyzer": "blutter-semantic-index",
            "blutter_commit": blutter_commit,
            "runtime": runtime or {},
            "source_dir": ".",
            "scan_bytes": scan_bytes,
            "limits": {
                "max_asm_files": MAX_ASM_FILES,
                "max_scan_bytes": MAX_SCAN_BYTES,
                "max_line_bytes": MAX_LINE_BYTES,
                "max_functions": MAX_FUNCTIONS,
                "max_call_edges": MAX_CALL_EDGES,
                "max_strings": MAX_STRINGS,
            },
        }
        for key, value in metadata.items():
            conn.execute(
                "INSERT INTO metadata(key,value) VALUES (?,?)",
                (key, _safe_json(value) if not isinstance(value, str) else value),
            )

        seen_strings: set[str] = set()

        for path in asm_files:
            rel = _relative(source, path)
            library_id: str | None = None
            library_url = ""
            class_row_id: str | None = None
            class_name = "::"
            pending_class_meta: tuple[int, int] | None = None
            pending_signature: tuple[int, str] | None = None
            current_function_id: str | None = None

            for line_no, line in _iter_bounded_lines(path):
                lib_match = LIB_RE.match(line)
                if lib_match:
                    lib_name = lib_match.group(1)[:1024]
                    library_url = lib_match.group(2)[:2048]
                    library_id = _stable_id("dartlib", library_url)
                    conn.execute(
                        "INSERT OR IGNORE INTO libraries(id,name,url,source_file,line) VALUES (?,?,?,?,?)",
                        (library_id, lib_name, library_url, rel, line_no),
                    )
                    continue

                meta_match = CLASS_META_RE.match(line)
                if meta_match:
                    pending_class_meta = (
                        int(meta_match.group(1)),
                        int(meta_match.group(2), 16),
                    )
                    current_function_id = None
                    continue

                class_match = CLASS_RE.match(line.strip())
                if class_match and library_id:
                    raw_name = class_match.group(1)
                    class_name = raw_name.split("<", 1)[0][:512]
                    cid, size = pending_class_meta or (None, None)
                    class_row_id = _stable_id(
                        "dartclass",
                        library_url,
                        class_name,
                        str(cid if cid is not None else ""),
                    )
                    conn.execute(
                        """INSERT OR IGNORE INTO classes
                           (id,library_id,name,class_id,size,declaration,source_file,line)
                           VALUES (?,?,?,?,?,?,?,?)""",
                        (
                            class_row_id,
                            library_id,
                            class_name,
                            cid,
                            size,
                            line.strip()[:4096],
                            rel,
                            line_no,
                        ),
                    )
                    pending_class_meta = None
                    pending_signature = None
                    current_function_id = None
                    continue

                stripped = line.rstrip()
                if (
                    stripped.startswith("  ")
                    and not stripped.startswith("    ")
                    and stripped.strip().endswith("{")
                ):
                    pending_signature = (line_no, stripped.strip())
                    continue

                addr_match = FUNCTION_ADDR_RE.match(line)
                if addr_match and pending_signature and library_id and class_row_id:
                    if counts["functions"] >= MAX_FUNCTIONS:
                        raise FlutterIndexError(
                            f"function count exceeds {MAX_FUNCTIONS}"
                        )
                    sig_line, signature = pending_signature
                    address = int(addr_match.group(1), 16)
                    size = int(addr_match.group(2), 16)
                    name = _function_name(signature)
                    current_function_id = _stable_id(
                        "dartfn", library_url, class_name, name, f"{address:x}"
                    )
                    conn.execute(
                        """INSERT OR REPLACE INTO functions
                           (id,library_id,class_id_ref,library_url,class_name,name,
                            signature,native_offset,size,source_file,line)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            current_function_id,
                            library_id,
                            class_row_id,
                            library_url,
                            class_name,
                            name,
                            signature[:4096],
                            address,
                            size,
                            rel,
                            sig_line,
                        ),
                    )
                    counts["functions"] += 1
                    pending_signature = None
                    continue

                if current_function_id:
                    for match in CALL_TARGET_RE.finditer(line):
                        if counts["calls"] >= MAX_CALL_EDGES:
                            raise FlutterIndexError(
                                f"call edge count exceeds {MAX_CALL_EDGES}"
                            )
                        conn.execute(
                            """INSERT INTO calls
                               (caller_id,target_library_url,target_class_name,target_name,
                                target_id,source_file,line)
                               VALUES (?,?,?,?,NULL,?,?)""",
                            (
                                current_function_id,
                                match.group("library")[:2048],
                                match.group("class").strip()[:512],
                                match.group("name").strip()[:512],
                                rel,
                                line_no,
                            ),
                        )
                        counts["calls"] += 1

                if stripped == "  }":
                    current_function_id = None

                if counts["strings"] < MAX_STRINGS:
                    for match in QUOTED_RE.finditer(line):
                        value = match.group("value")
                        if not value or len(value) > MAX_STRING_LENGTH:
                            continue
                        key = hashlib.sha256(
                            value.encode("utf-8", "replace")
                        ).hexdigest()
                        if key in seen_strings:
                            continue
                        seen_strings.add(key)
                        conn.execute(
                            """INSERT OR IGNORE INTO strings
                               (id,value,source_kind,source_file,line,function_id)
                               VALUES (?,?,?,?,?,?)""",
                            (
                                f"str:{key}",
                                value,
                                "asm",
                                rel,
                                line_no,
                                current_function_id,
                            ),
                        )
                        counts["strings"] += 1

        counts["libraries"] = conn.execute(
            "SELECT COUNT(*) FROM libraries"
        ).fetchone()[0]
        counts["classes"] = conn.execute("SELECT COUNT(*) FROM classes").fetchone()[0]

        for path in scan_files:
            if path.suffix == ".dart":
                continue
            rel = _relative(source, path)
            for line_no, line in _iter_bounded_lines(path):
                for match in QUOTED_RE.finditer(line):
                    if counts["strings"] >= MAX_STRINGS:
                        break
                    value = match.group("value")
                    if not value or len(value) > MAX_STRING_LENGTH:
                        continue
                    key = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()
                    if key in seen_strings:
                        continue
                    seen_strings.add(key)
                    conn.execute(
                        """INSERT OR IGNORE INTO strings
                           (id,value,source_kind,source_file,line,function_id)
                           VALUES (?,?,?,?,?,NULL)""",
                        (
                            f"str:{key}",
                            value,
                            "object-pool" if path.name == "pp.txt" else "objects",
                            rel,
                            line_no,
                        ),
                    )
                    counts["strings"] += 1

        conn.execute(
            """UPDATE calls
               SET target_id = (
                 SELECT f.id FROM functions f
                 WHERE f.library_url=calls.target_library_url
                   AND f.class_name=calls.target_class_name
                   AND f.name=calls.target_name
                 ORDER BY f.native_offset LIMIT 1
               )"""
        )
        conn.execute(
            "INSERT OR REPLACE INTO metadata(key,value) VALUES ('counts',?)",
            (_safe_json(counts),),
        )
        conn.commit()
    except Exception:
        conn.close()
        index_path.unlink(missing_ok=True)
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass

    return {
        "status": "ok",
        "schema_version": INDEX_SCHEMA_VERSION,
        "index": index_path.name,
        "analysis_id": analysis_id,
        "artifact_sha256": artifact_sha256,
        "blutter_commit": blutter_commit,
        "counts": counts,
        "scan_bytes": scan_bytes,
    }


def _metadata(conn: sqlite3.Connection) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for row in conn.execute("SELECT key,value FROM metadata"):
        value: Any = row["value"]
        if row["key"] in {
            "schema_version",
            "runtime",
            "scan_bytes",
            "limits",
            "counts",
        }:
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                pass
        result[row["key"]] = value
    if result.get("schema_version") != INDEX_SCHEMA_VERSION:
        raise FlutterIndexError("unsupported Flutter semantic index schema")
    return result


def _provenance(meta: dict[str, Any]) -> dict[str, Any]:
    return {
        "analysis_id": meta.get("analysis_id"),
        "artifact_sha256": meta.get("artifact_sha256"),
        "analyzer": meta.get("analyzer"),
        "blutter_commit": meta.get("blutter_commit"),
        "runtime": meta.get("runtime"),
        "index_schema_version": INDEX_SCHEMA_VERSION,
        "evidence_state": "derived",
    }


def find_dart_symbols(
    index_path: Path, query: str, limit: int = 50
) -> dict[str, Any]:
    query = _query_text(query)
    limit = _query_limit(limit)
    conn = _open_db(index_path)
    try:
        meta = _metadata(conn)
        pattern = _like(query)
        rows = conn.execute(
            """SELECT id,library_url,class_name,name,signature,native_offset,size,
                      source_file,line
               FROM functions
               WHERE name LIKE ? ESCAPE '\\'
                  OR class_name LIKE ? ESCAPE '\\'
                  OR library_url LIKE ? ESCAPE '\\'
                  OR signature LIKE ? ESCAPE '\\'
               ORDER BY CASE
                 WHEN name=? THEN 0
                 WHEN name LIKE ? ESCAPE '\\' THEN 1
                 ELSE 2 END,
                 native_offset
               LIMIT ?""",
            (pattern, pattern, pattern, pattern, query, _like(query)[:-1], limit),
        ).fetchall()
        return {
            "status": "ok",
            "provenance": _provenance(meta),
            "results": [dict(row) for row in rows],
            "truncated": len(rows) >= limit,
            "limit": limit,
        }
    finally:
        conn.close()


def find_dart_strings(
    index_path: Path, query: str, limit: int = 50
) -> dict[str, Any]:
    query = _query_text(query)
    limit = _query_limit(limit)
    conn = _open_db(index_path)
    try:
        meta = _metadata(conn)
        rows = conn.execute(
            """SELECT id,value,source_kind,source_file,line,function_id
               FROM strings
               WHERE value LIKE ? ESCAPE '\\'
               ORDER BY length(value),source_file,line LIMIT ?""",
            (_like(query), limit),
        ).fetchall()
        return {
            "status": "ok",
            "provenance": _provenance(meta),
            "results": [dict(row) for row in rows],
            "truncated": len(rows) >= limit,
            "limit": limit,
        }
    finally:
        conn.close()


def _resolve_function(conn: sqlite3.Connection, symbol: str) -> sqlite3.Row:
    symbol = _bounded_text(symbol, 1024, "symbol")
    if not symbol:
        raise FlutterIndexError("symbol must not be empty")
    if symbol.startswith("dartfn:"):
        row = conn.execute("SELECT * FROM functions WHERE id=?", (symbol,)).fetchone()
        if not row:
            raise FlutterIndexError("Dart function id not found")
        return row
    rows = conn.execute(
        """SELECT * FROM functions
           WHERE name=? OR signature LIKE ? ESCAPE '\\'
              OR (library_url || ' ' || class_name || '::' || name)=?
           ORDER BY native_offset LIMIT 2""",
        (symbol, _like(symbol), symbol),
    ).fetchall()
    if not rows:
        raise FlutterIndexError("Dart symbol not found")
    if len(rows) > 1:
        raise FlutterIndexError("Dart symbol is ambiguous; use the function id")
    return rows[0]


def find_dart_xrefs(
    index_path: Path,
    symbol: str,
    direction: str = "both",
    limit: int = 100,
) -> dict[str, Any]:
    if direction not in {"incoming", "outgoing", "both"}:
        raise FlutterIndexError("direction must be incoming, outgoing, or both")
    limit = _query_limit(limit)
    conn = _open_db(index_path)
    try:
        meta = _metadata(conn)
        fn = _resolve_function(conn, symbol)
        result: dict[str, Any] = {
            "status": "ok",
            "provenance": _provenance(meta),
            "symbol": dict(fn),
            "direction": direction,
            "limitations": [
                "Blutter call annotations are call/XREF evidence, not proof of value flow"
            ],
        }
        if direction in {"outgoing", "both"}:
            rows = conn.execute(
                """SELECT c.target_id,c.target_library_url,c.target_class_name,
                          c.target_name,c.source_file,c.line,
                          f.native_offset AS target_native_offset
                   FROM calls c LEFT JOIN functions f ON f.id=c.target_id
                   WHERE c.caller_id=? ORDER BY c.line LIMIT ?""",
                (fn["id"], limit),
            ).fetchall()
            result["outgoing"] = [dict(row) for row in rows]
            result["outgoing_truncated"] = len(rows) >= limit
        if direction in {"incoming", "both"}:
            rows = conn.execute(
                """SELECT c.caller_id,c.source_file,c.line,
                          f.library_url AS caller_library_url,
                          f.class_name AS caller_class_name,
                          f.name AS caller_name,
                          f.native_offset AS caller_native_offset
                   FROM calls c JOIN functions f ON f.id=c.caller_id
                   WHERE c.target_id=? ORDER BY c.line LIMIT ?""",
                (fn["id"], limit),
            ).fetchall()
            result["incoming"] = [dict(row) for row in rows]
            result["incoming_truncated"] = len(rows) >= limit
        return result
    finally:
        conn.close()


def map_dart_to_native(index_path: Path, symbol: str) -> dict[str, Any]:
    conn = _open_db(index_path)
    try:
        meta = _metadata(conn)
        fn = _resolve_function(conn, symbol)
        return {
            "status": "ok",
            "provenance": _provenance(meta),
            "function": {
                "id": fn["id"],
                "library_url": fn["library_url"],
                "class_name": fn["class_name"],
                "name": fn["name"],
                "signature": fn["signature"],
                "native_offset": fn["native_offset"],
                "native_offset_hex": hex(fn["native_offset"]),
                "size": fn["size"],
                "size_hex": hex(fn["size"]),
                "source_file": fn["source_file"],
                "line": fn["line"],
            },
            "limitations": [
                "native_offset is the libapp.so-relative entry offset reported by the pinned Blutter analyzer",
                "this mapping does not by itself prove runtime reachability or value flow",
            ],
        }
    finally:
        conn.close()
