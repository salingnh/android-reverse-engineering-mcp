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
MAX_ASM_ENTRIES = 50_000
MAX_LIBRARIES = 10_000
MAX_CLASSES = 250_000
MAX_FUNCTIONS = 250_000
MAX_XREFS = 1_000_000
MAX_STRINGS = 300_000
MAX_SCAN_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 32 * 1024
MAX_PATH_LENGTH = 4096
MAX_STRING_LENGTH = 4096
MAX_QUERY_LIMIT = 200
MAX_QUERY_TEXT = 512

LIB_RE = re.compile(r"^// lib:\s*(.*?),\s*url:\s*(.+?)\s*$")
CLASS_META_RE = re.compile(r"^// class id:\s*(\d+),\s*size:\s*(0x[0-9a-fA-F]+)")
CLASS_RE = re.compile(r"^(?:(?:abstract\s+)?class|enum|maybe_class)\s+([^\s{;]+)")
FUNCTION_ADDR_RE = re.compile(
    r"^\s*// \*\* addr:\s*(0x[0-9a-fA-F]+),\s*size:\s*(0x[0-9a-fA-F]+)\s*$"
)
XREF_TARGET_RE = re.compile(
    r"\[(?P<library>[^\]\r\n]{1,1024})\]\s+"
    r"(?P<class>[^:\r\n]{0,256})::"
    r"(?P<name>[^\r\n;]{1,512}?)(?=(?:\s+->|\s*$))"
)
QUOTED_RE = re.compile(r'''(?P<q>["'])(?P<value>(?:\\.|(?!\1).){1,4096})(?P=q)''')


class FlutterIndexError(Exception):
    pass


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode("utf-8", "replace")).hexdigest()
    return f"{prefix}:{digest}"


def _bounded_text(value: Any, limit: int, field: str) -> str:
    text = str(value or "").strip()
    if len(text) > limit:
        raise FlutterIndexError(f"{field} exceeds {limit} characters")
    return text


def _query_text(value: str, field: str = "query") -> str:
    text = _bounded_text(value, MAX_QUERY_TEXT if field == "query" else 1024, field)
    if not text:
        raise FlutterIndexError(f"{field} must not be empty")
    return text


def _query_limit(value: int) -> int:
    return max(1, min(int(value), MAX_QUERY_LIMIT))


def _relative(root: Path, path: Path) -> str:
    root = root.resolve()
    path = path.resolve()
    if path != root and root not in path.parents:
        raise FlutterIndexError("path escapes Flutter analysis output")
    relative = path.relative_to(root).as_posix()
    if len(relative) > MAX_PATH_LENGTH:
        raise FlutterIndexError(f"source path exceeds {MAX_PATH_LENGTH} characters")
    return relative


def _iter_lines(path: Path) -> Iterable[tuple[int, str]]:
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


def _discover_files(source: Path) -> tuple[list[Path], list[Path], int]:
    source = source.resolve()
    asm_lexical = source / "asm"
    if asm_lexical.is_symlink():
        raise FlutterIndexError("asm directory must not be a symlink")
    asm = asm_lexical.resolve()
    if not asm.is_dir() or source not in asm.parents:
        raise FlutterIndexError("Blutter output is missing a valid asm/ directory")

    asm_files: list[Path] = []
    extra_files: list[Path] = []
    total_bytes = 0
    entry_count = 0

    for dirpath, dirnames, filenames in os.walk(asm, followlinks=False):
        base = Path(dirpath)
        for name in list(dirnames):
            entry_count += 1
            if entry_count > MAX_ASM_ENTRIES:
                raise FlutterIndexError(
                    f"asm directory entries exceed {MAX_ASM_ENTRIES}"
                )
            child = base / name
            if child.is_symlink():
                raise FlutterIndexError("symlinks are not allowed inside asm output")
        for name in filenames:
            entry_count += 1
            if entry_count > MAX_ASM_ENTRIES:
                raise FlutterIndexError(
                    f"asm directory entries exceed {MAX_ASM_ENTRIES}"
                )
            path = base / name
            if path.is_symlink():
                raise FlutterIndexError("symlinks are not allowed inside asm output")
            if path.suffix != ".dart":
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
                raise FlutterIndexError(f"semantic scan exceeds {MAX_SCAN_BYTES} bytes")
            asm_files.append(path)

    for name in ("pp.txt", "objs.txt"):
        path = source / name
        if path.is_symlink():
            raise FlutterIndexError(f"{name} must not be a symlink")
        if not path.is_file():
            continue
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise FlutterIndexError(f"{name} exceeds {MAX_FILE_BYTES} bytes")
        total_bytes += size
        if total_bytes > MAX_SCAN_BYTES:
            raise FlutterIndexError(f"semantic scan exceeds {MAX_SCAN_BYTES} bytes")
        extra_files.append(path)

    if not asm_files:
        raise FlutterIndexError("Blutter output contains no asm/*.dart files")
    return sorted(asm_files), extra_files, total_bytes


def _function_name(signature: str) -> str:
    text = signature.strip()
    if text.endswith("{"):
        text = text[:-1].rstrip()
    for prefix in ("[closure] ", "[ffi] "):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    paren = text.find("(")
    left = text[:paren].rstrip() if paren >= 0 else text
    if "<anonymous closure>" in left:
        return "<anonymous closure>"
    if not left:
        return "<unknown>"
    token = left.split()[-1]
    if "<" in token and token.endswith(">"):
        token = token[: token.find("<")]
    return token[:512] or "<unknown>"


def _open_db(index_path: Path, *, writable: bool = False) -> sqlite3.Connection:
    index_path = index_path.resolve()
    if writable:
        conn = sqlite3.connect(str(index_path))
    else:
        if not index_path.is_file():
            raise FlutterIndexError("Flutter semantic index does not exist")
        conn = sqlite3.connect(index_path.as_uri() + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    if not writable:
        conn.execute("PRAGMA query_only=ON")
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
        CREATE TABLE xrefs(
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
        CREATE INDEX idx_functions_fullname
            ON functions(library_url,class_name,name);
        CREATE INDEX idx_xrefs_caller ON xrefs(caller_id);
        CREATE INDEX idx_xrefs_target ON xrefs(target_id);
        CREATE INDEX idx_strings_value ON strings(value);
        """
    )


def _insert_string(
    conn: sqlite3.Connection,
    *,
    value: str,
    source_kind: str,
    source_file: str,
    line: int,
    function_id: str | None,
    count: int,
) -> int:
    if count >= MAX_STRINGS or not value or len(value) > MAX_STRING_LENGTH:
        return count
    sid = _stable_id(
        "str",
        value,
        source_kind,
        source_file,
        str(line),
        function_id or "",
    )
    conn.execute(
        """INSERT OR IGNORE INTO strings
           (id,value,source_kind,source_file,line,function_id)
           VALUES (?,?,?,?,?,?)""",
        (sid, value, source_kind, source_file, line, function_id),
    )
    return count + int(conn.execute("SELECT changes()").fetchone()[0] > 0)


def build_flutter_index(
    source_dir: Path,
    index_path: Path,
    *,
    analysis_id: str,
    artifact_sha256: str,
    blutter_commit: str,
    runtime: dict[str, Any] | None = None,
    image_version: str | None = None,
    build_commit: str | None = None,
) -> dict[str, Any]:
    source = source_dir.resolve()
    index_path = index_path.resolve()
    if index_path == source or source not in index_path.parents:
        raise FlutterIndexError(
            "index must be created inside the Blutter output directory"
        )
    if index_path.exists():
        raise FlutterIndexError(
            "index already exists; use a fresh analysis output or remove the stale index"
        )
    index_path.parent.mkdir(parents=True, exist_ok=True)

    analysis_id = _bounded_text(analysis_id, 256, "analysis_id")
    artifact_sha256 = _bounded_text(artifact_sha256, 64, "artifact_sha256").lower()
    blutter_commit = _bounded_text(blutter_commit, 40, "blutter_commit").lower()
    image_version = _bounded_text(image_version, 128, "image_version") if image_version else None
    build_commit = _bounded_text(build_commit, 128, "build_commit") if build_commit else None
    if not re.fullmatch(r"[0-9a-f]{64}", artifact_sha256):
        raise FlutterIndexError(
            "artifact_sha256 must be 64 lowercase hexadecimal characters"
        )
    if not re.fullmatch(r"[0-9a-f]{40}", blutter_commit):
        raise FlutterIndexError("blutter_commit must be a full 40-character Git SHA")

    asm_files, extra_files, scan_bytes = _discover_files(source)
    counts = {
        "libraries": 0,
        "classes": 0,
        "functions": 0,
        "xrefs": 0,
        "strings": 0,
    }
    conn = _open_db(index_path, writable=True)
    try:
        _init_db(conn)
        metadata = {
            "schema_version": INDEX_SCHEMA_VERSION,
            "analysis_id": analysis_id,
            "artifact_sha256": artifact_sha256,
            "artifact_kind": "libapp.so",
            "analyzer": "blutter-semantic-index",
            "blutter_commit": blutter_commit,
            "runtime": runtime or {},
            "image_version": image_version,
            "build_commit": build_commit,
            "scan_bytes": scan_bytes,
            "limits": {
                "max_asm_files": MAX_ASM_FILES,
                "max_asm_entries": MAX_ASM_ENTRIES,
                "max_libraries": MAX_LIBRARIES,
                "max_classes": MAX_CLASSES,
                "max_functions": MAX_FUNCTIONS,
                "max_xrefs": MAX_XREFS,
                "max_strings": MAX_STRINGS,
                "max_scan_bytes": MAX_SCAN_BYTES,
                "max_line_bytes": MAX_LINE_BYTES,
                "max_path_length": MAX_PATH_LENGTH,
            },
        }
        for key, value in metadata.items():
            conn.execute(
                "INSERT INTO metadata(key,value) VALUES (?,?)",
                (key, _json(value) if not isinstance(value, str) else value),
            )

        for path in asm_files:
            rel = _relative(source, path)
            library_id: str | None = None
            library_url = ""
            class_row_id: str | None = None
            class_name = ""
            pending_class_meta: tuple[int, int] | None = None
            pending_signature: tuple[int, str] | None = None
            current_function_id: str | None = None

            for line_no, line in _iter_lines(path):
                lib_match = LIB_RE.match(line)
                if lib_match:
                    library_url = lib_match.group(2)[:2048]
                    library_id = _stable_id("dartlib", library_url)
                    conn.execute(
                        "INSERT OR IGNORE INTO libraries(id,name,url,source_file,line) VALUES (?,?,?,?,?)",
                        (
                            library_id,
                            lib_match.group(1)[:1024],
                            library_url,
                            rel,
                            line_no,
                        ),
                    )
                    if conn.execute("SELECT changes()").fetchone()[0]:
                        counts["libraries"] += 1
                        if counts["libraries"] > MAX_LIBRARIES:
                            raise FlutterIndexError(
                                f"library count exceeds {MAX_LIBRARIES}"
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
                    class_name = "" if raw_name == "::" else raw_name.split("<", 1)[0][:512]
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
                    if conn.execute("SELECT changes()").fetchone()[0]:
                        counts["classes"] += 1
                        if counts["classes"] > MAX_CLASSES:
                            raise FlutterIndexError(
                                f"class count exceeds {MAX_CLASSES}"
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
                        """INSERT OR IGNORE INTO functions
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
                    if conn.execute("SELECT changes()").fetchone()[0]:
                        counts["functions"] += 1
                    pending_signature = None
                    continue

                if current_function_id:
                    for match in XREF_TARGET_RE.finditer(line):
                        if counts["xrefs"] >= MAX_XREFS:
                            raise FlutterIndexError(f"XREF count exceeds {MAX_XREFS}")
                        conn.execute(
                            """INSERT INTO xrefs
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
                        counts["xrefs"] += 1

                for match in QUOTED_RE.finditer(line):
                    counts["strings"] = _insert_string(
                        conn,
                        value=match.group("value"),
                        source_kind="asm",
                        source_file=rel,
                        line=line_no,
                        function_id=current_function_id,
                        count=counts["strings"],
                    )
                    if counts["strings"] >= MAX_STRINGS:
                        break

                if stripped == "  }":
                    current_function_id = None

        for path in extra_files:
            rel = _relative(source, path)
            source_kind = "object-pool" if path.name == "pp.txt" else "objects"
            for line_no, line in _iter_lines(path):
                for match in QUOTED_RE.finditer(line):
                    counts["strings"] = _insert_string(
                        conn,
                        value=match.group("value"),
                        source_kind=source_kind,
                        source_file=rel,
                        line=line_no,
                        function_id=None,
                        count=counts["strings"],
                    )
                    if counts["strings"] >= MAX_STRINGS:
                        break

        # Blutter annotations provide library/class/function names but not a
        # complete Dart signature. Resolve only a unique identity. Ambiguous
        # overloads intentionally remain unresolved rather than inventing an edge.
        conn.execute(
            """UPDATE xrefs
               SET target_id = (
                 SELECT CASE WHEN COUNT(*)=1 THEN MIN(f.id) ELSE NULL END
                 FROM functions f
                 WHERE f.library_url=xrefs.target_library_url
                   AND f.class_name=xrefs.target_class_name
                   AND f.name=xrefs.target_name
               )"""
        )
        conn.execute(
            "INSERT OR REPLACE INTO metadata(key,value) VALUES ('counts',?)",
            (_json(counts),),
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
    try:
        rows = conn.execute("SELECT key,value FROM metadata").fetchall()
    except sqlite3.DatabaseError as exc:
        raise FlutterIndexError("invalid Flutter semantic index") from exc
    result: dict[str, Any] = {}
    for row in rows:
        value: Any = row["value"]
        if row["key"] in {
            "schema_version",
            "runtime",
            "image_version",
            "build_commit",
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
        "artifact_kind": meta.get("artifact_kind"),
        "analyzer": meta.get("analyzer"),
        "blutter_commit": meta.get("blutter_commit"),
        "runtime": meta.get("runtime"),
        "image_version": meta.get("image_version"),
        "build_commit": meta.get("build_commit"),
        "index_schema_version": INDEX_SCHEMA_VERSION,
        "evidence_state": "derived",
    }


def _rows_with_truncation(rows: list[sqlite3.Row], limit: int) -> tuple[list[dict], bool]:
    truncated = len(rows) > limit
    return [dict(row) for row in rows[:limit]], truncated


def find_dart_symbols(
    index_path: Path, query: str, limit: int = 50
) -> dict[str, Any]:
    query = _query_text(query)
    limit = _query_limit(limit)
    conn = _open_db(index_path)
    try:
        meta = _metadata(conn)
        rows = conn.execute(
            """SELECT id,library_url,class_name,name,signature,native_offset,size,
                      source_file,line
               FROM functions
               WHERE instr(name,?)>0
                  OR instr(class_name,?)>0
                  OR instr(library_url,?)>0
                  OR instr(signature,?)>0
               ORDER BY CASE
                 WHEN name=? THEN 0
                 WHEN substr(name,1,length(?))=? THEN 1
                 ELSE 2 END,
                 native_offset
               LIMIT ?""",
            (query, query, query, query, query, query, query, limit + 1),
        ).fetchall()
        results, truncated = _rows_with_truncation(rows, limit)
        return {
            "status": "ok",
            "provenance": _provenance(meta),
            "results": results,
            "truncated": truncated,
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
               WHERE instr(value,?)>0
               ORDER BY length(value),source_file,line LIMIT ?""",
            (query, limit + 1),
        ).fetchall()
        results, truncated = _rows_with_truncation(rows, limit)
        return {
            "status": "ok",
            "provenance": _provenance(meta),
            "results": results,
            "truncated": truncated,
            "limit": limit,
        }
    finally:
        conn.close()


def _resolve_function(conn: sqlite3.Connection, symbol: str) -> sqlite3.Row:
    symbol = _query_text(symbol, "symbol")
    if symbol.startswith("dartfn:"):
        row = conn.execute("SELECT * FROM functions WHERE id=?", (symbol,)).fetchone()
        if not row:
            raise FlutterIndexError("Dart function id not found")
        return row
    rows = conn.execute(
        """SELECT * FROM functions
           WHERE name=?
              OR instr(signature,?)>0
              OR (library_url || ' ' || class_name || '::' || name)=?
           ORDER BY native_offset LIMIT 2""",
        (symbol, symbol, symbol),
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
                "Blutter annotations are XREF/call-adjacency evidence, not proof of value flow",
                "overloaded targets remain unresolved unless the annotation identifies a unique function",
            ],
        }
        if direction in {"outgoing", "both"}:
            rows = conn.execute(
                """SELECT x.target_id,x.target_library_url,x.target_class_name,
                          x.target_name,x.source_file,x.line,
                          f.native_offset AS target_native_offset
                   FROM xrefs x LEFT JOIN functions f ON f.id=x.target_id
                   WHERE x.caller_id=? ORDER BY x.line LIMIT ?""",
                (fn["id"], limit + 1),
            ).fetchall()
            result["outgoing"], result["outgoing_truncated"] = _rows_with_truncation(
                rows, limit
            )
        if direction in {"incoming", "both"}:
            rows = conn.execute(
                """SELECT x.caller_id,x.source_file,x.line,
                          f.library_url AS caller_library_url,
                          f.class_name AS caller_class_name,
                          f.name AS caller_name,
                          f.native_offset AS caller_native_offset
                   FROM xrefs x JOIN functions f ON f.id=x.caller_id
                   WHERE x.target_id=? ORDER BY x.line LIMIT ?""",
                (fn["id"], limit + 1),
            ).fetchall()
            result["incoming"], result["incoming_truncated"] = _rows_with_truncation(
                rows, limit
            )
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
