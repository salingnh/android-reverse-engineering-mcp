#!/usr/bin/env python3
from __future__ import annotations

import re
import sqlite3
import urllib.parse
from pathlib import Path
from typing import Any

import flutter_semantic as semantic

MAX_MODEL_ITEMS = 200
MAX_URL_CANDIDATES = 5_000
MAX_PATH_CANDIDATES = 5_000
MAX_SIGNAL_CANDIDATES = 10_000
MAX_FUNCTION_CANDIDATES = 10_000
MAX_XREF_CANDIDATES = 20_000
MAX_URLS_PER_STRING = 8
MAX_ENDPOINT_TEXT = 1024
MAX_HEADER_NAME = 128

URL_RE = re.compile(r"(?i)\b(?:https?|wss?)://[^\s\"'<>]+")
SECRET_SEGMENT_RE = re.compile(
    r"(?i)^(?:"
    r"[0-9a-f]{24,}|"
    r"[A-Za-z0-9_-]{32,}={0,2}|"
    r"eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{8,})?"
    r")$"
)
SAFE_QUERY_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
PATH_HINT_RE = re.compile(
    r"(?i)^/(?:"
    r"api(?:/|$)|v\d+(?:/|$)|graphql(?:/|$)|rest(?:/|$)|"
    r"auth(?:/|$)|oauth(?:/|$)|token(?:/|$)|session(?:/|$)|"
    r"users?(?:/|$)|accounts?(?:/|$)|profiles?(?:/|$)|"
    r"orders?(?:/|$)|payments?(?:/|$)|search(?:/|$)|"
    r"upload(?:/|$)|download(?:/|$)"
    r")"
)

THIRD_PARTY_DOMAIN_SUFFIXES = (
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "firebaseio.com",
    "firebaseapp.com",
    "appspot.com",
    "facebook.com",
    "fbcdn.net",
    "stripe.com",
    "braintreegateway.com",
    "paypal.com",
    "sentry.io",
    "datadoghq.com",
    "appsflyer.com",
    "amplitude.com",
    "mixpanel.com",
    "segment.io",
    "segment.com",
    "onesignal.com",
    "intercom.io",
    "intercomcdn.com",
    "zendesk.com",
    "microsoft.com",
    "azure.com",
    "amazonaws.com",
    "cloudfront.net",
    "github.com",
    "githubusercontent.com",
    "doubleclick.net",
    "crashlytics.com",
)

HEADER_NAMES = {
    "accept": "Accept",
    "accept-encoding": "Accept-Encoding",
    "accept-language": "Accept-Language",
    "authorization": "Authorization",
    "cache-control": "Cache-Control",
    "content-type": "Content-Type",
    "cookie": "Cookie",
    "set-cookie": "Set-Cookie",
    "user-agent": "User-Agent",
    "x-api-key": "X-Api-Key",
    "api-key": "Api-Key",
    "x-auth-token": "X-Auth-Token",
    "x-csrf-token": "X-CSRF-Token",
    "x-xsrf-token": "X-XSRF-Token",
    "x-request-id": "X-Request-ID",
    "x-signature": "X-Signature",
    "x-timestamp": "X-Timestamp",
    "x-nonce": "X-Nonce",
}

AUTH_TERMS = {
    "authorization": "authorization-header",
    "bearer": "bearer-auth",
    "oauth": "oauth",
    "access_token": "access-token",
    "access-token": "access-token",
    "refresh_token": "refresh-token",
    "refresh-token": "refresh-token",
    "id_token": "id-token",
    "id-token": "id-token",
    "jwt": "jwt",
    "x-api-key": "api-key",
    "api_key": "api-key",
    "api-key": "api-key",
    "basic auth": "basic-auth",
    "session_token": "session-token",
    "session-token": "session-token",
}

SIGNING_TERMS = {
    "hmac": "hmac",
    "signature": "signature",
    "signing": "signing",
    "canonical request": "canonical-request",
    "canonical_request": "canonical-request",
    "nonce": "nonce",
    "x-signature": "signature-header",
    "x-timestamp": "timestamp-header",
    "x-nonce": "nonce-header",
    "request digest": "request-digest",
}

CRYPTO_TERMS = {
    "aes": "aes",
    "rsa": "rsa",
    "chacha20": "chacha20",
    "poly1305": "poly1305",
    "pbkdf2": "pbkdf2",
    "hkdf": "hkdf",
    "sha256": "sha256",
    "sha-256": "sha256",
    "sha512": "sha512",
    "sha-512": "sha512",
    "md5": "md5",
    "cipher": "cipher",
    "encrypt": "encrypt",
    "decrypt": "decrypt",
    "package:crypto/": "package:crypto",
    "package:cryptography/": "package:cryptography",
}

CLIENT_RULES = (
    ("dio", ("package:dio/",), ("dio",)),
    ("package:http", ("package:http/",), ("baseclient", "client", "request")),
    ("dart:io HttpClient", ("dart:io", "dart:_http"), ("httpclient",)),
    ("retrofit.dart", ("package:retrofit/",), ("restapi", "httpmethod")),
    ("chopper", ("package:chopper/",), ("chopper",)),
    ("graphql", ("package:graphql/", "package:gql/"), ("graphql",)),
    ("web_socket_channel", ("package:web_socket_channel/",), ("websocket",)),
    ("grpc", ("package:grpc/",), ("clientchannel", "clientmethod")),
)


class FlutterNetworkError(semantic.FlutterIndexError):
    pass


class _Collector:
    def __init__(self, limit: int):
        self.limit = limit
        self.items: list[dict[str, Any]] = []
        self._keys: set[tuple[Any, ...]] = set()
        self.truncated = False

    def add(self, key: tuple[Any, ...], item: dict[str, Any]) -> None:
        if key in self._keys:
            return
        self._keys.add(key)
        if len(self.items) >= self.limit:
            self.truncated = True
            return
        self.items.append(item)


def _limit(value: int) -> int:
    return max(1, min(int(value), MAX_MODEL_ITEMS))


def _is_third_party(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(
        host == suffix or host.endswith("." + suffix)
        for suffix in THIRD_PARTY_DOMAIN_SUFFIXES
    )


def _redact_path(path: str) -> str:
    if not path:
        return "/"
    parts = path.split("/")
    redacted = []
    for part in parts:
        try:
            decoded = urllib.parse.unquote(part)
        except (ValueError, UnicodeError):
            decoded = part
        if SECRET_SEGMENT_RE.fullmatch(part) or SECRET_SEGMENT_RE.fullmatch(decoded):
            redacted.append("{redacted}")
        else:
            redacted.append(part[:256])
    value = "/".join(redacted)
    if len(value) > MAX_ENDPOINT_TEXT:
        value = value[:MAX_ENDPOINT_TEXT]
    return value or "/"


def _query_keys(query: str) -> list[str]:
    keys: list[str] = []
    try:
        for key, _ in urllib.parse.parse_qsl(
            query, keep_blank_values=True, strict_parsing=False, max_num_fields=100
        ):
            clean = key[:128]
            if clean and not SAFE_QUERY_KEY_RE.fullmatch(clean):
                clean = "{redacted-key}"
            if clean and clean not in keys:
                keys.append(clean)
            if len(keys) >= 32:
                break
    except (ValueError, UnicodeError):
        return []
    return keys


def _safe_endpoint_from_url(raw_url: str) -> dict[str, Any] | None:
    raw_url = raw_url.rstrip(".,);]}")
    if len(raw_url) > MAX_ENDPOINT_TEXT * 4:
        return None
    try:
        parsed = urllib.parse.urlsplit(raw_url)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except (ValueError, UnicodeError):
        return None
    if parsed.scheme.lower() not in {"http", "https", "ws", "wss"} or not host:
        return None
    netloc = host
    if port is not None:
        netloc = f"{host}:{port}"
    path = _redact_path(parsed.path or "/")
    return {
        "scheme": parsed.scheme.lower(),
        "host": host,
        "port": port,
        "path": path,
        "query_keys": _query_keys(parsed.query),
        "sanitized_url": urllib.parse.urlunsplit(
            (parsed.scheme.lower(), netloc, path, "", "")
        ),
        "classification": (
            "known-third-party" if _is_third_party(host) else "first-party-candidate"
        ),
    }


def _safe_path_candidate(value: str) -> dict[str, Any] | None:
    text = value.strip()
    if not text.startswith("/") or len(text) > MAX_ENDPOINT_TEXT * 2:
        return None
    if any(ch in text for ch in ("\r", "\n", "\x00")):
        return None
    path, _, query = text.partition("?")
    if not PATH_HINT_RE.search(path) and path.count("/") < 2:
        return None
    return {
        "path": _redact_path(path),
        "query_keys": _query_keys(query),
        "classification": "path-candidate",
    }


def _function_context(
    conn: sqlite3.Connection,
    function_id: str | None,
    cache: dict[str, dict[str, Any] | None],
) -> dict[str, Any] | None:
    if not function_id:
        return None
    if function_id in cache:
        return cache[function_id]
    row = conn.execute(
        """SELECT id,library_url,class_name,name,signature,native_offset,
                  source_file,line
           FROM functions WHERE id=?""",
        (function_id,),
    ).fetchone()
    if row is None:
        cache[function_id] = None
        return None
    result = dict(row)
    result["native_offset_hex"] = hex(result["native_offset"])
    cache[function_id] = result
    return result


def _string_evidence(
    row: sqlite3.Row,
    function: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "source_kind": row["source_kind"],
        "source_file": row["source_file"],
        "line": row["line"],
        "function": function,
    }


def _client_name(library_url: str, class_name: str, name: str, signature: str = "") -> str | None:
    library = library_url.lower()
    text = " ".join((class_name, name, signature)).lower()
    for label, library_markers, symbol_markers in CLIENT_RULES:
        library_match = any(marker in library for marker in library_markers)
        symbol_match = any(marker in text for marker in symbol_markers)
        if not library_match:
            continue
        if label == "dart:io HttpClient":
            if symbol_match:
                return label
            continue
        # A package-specific Dart library is already strong framework evidence.
        return label
    return None


def _keyword_hits(value: str, registry: dict[str, str]) -> list[str]:
    lower = value.lower()
    hits: list[str] = []
    for term, label in registry.items():
        if len(term) <= 3 and term.isalnum():
            matched = re.search(
                rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])",
                lower,
            ) is not None
        else:
            matched = term in lower
        if matched and label not in hits:
            hits.append(label)
    return hits


def _header_name(value: str) -> str | None:
    lower = value.strip().lower()
    if not lower:
        return None
    candidate = lower.split(":", 1)[0].strip()
    if len(candidate) > MAX_HEADER_NAME:
        return None
    return HEADER_NAMES.get(candidate)


def _fetch_string_candidates(conn: sqlite3.Connection) -> tuple[list[sqlite3.Row], dict[str, Any]]:
    queries = (
        (
            "url",
            MAX_URL_CANDIDATES,
            """SELECT id,value,source_kind,source_file,line,function_id
               FROM strings
               WHERE instr(lower(value),'http://')>0
                  OR instr(lower(value),'https://')>0
                  OR instr(lower(value),'ws://')>0
                  OR instr(lower(value),'wss://')>0
               ORDER BY source_file,line,id LIMIT ?""",
        ),
        (
            "path",
            MAX_PATH_CANDIDATES,
            """SELECT id,value,source_kind,source_file,line,function_id
               FROM strings
               WHERE substr(value,1,1)='/'
               ORDER BY source_file,line,id LIMIT ?""",
        ),
        (
            "signal",
            MAX_SIGNAL_CANDIDATES,
            """SELECT id,value,source_kind,source_file,line,function_id
               FROM strings
               WHERE instr(lower(value),'authorization')>0
                  OR instr(lower(value),'bearer')>0
                  OR instr(lower(value),'oauth')>0
                  OR instr(lower(value),'token')>0
                  OR instr(lower(value),'api-key')>0
                  OR instr(lower(value),'api_key')>0
                  OR instr(lower(value),'signature')>0
                  OR instr(lower(value),'hmac')>0
                  OR instr(lower(value),'nonce')>0
                  OR instr(lower(value),'timestamp')>0
                  OR instr(lower(value),'sha')>0
                  OR instr(lower(value),'aes')>0
                  OR instr(lower(value),'rsa')>0
                  OR instr(lower(value),'chacha')>0
                  OR instr(lower(value),'poly1305')>0
                  OR instr(lower(value),'pbkdf2')>0
                  OR instr(lower(value),'hkdf')>0
                  OR instr(lower(value),'cipher')>0
                  OR instr(lower(value),'encrypt')>0
                  OR instr(lower(value),'decrypt')>0
                  OR instr(lower(value),'content-type')>0
                  OR instr(lower(value),'user-agent')>0
                  OR instr(lower(value),'cookie')>0
                  OR instr(lower(value),'accept')>0
                  OR instr(lower(value),'cache-control')>0
                  OR instr(lower(value),'x-auth-token')>0
                  OR instr(lower(value),'x-csrf-token')>0
                  OR instr(lower(value),'x-xsrf-token')>0
                  OR instr(lower(value),'x-request-id')>0
               ORDER BY source_file,line,id LIMIT ?""",
        ),
    )
    seen: set[str] = set()
    rows: list[sqlite3.Row] = []
    scan: dict[str, Any] = {}
    for name, cap, sql in queries:
        selected = conn.execute(sql, (cap + 1,)).fetchall()
        scan[f"{name}_candidate_count"] = min(len(selected), cap)
        scan[f"{name}_candidates_truncated"] = len(selected) > cap
        for row in selected[:cap]:
            if row["id"] in seen:
                continue
            seen.add(row["id"])
            rows.append(row)
    scan["unique_string_candidates"] = len(rows)
    return rows, scan


def extract_flutter_network_model(
    index_path: Path,
    limit: int = 100,
) -> dict[str, Any]:
    limit = _limit(limit)
    conn = semantic._open_db(index_path)
    try:
        meta = semantic._metadata(conn)
        hosts = _Collector(limit)
        endpoints = _Collector(limit)
        headers = _Collector(limit)
        auth = _Collector(limit)
        signing = _Collector(limit)
        crypto = _Collector(limit)
        clients = _Collector(limit)
        function_cache: dict[str, dict[str, Any] | None] = {}

        rows, scan = _fetch_string_candidates(conn)
        for row in rows:
            value = row["value"]
            function = _function_context(conn, row["function_id"], function_cache)
            evidence = _string_evidence(row, function)

            url_count = 0
            for match in URL_RE.finditer(value):
                endpoint = _safe_endpoint_from_url(match.group(0))
                if endpoint is None:
                    continue
                url_count += 1
                host_item = {
                    "host": endpoint["host"],
                    "classification": endpoint["classification"],
                    "evidence": evidence,
                }
                hosts.add(
                    (endpoint["host"], row["source_file"], row["line"], row["id"]),
                    host_item,
                )
                endpoint_item = {
                    **endpoint,
                    "evidence": evidence,
                }
                endpoints.add(
                    (
                        endpoint["scheme"],
                        endpoint["host"],
                        endpoint["port"],
                        endpoint["path"],
                        tuple(endpoint["query_keys"]),
                        row["source_file"],
                        row["line"],
                        row["id"],
                    ),
                    endpoint_item,
                )
                if url_count >= MAX_URLS_PER_STRING:
                    break

            path_candidate = _safe_path_candidate(value)
            if path_candidate is not None:
                endpoints.add(
                    (
                        "path",
                        path_candidate["path"],
                        tuple(path_candidate["query_keys"]),
                        row["source_file"],
                        row["line"],
                        row["id"],
                    ),
                    {**path_candidate, "evidence": evidence},
                )

            header = _header_name(value)
            if header is not None:
                headers.add(
                    (header.lower(), row["source_file"], row["line"], row["id"]),
                    {"name": header, "evidence": evidence},
                )

            for signal in _keyword_hits(value, AUTH_TERMS):
                auth.add(
                    (signal, row["source_file"], row["line"], row["id"]),
                    {
                        "signal": signal,
                        "evidence": evidence,
                        "secret_value_returned": False,
                    },
                )
            for signal in _keyword_hits(value, SIGNING_TERMS):
                signing.add(
                    (signal, row["source_file"], row["line"], row["id"]),
                    {
                        "signal": signal,
                        "evidence": evidence,
                        "secret_value_returned": False,
                    },
                )
            for signal in _keyword_hits(value, CRYPTO_TERMS):
                crypto.add(
                    (signal, row["source_file"], row["line"], row["id"]),
                    {
                        "signal": signal,
                        "evidence": evidence,
                        "secret_value_returned": False,
                    },
                )

        function_rows = conn.execute(
            """SELECT id,library_url,class_name,name,signature,native_offset,
                      source_file,line
               FROM functions
               WHERE instr(lower(library_url),'package:dio/')>0
                  OR instr(lower(library_url),'package:http/')>0
                  OR (
                       (instr(lower(library_url),'dart:io')>0
                        OR instr(lower(library_url),'dart:_http')>0)
                       AND (
                           instr(lower(class_name),'httpclient')>0
                           OR instr(lower(name),'httpclient')>0
                           OR instr(lower(signature),'httpclient')>0
                       )
                     )
                  OR instr(lower(library_url),'package:retrofit/')>0
                  OR instr(lower(library_url),'package:chopper/')>0
                  OR instr(lower(library_url),'package:graphql/')>0
                  OR instr(lower(library_url),'package:gql/')>0
                  OR instr(lower(library_url),'package:web_socket_channel/')>0
                  OR instr(lower(library_url),'package:grpc/')>0
               ORDER BY library_url,native_offset LIMIT ?""",
            (MAX_FUNCTION_CANDIDATES + 1,),
        ).fetchall()
        scan["function_candidates"] = min(len(function_rows), MAX_FUNCTION_CANDIDATES)
        scan["function_candidates_truncated"] = len(function_rows) > MAX_FUNCTION_CANDIDATES
        for row in function_rows[:MAX_FUNCTION_CANDIDATES]:
            client = _client_name(
                row["library_url"], row["class_name"], row["name"], row["signature"]
            )
            if client is None:
                continue
            function = dict(row)
            function["native_offset_hex"] = hex(function["native_offset"])
            clients.add(
                ("symbol", client, row["id"]),
                {
                    "client": client,
                    "evidence_kind": "library-symbol-presence",
                    "function": function,
                },
            )

        xref_rows = conn.execute(
            """SELECT x.id,x.caller_id,x.target_library_url,x.target_class_name,
                      x.target_name,x.source_file,x.line,
                      f.library_url AS caller_library_url,
                      f.class_name AS caller_class_name,
                      f.name AS caller_name,
                      f.signature AS caller_signature,
                      f.native_offset AS caller_native_offset
               FROM xrefs x
               JOIN functions f ON f.id=x.caller_id
               WHERE instr(lower(x.target_library_url),'package:dio/')>0
                  OR instr(lower(x.target_library_url),'package:http/')>0
                  OR (
                       (instr(lower(x.target_library_url),'dart:io')>0
                        OR instr(lower(x.target_library_url),'dart:_http')>0)
                       AND (
                           instr(lower(x.target_class_name),'httpclient')>0
                           OR instr(lower(x.target_name),'httpclient')>0
                       )
                     )
                  OR instr(lower(x.target_library_url),'package:retrofit/')>0
                  OR instr(lower(x.target_library_url),'package:chopper/')>0
                  OR instr(lower(x.target_library_url),'package:graphql/')>0
                  OR instr(lower(x.target_library_url),'package:gql/')>0
                  OR instr(lower(x.target_library_url),'package:web_socket_channel/')>0
                  OR instr(lower(x.target_library_url),'package:grpc/')>0
               ORDER BY x.id LIMIT ?""",
            (MAX_XREF_CANDIDATES + 1,),
        ).fetchall()
        scan["xref_candidates"] = min(len(xref_rows), MAX_XREF_CANDIDATES)
        scan["xref_candidates_truncated"] = len(xref_rows) > MAX_XREF_CANDIDATES
        for row in xref_rows[:MAX_XREF_CANDIDATES]:
            client = _client_name(
                row["target_library_url"],
                row["target_class_name"],
                row["target_name"],
            )
            if client is None:
                continue
            caller = {
                "id": row["caller_id"],
                "library_url": row["caller_library_url"],
                "class_name": row["caller_class_name"],
                "name": row["caller_name"],
                "signature": row["caller_signature"],
                "native_offset": row["caller_native_offset"],
                "native_offset_hex": hex(row["caller_native_offset"]),
            }
            clients.add(
                ("xref", client, row["caller_id"], row["id"]),
                {
                    "client": client,
                    "evidence_kind": "xref-call-adjacency",
                    "caller": caller,
                    "target": {
                        "library_url": row["target_library_url"],
                        "class_name": row["target_class_name"],
                        "name": row["target_name"],
                    },
                    "source_file": row["source_file"],
                    "line": row["line"],
                },
            )

        return {
            "status": "ok",
            "provenance": semantic._provenance(meta),
            "hosts": hosts.items,
            "hosts_truncated": hosts.truncated,
            "endpoints": endpoints.items,
            "endpoints_truncated": endpoints.truncated,
            "http_clients": clients.items,
            "http_clients_truncated": clients.truncated,
            "headers": headers.items,
            "headers_truncated": headers.truncated,
            "auth_signals": auth.items,
            "auth_signals_truncated": auth.truncated,
            "signing_signals": signing.items,
            "signing_signals_truncated": signing.truncated,
            "crypto_signals": crypto.items,
            "crypto_signals_truncated": crypto.truncated,
            "scan": scan,
            "limit_per_category": limit,
            "limitations": [
                "This is deterministic static string/symbol/XREF reconstruction, not proof of value flow.",
                "first-party-candidate means the host is not in the bundled known-third-party suffix registry; it is not proof of ownership.",
                "Auth/signing/crypto evidence returns identifiers and locations only; secret/token values are deliberately not returned.",
                "Object-pool strings without function_id cannot be attributed to an owning Dart function.",
                "Endpoints assembled dynamically from multiple values can be missed until data-flow analysis is available.",
            ],
        }
    except sqlite3.DatabaseError as exc:
        raise FlutterNetworkError("invalid Flutter semantic index") from exc
    finally:
        conn.close()
