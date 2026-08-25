from __future__ import annotations

import re
import urllib.parse
from pathlib import Path
from typing import Any

import program_understanding as legacy
import pu_ownership
from pu_source import class_scopes, source_meta, sources, text

PATH_LITERAL_RE = re.compile(
    r"[\"']((?:/[A-Za-z0-9_{}.-]+){2,}/?|(?:api|v\d+|graphql|rest|auth|oauth|users?|account|session|token|profile|order|payment|search|upload|download)(?:/[A-Za-z0-9_{}.-]+)+/?)[\"']",
    re.I,
)
THIRD_PARTY_DOMAINS = {
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
    "hotjar.com",
    "microsoft.com",
    "azure.com",
    "amazonaws.com",
    "cloudfront.net",
    "github.com",
    "githubusercontent.com",
    "googlesyndication.com",
    "doubleclick.net",
    "crashlytics.com",
}
SIGNAL_PATTERNS = {
    "ktor": re.compile(
        r"\b(?:client|httpclient)\.(?:get|post|put|delete|patch|request)\s*[<(]",
        re.I,
    ),
    "apollo": re.compile(r"ApolloClient|\.serverUrl\("),
    "okhttp": re.compile(r"Request\.Builder|\.newCall\("),
    "volley": re.compile(r"StringRequest|JsonObjectRequest"),
    "bearer": re.compile(r"\bbearer\b", re.I),
    "hmac": re.compile(r"hmacsha|mac\.getinstance\(\s*\"hmac", re.I),
    "api_key_identifiers": re.compile(
        r"\b(?:api[_-]?key|client[_-]?secret|access[_-]?token)\b",
        re.I,
    ),
}


def _is_third_party_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == domain or host.endswith("." + domain) for domain in THIRD_PARTY_DOMAINS)


def _fqn(package: str, class_name: str) -> str:
    return f"{package}.{class_name}" if package else class_name


def _class_name_at_position(
    scopes: list[dict[str, Any]],
    position: int,
    default_class: str,
) -> str:
    matches = [
        item
        for item in scopes
        if int(item["start_pos"]) <= position <= int(item["end_pos"])
    ]
    if not matches:
        return default_class
    return max(matches, key=lambda item: int(item["start_pos"]))["class_name"]


def _class_names(scopes: list[dict[str, Any]], default_class: str) -> list[str]:
    names = {str(item.get("class_name") or "") for item in scopes}
    names.discard("")
    if not names and default_class:
        names.add(default_class)
    return sorted(names)


def extract_api(
    job: Path,
    *,
    scope: str = "application",
    max_items: int = 500,
) -> dict[str, Any]:
    scope = pu_ownership.validate_query_scope(scope)
    cap = max(20, min(int(max_items), 2000))
    classifier = pu_ownership.CodeOwnershipClassifier.for_job(job)
    urls: dict[str, dict[str, Any]] = {}
    endpoints: dict[tuple[str, str], dict[str, Any]] = {}
    paths: dict[str, dict[str, Any]] = {}
    signals = {key: 0 for key in SIGNAL_PATTERNS}
    scanned = 0
    skipped_by_scope = 0
    evidence_skipped_by_scope = 0

    for file in sources(job):
        value = text(file)
        if not value:
            continue
        package, default_class = source_meta(value, file)
        scopes = class_scopes(value, default_class)
        decision_cache: dict[str, dict[str, Any]] = {}

        def decision_for(class_name: str) -> tuple[str, dict[str, Any]]:
            declaring_class = _fqn(package, class_name)
            decision = decision_cache.get(declaring_class)
            if decision is None:
                decision = classifier.classify(declaring_class)
                decision_cache[declaring_class] = decision
            return declaring_class, decision

        source_classes = _class_names(scopes, default_class)
        if source_classes and not any(
            pu_ownership.scope_accepts(decision_for(name)[1], scope)
            for name in source_classes
        ):
            skipped_by_scope += 1
            continue

        scanned += 1
        relative = str(file.relative_to(job))

        def evidence_ownership(position: int) -> tuple[str, dict[str, Any]] | None:
            nonlocal evidence_skipped_by_scope
            class_name = _class_name_at_position(scopes, position, default_class)
            declaring_class, decision = decision_for(class_name)
            if not pu_ownership.scope_accepts(decision, scope):
                evidence_skipped_by_scope += 1
                return None
            return declaring_class, decision

        for match in legacy.URL_RE.finditer(value):
            owned = evidence_ownership(match.start())
            if owned is None:
                continue
            declaring_class, ownership = owned
            url = match.group(0).rstrip(".,);]")
            try:
                parsed = urllib.parse.urlparse(url)
                host = (parsed.hostname or "").lower()
            except ValueError:
                continue
            if host and url not in urls and len(urls) < cap:
                urls[url] = {
                    "url": url,
                    "host": host,
                    "host_classification": (
                        "third-party" if _is_third_party_host(host) else "first-party-candidate"
                    ),
                    "declaring_class": declaring_class,
                    "ownership": ownership,
                    "source": relative,
                }

        for match in legacy.RETROFIT_RE.finditer(value):
            owned = evidence_ownership(match.start())
            if owned is None:
                continue
            declaring_class, ownership = owned
            key = (match.group(1).upper(), match.group(2))
            if key not in endpoints and len(endpoints) < cap:
                endpoints[key] = {
                    "method": key[0],
                    "path": key[1],
                    "declaring_class": declaring_class,
                    "ownership": ownership,
                    "source": relative,
                    "kind": "retrofit",
                }

        for match in PATH_LITERAL_RE.finditer(value):
            owned = evidence_ownership(match.start())
            if owned is None:
                continue
            declaring_class, ownership = owned
            path = match.group(1)
            if path not in paths and len(paths) < cap:
                paths[path] = {
                    "path": path,
                    "declaring_class": declaring_class,
                    "ownership": ownership,
                    "source": relative,
                }

        for signal, pattern in SIGNAL_PATTERNS.items():
            for match in pattern.finditer(value):
                if evidence_ownership(match.start()) is not None:
                    signals[signal] += 1

    report = {
        "job_id": job.name,
        "scope": scope,
        "source_files_scanned": scanned,
        "source_files_skipped_by_scope": skipped_by_scope,
        "evidence_items_skipped_by_scope": evidence_skipped_by_scope,
        "ownership_model": classifier.descriptor(),
        "urls": list(urls.values()),
        "retrofit_endpoints": list(endpoints.values()),
        "endpoint_path_literals": list(paths.values()),
        "signals": signals,
        "notes": [
            "Default application scope scans FIRST_PARTY and UNKNOWN lexical classes only; explicit scope expansion is required for definite SDK/platform/generated internals.",
            "Multi-class decompiler files are filtered per lexical owning class, so a generated or SDK class cannot hide an eligible application class in the same source file.",
            "URL host classification is independent from code ownership and treats apex/subdomains of known service domains as third-party network destinations.",
            "Auth scanning reports identifiers/counts only; it does not intentionally return secret values.",
            "This shallow API inventory is lexical evidence; use extract_network_model for symbol/XREF linkage and later data-flow stages for proven value propagation.",
        ],
    }
    legacy._save(job / "api-report.json", report)
    return report
