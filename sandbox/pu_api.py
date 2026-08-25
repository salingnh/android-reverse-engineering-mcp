from __future__ import annotations

import re
import urllib.parse
from pathlib import Path
from typing import Any

import program_understanding as legacy
import pu_ownership
from pu_source import source_meta, sources, text

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


def _is_third_party_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == domain or host.endswith("." + domain) for domain in THIRD_PARTY_DOMAINS)


def _fqn(package: str, class_name: str) -> str:
    return f"{package}.{class_name}" if package else class_name


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
    signals = {
        "ktor": 0,
        "apollo": 0,
        "okhttp": 0,
        "volley": 0,
        "bearer": 0,
        "hmac": 0,
        "api_key_identifiers": 0,
    }
    scanned = 0
    skipped_by_scope = 0

    for file in sources(job):
        value = text(file)
        if not value:
            continue
        package, default_class = source_meta(value, file)
        declaring_class = _fqn(package, default_class)
        ownership = classifier.classify(declaring_class)
        if not pu_ownership.scope_accepts(ownership, scope):
            skipped_by_scope += 1
            continue
        scanned += 1
        relative = str(file.relative_to(job))

        for match in legacy.URL_RE.finditer(value):
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
            path = match.group(1)
            if path not in paths and len(paths) < cap:
                paths[path] = {
                    "path": path,
                    "declaring_class": declaring_class,
                    "ownership": ownership,
                    "source": relative,
                }

        low = value.lower()
        signals["ktor"] += len(
            re.findall(
                r"\b(?:client|httpclient)\.(?:get|post|put|delete|patch|request)\s*[<(]",
                low,
            )
        )
        signals["apollo"] += value.count("ApolloClient") + value.count(".serverUrl(")
        signals["okhttp"] += value.count("Request.Builder") + value.count(".newCall(")
        signals["volley"] += value.count("StringRequest") + value.count("JsonObjectRequest")
        signals["bearer"] += len(re.findall(r"\bbearer\b", low))
        signals["hmac"] += len(re.findall(r"hmacsha|mac\.getinstance\(\s*\"hmac", low))
        signals["api_key_identifiers"] += len(
            re.findall(r"\b(?:api[_-]?key|client[_-]?secret|access[_-]?token)\b", low)
        )

    report = {
        "job_id": job.name,
        "scope": scope,
        "source_files_scanned": scanned,
        "source_files_skipped_by_scope": skipped_by_scope,
        "ownership_model": classifier.descriptor(),
        "urls": list(urls.values()),
        "retrofit_endpoints": list(endpoints.values()),
        "endpoint_path_literals": list(paths.values()),
        "signals": signals,
        "notes": [
            "Default application scope scans FIRST_PARTY and UNKNOWN source only; explicit scope expansion is required for definite SDK/platform/generated internals.",
            "URL host classification is independent from code ownership and treats apex/subdomains of known service domains as third-party network destinations.",
            "Auth scanning reports identifiers/counts only; it does not intentionally return secret values.",
            "This shallow API inventory is lexical evidence; use extract_network_model for symbol/XREF linkage and later data-flow stages for proven value propagation.",
        ],
    }
    legacy._save(job / "api-report.json", report)
    return report
