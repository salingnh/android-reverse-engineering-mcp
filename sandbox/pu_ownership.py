from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

OWNERSHIP_MODEL_VERSION = 1
OWNERSHIP_RULES_SCHEMA = 1
MAX_RULES_BYTES = 256 * 1024
MAX_NAMESPACE_RULES = 512
MAX_GENERATED_PATTERNS = 128
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_COMPONENTS = 5000

SCOPES = ("FIRST_PARTY", "THIRD_PARTY", "PLATFORM", "GENERATED", "UNKNOWN")
QUERY_SCOPES = (
    "application",
    "all",
    "first_party",
    "third_party",
    "platform",
    "generated",
    "unknown",
)
QUERY_SCOPE_MAP = {
    "application": frozenset({"FIRST_PARTY", "UNKNOWN"}),
    "all": frozenset(SCOPES),
    "first_party": frozenset({"FIRST_PARTY"}),
    "third_party": frozenset({"THIRD_PARTY"}),
    "platform": frozenset({"PLATFORM"}),
    "generated": frozenset({"GENERATED"}),
    "unknown": frozenset({"UNKNOWN"}),
}
ANDROID_NAME = "{http://schemas.android.com/apk/res/android}name"
RULES_PATH = Path(__file__).with_name("ownership_rules.json")
MANIFEST_CANDIDATES = (
    Path("jadx/resources/AndroidManifest.xml"),
    Path("jadx/AndroidManifest.xml"),
    Path("apktool/AndroidManifest.xml"),
    Path("resources/AndroidManifest.xml"),
)


class OwnershipModelError(ValueError):
    pass


@dataclass(frozen=True)
class NamespaceRule:
    prefix: str
    scope: str
    owner: str
    sdk: str | None = None


@dataclass(frozen=True)
class OwnershipRules:
    schema_version: int
    digest: str
    namespaces: tuple[NamespaceRule, ...]
    generated_patterns: tuple[re.Pattern[str], ...]

    def descriptor(self) -> dict[str, Any]:
        return {
            "model_version": OWNERSHIP_MODEL_VERSION,
            "rules_schema": self.schema_version,
            "rules_sha256": self.digest,
            "scopes": list(SCOPES),
            "query_scopes": list(QUERY_SCOPES),
        }


@dataclass(frozen=True)
class OwnershipContext:
    application_package: str | None
    manifest_components: frozenset[str]
    manifest_status: str
    manifest_source: str | None = None

    def descriptor(self) -> dict[str, Any]:
        return {
            "application_package": self.application_package,
            "manifest_component_count": len(self.manifest_components),
            "manifest_status": self.manifest_status,
            "manifest_source": self.manifest_source,
        }


def _validate_namespace(value: str) -> str:
    value = str(value or "").strip().replace("/", ".")
    if value.startswith("L") and value.endswith(";"):
        value = value[1:-1]
    value = value.strip(".")
    if not value or len(value) > 512:
        raise OwnershipModelError("ownership namespace is invalid")
    if not re.fullmatch(r"[A-Za-z0-9_$]+(?:\.[A-Za-z0-9_$]+)*", value):
        raise OwnershipModelError("ownership namespace contains invalid characters")
    return value


def normalize_class_name(value: Any) -> str:
    raw = str(value or "").strip()
    if raw.startswith("["):
        raw = raw.lstrip("[")
    if raw.startswith("L") and raw.endswith(";"):
        raw = raw[1:-1]
    raw = raw.replace("/", ".").strip(".")
    if not raw or len(raw) > 1024:
        return ""
    return raw


def validate_query_scope(value: str) -> str:
    scope = str(value or "application").strip().lower()
    if scope not in QUERY_SCOPE_MAP:
        raise OwnershipModelError("invalid ownership query scope")
    return scope


def scope_accepts(decision: dict[str, Any], query_scope: str) -> bool:
    scope = validate_query_scope(query_scope)
    return str(decision.get("scope")) in QUERY_SCOPE_MAP[scope]


def load_rules(path: Path = RULES_PATH) -> OwnershipRules:
    if path.is_symlink() or not path.is_file():
        raise OwnershipModelError("ownership rule registry is unavailable")
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_RULES_BYTES:
        raise OwnershipModelError("ownership rule registry exceeds size bound")
    digest = hashlib.sha256(raw).hexdigest()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OwnershipModelError("ownership rule registry is invalid") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != OWNERSHIP_RULES_SCHEMA:
        raise OwnershipModelError("unsupported ownership rule schema")

    namespace_rows = payload.get("namespaces")
    pattern_rows = payload.get("generated_patterns")
    if not isinstance(namespace_rows, list) or len(namespace_rows) > MAX_NAMESPACE_RULES:
        raise OwnershipModelError("ownership namespace registry is invalid")
    if not isinstance(pattern_rows, list) or len(pattern_rows) > MAX_GENERATED_PATTERNS:
        raise OwnershipModelError("ownership generated-pattern registry is invalid")

    namespaces: list[NamespaceRule] = []
    seen_prefixes: set[str] = set()
    for item in namespace_rows:
        if not isinstance(item, dict):
            raise OwnershipModelError("ownership namespace rule must be an object")
        if set(item) - {"prefix", "scope", "owner", "sdk"}:
            raise OwnershipModelError("ownership namespace rule contains unknown fields")
        prefix = _validate_namespace(str(item.get("prefix") or "")) + "."
        scope = str(item.get("scope") or "")
        owner = str(item.get("owner") or "").strip()
        sdk = item.get("sdk")
        if scope not in {"THIRD_PARTY", "PLATFORM"}:
            raise OwnershipModelError("namespace rules may classify only third-party/platform code")
        if not owner or len(owner) > 128:
            raise OwnershipModelError("ownership rule owner is invalid")
        if sdk is not None and (not isinstance(sdk, str) or not sdk.strip() or len(sdk) > 128):
            raise OwnershipModelError("ownership rule SDK is invalid")
        if prefix in seen_prefixes:
            raise OwnershipModelError("ownership namespace rule is duplicated")
        seen_prefixes.add(prefix)
        namespaces.append(NamespaceRule(prefix, scope, owner, sdk.strip() if isinstance(sdk, str) else None))

    compiled: list[re.Pattern[str]] = []
    for value in pattern_rows:
        if not isinstance(value, str) or not value or len(value) > 512:
            raise OwnershipModelError("generated-code pattern is invalid")
        try:
            compiled.append(re.compile(value))
        except re.error as exc:
            raise OwnershipModelError("generated-code pattern cannot be compiled") from exc

    namespaces.sort(key=lambda item: (-len(item.prefix), item.prefix, item.scope, item.owner))
    return OwnershipRules(
        schema_version=OWNERSHIP_RULES_SCHEMA,
        digest=digest,
        namespaces=tuple(namespaces),
        generated_patterns=tuple(compiled),
    )


def _resolve_component_name(application_package: str | None, value: str) -> str | None:
    value = str(value or "").strip()
    if not value:
        return None
    if value.startswith("."):
        return f"{application_package}{value}" if application_package else None
    if "." not in value:
        return f"{application_package}.{value}" if application_package else value
    return normalize_class_name(value) or None


def _manifest_path(job: Path) -> Path | None:
    root = job.resolve()
    for relative in MANIFEST_CANDIDATES:
        candidate = job / relative
        if candidate.is_symlink() or not candidate.is_file():
            continue
        resolved = candidate.resolve()
        if root != resolved and root not in resolved.parents:
            continue
        return candidate
    return None


def ownership_context(job: Path) -> OwnershipContext:
    manifest = _manifest_path(job)
    if manifest is None:
        return OwnershipContext(None, frozenset(), "missing", None)
    source = str(manifest.relative_to(job))
    try:
        if manifest.stat().st_size > MAX_MANIFEST_BYTES:
            return OwnershipContext(None, frozenset(), "oversized", source)
        raw = manifest.read_bytes()
        upper = raw.upper()
        # Decompiled manifests are attacker-controlled artifact data. Ownership
        # extraction needs only elements/attributes, so DTD/entity declarations
        # are never required and are rejected before XML parsing.
        if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
            return OwnershipContext(None, frozenset(), "unsafe_xml", source)
        root = ET.fromstring(raw)
    except (OSError, ET.ParseError, ValueError, RecursionError):
        return OwnershipContext(None, frozenset(), "invalid", source)

    raw_package = str(root.attrib.get("package") or "").strip()
    try:
        application_package = _validate_namespace(raw_package) if raw_package else None
    except OwnershipModelError:
        application_package = None

    components: set[str] = set()
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] not in {
            "application",
            "activity",
            "activity-alias",
            "service",
            "receiver",
            "provider",
            "instrumentation",
        }:
            continue
        resolved = _resolve_component_name(application_package, element.attrib.get(ANDROID_NAME, ""))
        if resolved:
            components.add(resolved)
            if len(components) >= MAX_MANIFEST_COMPONENTS:
                break
    return OwnershipContext(
        application_package,
        frozenset(sorted(components)),
        "parsed",
        source,
    )


def _under_package(class_name: str, package: str | None) -> bool:
    return bool(package) and (class_name == package or class_name.startswith(package + "."))


class CodeOwnershipClassifier:
    def __init__(
        self,
        context: OwnershipContext,
        *,
        rules: OwnershipRules | None = None,
    ) -> None:
        self.context = context
        self.rules = rules or load_rules()

    @classmethod
    def for_job(cls, job: Path) -> "CodeOwnershipClassifier":
        return cls(ownership_context(job))

    def descriptor(self) -> dict[str, Any]:
        return {
            **self.rules.descriptor(),
            "context": self.context.descriptor(),
        }

    def _namespace_rule(self, class_name: str) -> NamespaceRule | None:
        for rule in self.rules.namespaces:
            if class_name.startswith(rule.prefix):
                return rule
        return None

    def _generated(self, class_name: str) -> bool:
        return any(pattern.search(class_name) for pattern in self.rules.generated_patterns)

    @staticmethod
    def _result(
        scope: str,
        *,
        owner: str | None,
        sdk: str | None,
        reasons: list[str],
        evidence: list[dict[str, str]],
    ) -> dict[str, Any]:
        relevance = {
            "FIRST_PARTY": "application",
            "UNKNOWN": "application-candidate",
            "THIRD_PARTY": "external-boundary",
            "PLATFORM": "infrastructure",
            "GENERATED": "generated",
        }[scope]
        return {
            "scope": scope,
            "owner": owner,
            "sdk": sdk,
            "classification_reasons": reasons,
            "classification_evidence": evidence,
            "relevance": relevance,
        }

    def classify(self, class_name: Any, *, external: bool = False) -> dict[str, Any]:
        normalized = normalize_class_name(class_name)
        if not normalized:
            return self._result(
                "UNKNOWN",
                owner=None,
                sdk=None,
                reasons=["class_identity_unavailable"],
                evidence=[],
            )

        app_package = self.context.application_package
        app_match = _under_package(normalized, app_package)
        app_prefix_len = len(app_package) + 1 if app_match and app_package else 0
        exact_component = normalized in self.context.manifest_components
        rule = self._namespace_rule(normalized)

        # A known vendor/platform namespace is stronger than a merged manifest
        # component. A genuinely more-specific application namespace remains
        # first-party, e.g. com.google.firebase.demo.* versus com.google.firebase.*.
        if rule is not None and (not app_match or len(rule.prefix) >= app_prefix_len):
            return self._result(
                rule.scope,
                owner=rule.owner,
                sdk=rule.sdk,
                reasons=["known_namespace_rule"],
                evidence=[{"kind": "namespace_prefix", "value": rule.prefix.rstrip(".")}],
            )

        if self._generated(normalized):
            evidence: list[dict[str, str]] = [{"kind": "generated_name_pattern", "value": normalized.rsplit(".", 1)[-1]}]
            if app_match and app_package:
                evidence.append({"kind": "application_package", "value": app_package})
            return self._result(
                "GENERATED",
                owner=app_package if app_match else None,
                sdk=None,
                reasons=["generated_code_pattern"],
                evidence=evidence,
            )

        if app_match and app_package:
            return self._result(
                "FIRST_PARTY",
                owner=app_package,
                sdk=None,
                reasons=["application_package_namespace"],
                evidence=[{"kind": "application_package", "value": app_package}],
            )

        if exact_component:
            evidence = [{"kind": "manifest_component", "value": normalized}]
            if app_package:
                evidence.append({"kind": "application_package", "value": app_package})
            return self._result(
                "FIRST_PARTY",
                owner=app_package,
                sdk=None,
                reasons=["manifest_component"],
                evidence=evidence,
            )

        evidence = []
        reasons = ["insufficient_ownership_evidence"]
        if external:
            reasons.append("external_method_is_not_ownership")
            evidence.append({"kind": "dex_external", "value": "true"})
        return self._result(
            "UNKNOWN",
            owner=None,
            sdk=None,
            reasons=reasons,
            evidence=evidence,
        )

    def accepts(self, class_name: Any, query_scope: str, *, external: bool = False) -> bool:
        return scope_accepts(self.classify(class_name, external=external), query_scope)


def ownership_model(job: Path) -> dict[str, Any]:
    return CodeOwnershipClassifier.for_job(job).descriptor()
