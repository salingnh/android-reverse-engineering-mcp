from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from typing import Any, Iterable

SECURITY_FINDING_SCHEMA_VERSION = 1

FINDING_STATES = ("candidate", "probable", "verified", "refuted", "unknown")
TERMINAL_FINDING_STATES = frozenset({"verified", "refuted", "unknown"})
SEVERITIES = ("unknown", "info", "low", "medium", "high", "critical")
ANCHOR_KINDS = (
    "PROGRAM_ENTITY",
    "FLOW_NODE",
    "FLOW_EDGE",
    "FLOW_PATH",
    "FLOW_GAP",
    "ARTIFACT",
)
KNOWLEDGE_SCHEMES = ("CWE", "MASWE", "MASVS", "MASTG")
VERIFICATION_VERDICTS = ("verified", "refuted", "unknown")
VERIFICATION_METHODS = (
    "STATIC_SEMANTIC",
    "STATIC_REACHABILITY",
    "STATIC_DATA_FLOW",
    "DYNAMIC_OBSERVATION",
    "MANUAL_REVIEW",
)

MAX_TEXT = 512
MAX_TITLE = 256
MAX_REFS = 64
MAX_FLOW_PATHS = 32
MAX_KNOWLEDGE_REFS = 32
MAX_RELATED_ANCHORS = 64
MAX_LIMITATIONS = 32
MAX_LIMITATION_TEXT = 1024


class SecurityFindingError(ValueError):
    pass


class FindingTransitionError(SecurityFindingError):
    pass


def _text(value: Any, name: str, maximum: int = MAX_TEXT, *, empty: bool = False) -> str:
    if not isinstance(value, str):
        raise SecurityFindingError(f"{name} must be a string")
    result = value.strip()
    if not result and not empty:
        raise SecurityFindingError(f"{name} must be non-empty")
    if len(result) > maximum:
        raise SecurityFindingError(f"{name} exceeds size bound")
    if any(ord(char) < 32 and char not in "\t\n\r" for char in result):
        raise SecurityFindingError(f"{name} contains control characters")
    return result


def _enum(value: Any, allowed: Iterable[str], name: str, *, upper: bool = False) -> str:
    result = _text(value, name, 128)
    normalized = result.upper() if upper else result.lower()
    options = {item.upper() if upper else item.lower() for item in allowed}
    if normalized not in options:
        raise SecurityFindingError(f"unsupported {name}: {result}")
    return normalized


def _bounded_refs(values: Iterable[str], name: str, maximum: int) -> tuple[str, ...]:
    result = tuple(sorted({_text(item, name, 256) for item in values}))
    if len(result) > maximum:
        raise SecurityFindingError(f"{name} exceeds count bound")
    return result


def _digest(*parts: str) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part.encode("utf-8", "strict"))
        digest.update(b"\0")
    return digest.hexdigest()


@dataclass(frozen=True)
class RuleIdentity:
    namespace: str
    rule_id: str
    version: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "namespace", _text(self.namespace, "rule namespace", 128).lower())
        object.__setattr__(self, "rule_id", _text(self.rule_id, "rule_id", 256))
        object.__setattr__(self, "version", _text(self.version, "rule version", 128))

    def to_dict(self) -> dict[str, str]:
        return {
            "namespace": self.namespace,
            "rule_id": self.rule_id,
            "version": self.version,
        }


@dataclass(frozen=True)
class KnowledgeRef:
    scheme: str
    identifier: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "scheme", _enum(self.scheme, KNOWLEDGE_SCHEMES, "knowledge scheme", upper=True))
        object.__setattr__(self, "identifier", _text(self.identifier, "knowledge identifier", 128))

    def to_dict(self) -> dict[str, str]:
        return {"scheme": self.scheme, "identifier": self.identifier}


@dataclass(frozen=True)
class SemanticAnchor:
    kind: str
    anchor_id: str
    representation: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _enum(self.kind, ANCHOR_KINDS, "anchor kind", upper=True))
        object.__setattr__(self, "anchor_id", _text(self.anchor_id, "anchor_id", 256))
        object.__setattr__(
            self,
            "representation",
            _text(self.representation, "representation", 64, empty=True).lower(),
        )

    def identity_key(self) -> str:
        return f"{self.kind}:{self.anchor_id}"

    def to_dict(self) -> dict[str, str]:
        result = {"kind": self.kind, "anchor_id": self.anchor_id}
        if self.representation:
            result["representation"] = self.representation
        return result


@dataclass(frozen=True)
class VerificationRecord:
    verifier: str
    verdict: str
    method: str
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)
    flow_path_ids: tuple[str, ...] = field(default_factory=tuple)
    limitations: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "verifier", _text(self.verifier, "verifier", 128))
        object.__setattr__(
            self,
            "verdict",
            _enum(self.verdict, VERIFICATION_VERDICTS, "verification verdict"),
        )
        object.__setattr__(
            self,
            "method",
            _enum(self.method, VERIFICATION_METHODS, "verification method", upper=True),
        )
        object.__setattr__(
            self,
            "evidence_refs",
            _bounded_refs(self.evidence_refs, "verification evidence_ref", MAX_REFS),
        )
        object.__setattr__(
            self,
            "flow_path_ids",
            _bounded_refs(self.flow_path_ids, "verification flow_path_id", MAX_FLOW_PATHS),
        )
        limitations = tuple(
            sorted({_text(item, "verification limitation", MAX_LIMITATION_TEXT) for item in self.limitations})
        )
        if len(limitations) > MAX_LIMITATIONS:
            raise SecurityFindingError("verification limitations exceed count bound")
        object.__setattr__(self, "limitations", limitations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verifier": self.verifier,
            "verdict": self.verdict,
            "method": self.method,
            "evidence_refs": list(self.evidence_refs),
            "flow_path_ids": list(self.flow_path_ids),
            "limitations": list(self.limitations),
        }


def security_finding_id(snapshot_id: str, rule: RuleIdentity, primary_anchor: SemanticAnchor) -> str:
    snapshot = _text(snapshot_id, "snapshot_id", 128)
    if not isinstance(rule, RuleIdentity):
        raise SecurityFindingError("rule must be RuleIdentity")
    if not isinstance(primary_anchor, SemanticAnchor):
        raise SecurityFindingError("primary_anchor must be SemanticAnchor")
    digest = _digest(
        snapshot,
        rule.namespace,
        rule.rule_id,
        rule.version,
        primary_anchor.identity_key(),
    )
    return f"finding:v{SECURITY_FINDING_SCHEMA_VERSION}:{digest}"


@dataclass(frozen=True)
class SecurityFinding:
    snapshot_id: str
    finding_id: str
    rule: RuleIdentity
    title: str
    category: str
    severity: str
    state: str
    primary_anchor: SemanticAnchor
    producer: str
    related_anchors: tuple[SemanticAnchor, ...] = field(default_factory=tuple)
    knowledge_refs: tuple[KnowledgeRef, ...] = field(default_factory=tuple)
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)
    flow_path_ids: tuple[str, ...] = field(default_factory=tuple)
    limitations: tuple[str, ...] = field(default_factory=tuple)
    verification: VerificationRecord | None = None

    def __post_init__(self) -> None:
        snapshot = _text(self.snapshot_id, "snapshot_id", 128)
        if not isinstance(self.rule, RuleIdentity):
            raise SecurityFindingError("rule must be RuleIdentity")
        if not isinstance(self.primary_anchor, SemanticAnchor):
            raise SecurityFindingError("primary_anchor must be SemanticAnchor")
        finding_id = _text(self.finding_id, "finding_id", 256)
        expected_id = security_finding_id(snapshot, self.rule, self.primary_anchor)
        if finding_id != expected_id:
            raise SecurityFindingError("finding_id does not match canonical identity")

        title = _text(self.title, "title", MAX_TITLE)
        category = _text(self.category, "category", 128).lower()
        severity = _enum(self.severity, SEVERITIES, "severity")
        state = _enum(self.state, FINDING_STATES, "finding state")
        producer = _text(self.producer, "producer", 128)

        related: dict[str, SemanticAnchor] = {}
        for anchor in self.related_anchors:
            if not isinstance(anchor, SemanticAnchor):
                raise SecurityFindingError("related anchor must be SemanticAnchor")
            related[anchor.identity_key()] = anchor
        related.pop(self.primary_anchor.identity_key(), None)
        if len(related) > MAX_RELATED_ANCHORS:
            raise SecurityFindingError("related anchors exceed count bound")

        knowledge: dict[tuple[str, str], KnowledgeRef] = {}
        for item in self.knowledge_refs:
            if not isinstance(item, KnowledgeRef):
                raise SecurityFindingError("knowledge ref must be KnowledgeRef")
            knowledge[(item.scheme, item.identifier)] = item
        if len(knowledge) > MAX_KNOWLEDGE_REFS:
            raise SecurityFindingError("knowledge refs exceed count bound")

        evidence_refs = _bounded_refs(self.evidence_refs, "evidence_ref", MAX_REFS)
        flow_path_ids = _bounded_refs(self.flow_path_ids, "flow_path_id", MAX_FLOW_PATHS)
        limitations = tuple(sorted({_text(item, "limitation", MAX_LIMITATION_TEXT) for item in self.limitations}))
        if len(limitations) > MAX_LIMITATIONS:
            raise SecurityFindingError("limitations exceed count bound")

        verification = self.verification
        if state in TERMINAL_FINDING_STATES:
            if not isinstance(verification, VerificationRecord):
                raise SecurityFindingError("terminal finding state requires VerificationRecord")
            if verification.verdict != state:
                raise SecurityFindingError("verification verdict must match terminal finding state")
            if verification.verifier == producer:
                raise SecurityFindingError("verification must be logically independent from finding producer")
        elif verification is not None:
            raise SecurityFindingError("candidate/probable finding cannot carry terminal verification")

        for name, value in (
            ("snapshot_id", snapshot),
            ("finding_id", finding_id),
            ("title", title),
            ("category", category),
            ("severity", severity),
            ("state", state),
            ("producer", producer),
            ("related_anchors", tuple(related[key] for key in sorted(related))),
            ("knowledge_refs", tuple(knowledge[key] for key in sorted(knowledge))),
            ("evidence_refs", evidence_refs),
            ("flow_path_ids", flow_path_ids),
            ("limitations", limitations),
        ):
            object.__setattr__(self, name, value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SECURITY_FINDING_SCHEMA_VERSION,
            "snapshot_id": self.snapshot_id,
            "finding_id": self.finding_id,
            "rule": self.rule.to_dict(),
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "state": self.state,
            "primary_anchor": self.primary_anchor.to_dict(),
            "related_anchors": [item.to_dict() for item in self.related_anchors],
            "knowledge_refs": [item.to_dict() for item in self.knowledge_refs],
            "producer": self.producer,
            "evidence_refs": list(self.evidence_refs),
            "flow_path_ids": list(self.flow_path_ids),
            "limitations": list(self.limitations),
            "verification": self.verification.to_dict() if self.verification else None,
        }


_ALLOWED_TRANSITIONS = {
    "candidate": frozenset({"probable", "verified", "refuted", "unknown"}),
    "probable": frozenset({"verified", "refuted", "unknown"}),
    "verified": frozenset(),
    "refuted": frozenset(),
    "unknown": frozenset(),
}


def transition_finding(
    finding: SecurityFinding,
    state: str,
    *,
    verification: VerificationRecord | None = None,
) -> SecurityFinding:
    if not isinstance(finding, SecurityFinding):
        raise FindingTransitionError("finding must be SecurityFinding")
    target = _enum(state, FINDING_STATES, "finding state")
    if target == finding.state:
        if verification is not None and verification != finding.verification:
            raise FindingTransitionError("same-state transition cannot replace verification")
        return finding
    if target not in _ALLOWED_TRANSITIONS[finding.state]:
        raise FindingTransitionError(f"invalid finding transition: {finding.state} -> {target}")
    try:
        return replace(finding, state=target, verification=verification)
    except SecurityFindingError as exc:
        raise FindingTransitionError(str(exc)) from exc
