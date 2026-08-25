from __future__ import annotations

from typing import Any

OWNERSHIP_SCOPES = ("FIRST_PARTY", "THIRD_PARTY", "PLATFORM", "GENERATED", "UNKNOWN")
OWNERSHIP_QUERY_SCOPES = (
    "application",
    "all",
    "first_party",
    "third_party",
    "platform",
    "generated",
    "unknown",
)
OWNERSHIP_QUERY_SCOPE_MAP = {
    "application": frozenset({"FIRST_PARTY", "UNKNOWN"}),
    "all": frozenset(OWNERSHIP_SCOPES),
    "first_party": frozenset({"FIRST_PARTY"}),
    "third_party": frozenset({"THIRD_PARTY"}),
    "platform": frozenset({"PLATFORM"}),
    "generated": frozenset({"GENERATED"}),
    "unknown": frozenset({"UNKNOWN"}),
}


class OwnershipContractError(ValueError):
    pass


def validate_ownership_scope(value: Any) -> str:
    scope = str(value or "application").strip().lower()
    if scope not in OWNERSHIP_QUERY_SCOPE_MAP:
        raise OwnershipContractError("invalid ownership query scope")
    return scope


def validate_ownership(value: Any) -> str:
    scope = str(value or "UNKNOWN").strip().upper()
    if scope not in OWNERSHIP_SCOPES:
        raise OwnershipContractError("invalid ownership scope")
    return scope


def ownership_scope_accepts(ownership: Any, query_scope: Any) -> bool:
    return validate_ownership(ownership) in OWNERSHIP_QUERY_SCOPE_MAP[
        validate_ownership_scope(query_scope)
    ]
