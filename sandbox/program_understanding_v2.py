from __future__ import annotations

import shutil
from typing import Any

import program_understanding as legacy
import pu_api
import pu_index
import pu_network
import pu_ownership
import pu_ownership_queries


def capabilities() -> dict[str, Any]:
    apkid = shutil.which("apkid")
    result = {
        "androguard": False,
        "apkid": bool(apkid),
        "versions": {"androguard": None, "apkid": "external-cli" if apkid else None},
        "errors": {},
        "index_storage": "sqlite",
        "code_ownership": True,
        "ownership_model_version": pu_ownership.OWNERSHIP_MODEL_VERSION,
        "ownership_scopes": list(pu_ownership.QUERY_SCOPES),
    }
    try:
        import androguard  # type: ignore
        from androguard.core import dex as _dex  # noqa: F401  # type: ignore
        from androguard.core.analysis.analysis import Analysis as _Analysis  # noqa: F401  # type: ignore
        result["androguard"] = True
        result["versions"]["androguard"] = getattr(androguard, "__version__", "installed")
    except Exception as exc:
        result["errors"]["androguard"] = f"{type(exc).__name__}: {exc}"
    return result


def build_program_index(job, workspace, *, max_methods=100_000, max_edges=250_000, force=False):
    result = pu_index.build_program_index(
        job, workspace, capabilities(), max_methods=max_methods, max_edges=max_edges, force=force
    )
    result["ownership_model"] = pu_ownership.ownership_model(job)
    return result


def extract_api(job, *, scope="application", max_items=500):
    return pu_api.extract_api(job, scope=scope, max_items=max_items)


def find_symbols(job, workspace, query, *, scope="application", limit=100):
    return pu_ownership_queries.find_symbols(
        job,
        workspace,
        capabilities(),
        query,
        scope=scope,
        limit=limit,
    )


def find_xrefs(job, workspace, query, *, direction="both", scope="application", limit=200):
    return pu_ownership_queries.find_xrefs(
        job,
        workspace,
        capabilities(),
        query,
        direction=direction,
        scope=scope,
        limit=limit,
    )


def get_cfg(job, workspace, query, *, scope="application", max_blocks=500):
    return pu_ownership_queries.get_cfg(
        job,
        workspace,
        query,
        scope=scope,
        max_blocks=max_blocks,
    )


def identify_protector(artifact, *, timeout=10):
    return legacy.identify_protector(artifact, timeout=timeout)


def extract_network_model(job, workspace, *, scope="application", max_items=500):
    return pu_network.extract_network_model(
        job,
        workspace,
        capabilities(),
        scope=scope,
        max_items=max_items,
    )
