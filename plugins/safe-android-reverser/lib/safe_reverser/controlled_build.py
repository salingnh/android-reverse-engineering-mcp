from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Protocol

if TYPE_CHECKING:
    from .runtime_cache import RuntimeIdentity

MAX_PROVIDER_RESPONSE_BYTES = 1024 * 1024
MAX_PROVIDER_HANDLE = 512
MAX_PROVIDER_NAMESPACE = 64
GITHUB_API_VERSION = "2026-03-10"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)
WORKFLOW_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.ya?ml$")
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")


class ControlledBuildError(RuntimeError):
    code = "provider_error"


class ProviderUnavailableError(ControlledBuildError):
    code = "provider_unavailable"


class ProviderAuthenticationError(ControlledBuildError):
    code = "provider_authentication_failed"


class ProviderRequestError(ControlledBuildError):
    code = "provider_request_failed"


class ProviderPollingError(ControlledBuildError):
    code = "provider_polling_failed"


class ProviderBuildState(Enum):
    BUILDING = "BUILDING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class ProviderBuildHandle:
    namespace: str
    opaque_id: str
    submitted_at_epoch: int

    def __post_init__(self) -> None:
        if (
            not self.namespace
            or len(self.namespace) > MAX_PROVIDER_NAMESPACE
            or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", self.namespace)
        ):
            raise ValueError("invalid controlled-build provider namespace")
        if (
            not self.opaque_id
            or len(self.opaque_id) > MAX_PROVIDER_HANDLE
            or "\x00" in self.opaque_id
        ):
            raise ValueError("invalid controlled-build provider handle")
        if self.submitted_at_epoch < 0:
            raise ValueError("invalid controlled-build submission time")

    def to_private_dict(self) -> dict[str, Any]:
        return {
            "namespace": self.namespace,
            "opaque_id": self.opaque_id,
            "submitted_at_epoch": self.submitted_at_epoch,
        }

    @classmethod
    def from_private_dict(cls, value: dict[str, Any]) -> ProviderBuildHandle:
        if not isinstance(value, dict):
            raise ValueError("controlled-build handle must be an object")
        return cls(
            namespace=str(value.get("namespace") or ""),
            opaque_id=str(value.get("opaque_id") or ""),
            submitted_at_epoch=int(value.get("submitted_at_epoch") or 0),
        )


@dataclass(frozen=True)
class ProviderBuildStatus:
    state: ProviderBuildState
    source_revision: str | None = None
    failure_code: str | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.source_revision is not None and not SHA_RE.fullmatch(
            self.source_revision
        ):
            raise ValueError("invalid controlled-build source revision")
        for value, field in (
            (self.failure_code, "failure code"),
            (self.detail, "failure detail"),
        ):
            if value is not None and (len(value) > 512 or "\x00" in value):
                raise ValueError(f"invalid controlled-build {field}")


class ControlledBuildProvider(Protocol):
    @property
    def namespace(self) -> str: ...

    def submit(
        self, identity: RuntimeIdentity, request_identity: str
    ) -> ProviderBuildHandle: ...

    def status(
        self,
        handle: ProviderBuildHandle,
        identity: RuntimeIdentity,
        request_identity: str,
    ) -> ProviderBuildStatus: ...

    def reconcile(
        self, identity: RuntimeIdentity, request_identity: str
    ) -> ProviderBuildHandle | None: ...

    def cancel(self, handle: ProviderBuildHandle) -> None: ...


class GitHubActionsControlledBuildProvider:
    """GitHub Actions transport behind the provider-neutral build contract."""

    def __init__(
        self,
        *,
        token: str,
        repository: str,
        workflow: str,
        ref: str,
        api_base: str = "https://api.github.com",
        timeout_seconds: int = 20,
        opener: Callable[..., Any] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        token = str(token or "")
        if not token or len(token) > 8192 or any(ch in token for ch in "\x00\r\n"):
            raise ProviderAuthenticationError(
                "controlled-build credential is unavailable or invalid"
            )
        if not REPOSITORY_RE.fullmatch(repository):
            raise ProviderRequestError("controlled-build repository is invalid")
        if not WORKFLOW_RE.fullmatch(workflow):
            raise ProviderRequestError("controlled-build workflow is invalid")
        if not REF_RE.fullmatch(ref) or ".." in ref.split("/"):
            raise ProviderRequestError("controlled-build reference is invalid")
        parsed = urllib.parse.urlsplit(api_base)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ProviderRequestError("controlled-build API base must be HTTPS")
        self._token = token
        self.repository = repository
        self.workflow = workflow
        self.ref = ref
        self.api_base = api_base.rstrip("/")
        self.timeout_seconds = max(1, min(int(timeout_seconds), 60))
        self._opener = opener or urllib.request.urlopen
        self._clock = clock
        provider_config = json.dumps(
            {
                "api_base": self.api_base,
                "repository": self.repository,
                "workflow": self.workflow,
                "ref": self.ref,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        self._namespace = (
            "github-actions-v1-"
            + hashlib.sha256(provider_config).hexdigest()[:16]
        )

    @property
    def namespace(self) -> str:
        # The private namespace binds persisted opaque handles to one provider
        # configuration. Credentials are intentionally excluded from the
        # fingerprint so rotation does not strand an in-flight request.
        return self._namespace

    def _workflow_path(self) -> str:
        repository = "/".join(
            urllib.parse.quote(part, safe="") for part in self.repository.split("/")
        )
        workflow = urllib.parse.quote(self.workflow, safe="")
        return f"/repos/{repository}/actions/workflows/{workflow}"

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        polling: bool = False,
    ) -> dict[str, Any]:
        body = None
        if payload is not None:
            body = json.dumps(
                payload, ensure_ascii=True, separators=(",", ":")
            ).encode("ascii")
        request = urllib.request.Request(
            self.api_base + path,
            data=body,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "User-Agent": "safe-android-reverser-controlled-builder",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
            },
        )
        error_type = ProviderPollingError if polling else ProviderRequestError
        try:
            with self._opener(request, timeout=self.timeout_seconds) as response:
                raw = response.read(MAX_PROVIDER_RESPONSE_BYTES + 1)
                status = int(getattr(response, "status", 0))
        except urllib.error.HTTPError as exc:
            if exc.code in {401, 403}:
                raise ProviderAuthenticationError(
                    "controlled-build provider rejected authentication"
                ) from exc
            raise error_type(
                f"controlled-build provider returned HTTP {int(exc.code)}"
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ProviderUnavailableError(
                "controlled-build provider is unavailable"
            ) from exc
        if len(raw) > MAX_PROVIDER_RESPONSE_BYTES:
            raise error_type("controlled-build provider response exceeds size bound")
        if status < 200 or status >= 300:
            raise error_type(f"controlled-build provider returned HTTP {status}")
        if not raw:
            return {}
        try:
            value = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise error_type("controlled-build provider returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise error_type("controlled-build provider returned a non-object response")
        return value

    @staticmethod
    def _inputs(
        identity: RuntimeIdentity, request_identity: str
    ) -> dict[str, Any]:
        return {
            "request_identity": request_identity,
            "dart_version": identity.dart_version,
            "snapshot_hash": identity.snapshot_hash,
            "arch": identity.arch,
            "os": identity.os,
            "compressed_pointers": identity.compressed_pointers,
            "blutter_commit": identity.blutter_commit,
            "runtime_cache_schema": str(identity.runtime_cache_schema),
            "capability_api": str(identity.capability_api),
            "worker_abi": str(identity.worker_abi),
        }

    def submit(
        self, identity: RuntimeIdentity, request_identity: str
    ) -> ProviderBuildHandle:
        if request_identity != identity.request_identity:
            raise ProviderRequestError(
                "controlled-build request identity does not match runtime identity"
            )
        response = self._request(
            "POST",
            self._workflow_path() + "/dispatches",
            payload={
                "ref": self.ref,
                "inputs": self._inputs(identity, request_identity),
                "return_run_details": True,
            },
        )
        raw_id = response.get("workflow_run_id")
        try:
            run_id = int(raw_id)
        except (TypeError, ValueError) as exc:
            raise ProviderRequestError(
                "controlled-build provider omitted the run handle"
            ) from exc
        if run_id <= 0:
            raise ProviderRequestError("controlled-build provider returned an invalid run handle")
        return ProviderBuildHandle(
            namespace=self.namespace,
            opaque_id=str(run_id),
            submitted_at_epoch=int(self._clock()),
        )

    def _run_to_handle(self, run: dict[str, Any]) -> ProviderBuildHandle:
        try:
            run_id = int(run.get("id"))
        except (TypeError, ValueError) as exc:
            raise ProviderPollingError("controlled-build run has no valid handle") from exc
        if run_id <= 0:
            raise ProviderPollingError("controlled-build run has an invalid handle")
        return ProviderBuildHandle(
            namespace=self.namespace,
            opaque_id=str(run_id),
            submitted_at_epoch=int(self._clock()),
        )

    def status(
        self,
        handle: ProviderBuildHandle,
        identity: RuntimeIdentity,
        request_identity: str,
    ) -> ProviderBuildStatus:
        if request_identity != identity.request_identity:
            raise ProviderPollingError(
                "controlled-build request identity does not match runtime identity"
            )
        if handle.namespace != self.namespace or not handle.opaque_id.isdigit():
            raise ProviderPollingError("controlled-build handle belongs to another provider")
        run = self._request(
            "GET",
            f"/repos/{self.repository}/actions/runs/{handle.opaque_id}",
            polling=True,
        )
        expected_title = f"Runtime cache {request_identity}"
        if run.get("event") != "workflow_dispatch" or run.get("display_title") != expected_title:
            raise ProviderPollingError("controlled-build run identity does not match")
        status = str(run.get("status") or "")
        if status != "completed":
            return ProviderBuildStatus(ProviderBuildState.BUILDING)
        conclusion = str(run.get("conclusion") or "")
        if conclusion == "success":
            revision = str(run.get("head_sha") or "").lower()
            if not SHA_RE.fullmatch(revision):
                raise ProviderPollingError(
                    "controlled-build run omitted a valid source revision"
                )
            return ProviderBuildStatus(
                ProviderBuildState.SUCCEEDED, source_revision=revision
            )
        failure_code = {
            "cancelled": "build_cancelled",
            "timed_out": "build_timed_out",
            "action_required": "build_action_required",
        }.get(conclusion, "build_failed")
        return ProviderBuildStatus(
            ProviderBuildState.FAILED,
            failure_code=failure_code,
            detail="controlled runtime-cache build did not succeed",
        )

    def reconcile(
        self, identity: RuntimeIdentity, request_identity: str
    ) -> ProviderBuildHandle | None:
        if request_identity != identity.request_identity:
            raise ProviderPollingError(
                "controlled-build request identity does not match runtime identity"
            )
        query = urllib.parse.urlencode(
            {
                "branch": self.ref,
                "event": "workflow_dispatch",
                "per_page": "100",
                "exclude_pull_requests": "true",
            }
        )
        payload = self._request(
            "GET", self._workflow_path() + f"/runs?{query}", polling=True
        )
        runs = payload.get("workflow_runs")
        if not isinstance(runs, list) or len(runs) > 100:
            raise ProviderPollingError("controlled-build run list is invalid or unbounded")
        expected_title = f"Runtime cache {request_identity}"
        for run in runs:
            if isinstance(run, dict) and run.get("display_title") == expected_title:
                return self._run_to_handle(run)
        return None

    def cancel(self, handle: ProviderBuildHandle) -> None:
        if handle.namespace != self.namespace or not handle.opaque_id.isdigit():
            return
        self._request(
            "POST",
            f"/repos/{self.repository}/actions/runs/{handle.opaque_id}/cancel",
            polling=True,
        )
