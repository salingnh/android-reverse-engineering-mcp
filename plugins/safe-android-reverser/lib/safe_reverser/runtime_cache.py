from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterator

from .controlled_build import (
    ControlledBuildError,
    ControlledBuildProvider,
    ProviderAuthenticationError,
    ProviderBuildHandle,
    ProviderBuildState,
    ProviderPollingError,
    ProviderRequestError,
    ProviderUnavailableError,
)
from .paths import (
    PathPolicyError,
    atomic_write_json,
    ensure_private_child,
    read_json_file,
)
from .runtime import (
    ContainerRuntime,
    ImageUnavailableError,
    ImageVerificationError,
    RuntimeErrorSafe,
    VerifiedImage,
)

RUNTIME_CACHE_STATE_SCHEMA = 1
MAX_RUNTIME_CACHE_STATE_BYTES = 64 * 1024
MAX_STATE_ENTRIES = 10_000
DART_VERSION_RE = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]{1,24})?$"
)
SNAPSHOT_RE = re.compile(r"^[0-9a-f]{32,64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
PLATFORM_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
FAILURE_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class RuntimeCacheError(RuntimeError):
    pass


class RuntimeCacheStoreError(RuntimeCacheError):
    pass


class RuntimeCacheState(Enum):
    READY = "READY"
    BUILD_REQUIRED = "BUILD_REQUIRED"
    BUILDING = "BUILDING"
    FAILED = "FAILED"


@dataclass(frozen=True)
class RuntimeIdentity:
    dart_version: str
    snapshot_hash: str
    arch: str
    os: str
    compressed_pointers: bool
    blutter_commit: str
    runtime_cache_schema: int
    capability_api: int
    worker_abi: int

    def __post_init__(self) -> None:
        if not DART_VERSION_RE.fullmatch(self.dart_version):
            raise RuntimeCacheError("invalid Dart runtime version")
        if not SNAPSHOT_RE.fullmatch(self.snapshot_hash):
            raise RuntimeCacheError("invalid Dart snapshot hash")
        if not PLATFORM_TOKEN_RE.fullmatch(self.arch):
            raise RuntimeCacheError("invalid runtime architecture")
        if not PLATFORM_TOKEN_RE.fullmatch(self.os):
            raise RuntimeCacheError("invalid runtime operating system")
        if type(self.compressed_pointers) is not bool:
            raise RuntimeCacheError("compressed-pointers identity must be boolean")
        if not COMMIT_RE.fullmatch(self.blutter_commit):
            raise RuntimeCacheError("invalid Blutter commit identity")
        for value, name in (
            (self.runtime_cache_schema, "runtime-cache schema"),
            (self.capability_api, "Capability API"),
            (self.worker_abi, "Worker ABI"),
        ):
            if type(value) is not int or value < 1 or value > 2**31 - 1:
                raise RuntimeCacheError(f"invalid {name} identity")

    def to_dict(self) -> dict[str, Any]:
        return {
            "dart_version": self.dart_version,
            "snapshot_hash": self.snapshot_hash,
            "arch": self.arch,
            "os": self.os,
            "compressed_pointers": self.compressed_pointers,
            "blutter_commit": self.blutter_commit,
            "runtime_cache_schema": self.runtime_cache_schema,
            "capability_api": self.capability_api,
            "worker_abi": self.worker_abi,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> RuntimeIdentity:
        if not isinstance(value, dict):
            raise RuntimeCacheError("runtime identity must be an object")
        expected = {
            "dart_version",
            "snapshot_hash",
            "arch",
            "os",
            "compressed_pointers",
            "blutter_commit",
            "runtime_cache_schema",
            "capability_api",
            "worker_abi",
        }
        if set(value) != expected:
            raise RuntimeCacheError("runtime identity fields are incomplete or unknown")
        for field in (
            "dart_version",
            "snapshot_hash",
            "arch",
            "os",
            "blutter_commit",
        ):
            if type(value[field]) is not str:
                raise RuntimeCacheError(f"runtime identity {field} must be a string")
        compressed = value["compressed_pointers"]
        if type(compressed) is not bool:
            raise RuntimeCacheError("compressed-pointers identity must be boolean")
        for field in (
            "runtime_cache_schema",
            "capability_api",
            "worker_abi",
        ):
            if type(value[field]) is not int:
                raise RuntimeCacheError(f"runtime identity {field} must be an integer")
        return cls(
            dart_version=str(value["dart_version"]),
            snapshot_hash=str(value["snapshot_hash"]).lower(),
            arch=str(value["arch"]).lower(),
            os=str(value["os"]).lower(),
            compressed_pointers=compressed,
            blutter_commit=str(value["blutter_commit"]).lower(),
            runtime_cache_schema=int(value["runtime_cache_schema"]),
            capability_api=int(value["capability_api"]),
            worker_abi=int(value["worker_abi"]),
        )

    @property
    def request_identity(self) -> str:
        encoded = json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        return hashlib.sha256(encoded).hexdigest()

    @property
    def cache_tag(self) -> str:
        """Derive the registry-independent OCI tag contract used by the worker."""
        canonical = {
            "dart_version": self.dart_version,
            "snapshot_hash": self.snapshot_hash,
            "arch": self.arch,
            "os": self.os,
            "blutter_commit": self.blutter_commit,
            "compressed_pointers": self.compressed_pointers,
            "cache_schema": self.runtime_cache_schema,
            "capability_api": self.capability_api,
            "worker_abi": self.worker_abi,
        }
        digest = hashlib.sha256(
            json.dumps(
                canonical,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest()
        mode = "cp" if self.compressed_pointers else "ncp"
        tag = f"dart-{self.dart_version}-{self.arch}-{mode}-{digest}"
        if len(tag) > 128:
            raise RuntimeCacheError("derived runtime-cache tag exceeds OCI tag bound")
        return tag

    def required_labels(self) -> dict[str, str]:
        return {
            "io.safe-reverser.capability.id": "framework-flutter",
            "io.safe-reverser.capability.api": str(self.capability_api),
            "io.safe-reverser.worker.abi": str(self.worker_abi),
            "io.safe-reverser.runtime-cache.schema": str(
                self.runtime_cache_schema
            ),
            "io.safe-reverser.blutter.commit": self.blutter_commit,
            "io.safe-reverser.dart.version": self.dart_version,
            "io.safe-reverser.dart.snapshot": self.snapshot_hash,
            "io.safe-reverser.dart.arch": self.arch,
            "io.safe-reverser.dart.os": self.os,
            "io.safe-reverser.dart.compressed-pointers": (
                "true" if self.compressed_pointers else "false"
            ),
        }


@dataclass(frozen=True)
class RuntimeCacheResolution:
    state: RuntimeCacheState
    request_identity: str
    cache_ref: str
    image: VerifiedImage | None = None
    failure_code: str | None = None
    detail: str | None = None
    warning: str | None = None
    retry_after_epoch: int | None = None

    def public_status(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "state": self.state.value,
            "request_identity": self.request_identity,
        }
        if self.image is not None:
            payload["image_id"] = self.image.immutable_ref
        if self.failure_code:
            payload["failure_code"] = self.failure_code
        if self.detail:
            payload["detail"] = self.detail
        if self.warning:
            payload["warning"] = self.warning
        if self.retry_after_epoch is not None:
            payload["retry_after_epoch"] = self.retry_after_epoch
        return payload


class RuntimeCacheStateStore:
    def __init__(self, data_root: Path) -> None:
        try:
            self.root = ensure_private_child(data_root.resolve(), "runtime-cache-resolver")
            self.states = ensure_private_child(self.root, "states-v1")
            self.locks = ensure_private_child(self.root, "locks-v1")
        except PathPolicyError as exc:
            raise RuntimeCacheStoreError(str(exc)) from exc

    @staticmethod
    def _filename(request_identity: str, suffix: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", request_identity):
            raise RuntimeCacheStoreError("invalid runtime-cache request identity")
        return request_identity + suffix

    def _bounded_entry_count(self, directory: Path) -> None:
        count = 0
        for _entry in directory.iterdir():
            count += 1
            if count > MAX_STATE_ENTRIES:
                raise RuntimeCacheStoreError(
                    "runtime-cache state directory exceeds entry bound"
                )

    @contextmanager
    def lock(self, request_identity: str) -> Iterator[None]:
        filename = self._filename(request_identity, ".lock")
        path = self.locks / filename
        if path.is_symlink():
            raise RuntimeCacheStoreError("runtime-cache lock must not be a symlink")
        self._bounded_entry_count(self.locks)
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise RuntimeCacheStoreError("cannot open runtime-cache lock") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise RuntimeCacheStoreError("runtime-cache lock is not a regular file")
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def read(self, identity: RuntimeIdentity) -> dict[str, Any] | None:
        filename = self._filename(identity.request_identity, ".json")
        path = self.states / filename
        if not path.exists() and not path.is_symlink():
            return None
        try:
            payload = read_json_file(
                self.states, filename, max_bytes=MAX_RUNTIME_CACHE_STATE_BYTES
            )
        except PathPolicyError as exc:
            raise RuntimeCacheStoreError(str(exc)) from exc
        if payload.get("schema_version") != RUNTIME_CACHE_STATE_SCHEMA:
            raise RuntimeCacheStoreError("unsupported runtime-cache state schema")
        try:
            stored_identity = RuntimeIdentity.from_dict(payload.get("identity"))
        except (RuntimeCacheError, TypeError, ValueError) as exc:
            raise RuntimeCacheStoreError("runtime-cache state identity is invalid") from exc
        if stored_identity != identity or payload.get("request_identity") != identity.request_identity:
            raise RuntimeCacheStoreError("runtime-cache state identity mismatch")
        return payload

    def write(self, identity: RuntimeIdentity, payload: dict[str, Any]) -> None:
        filename = self._filename(identity.request_identity, ".json")
        self._bounded_entry_count(self.states)
        value = {
            **payload,
            "schema_version": RUNTIME_CACHE_STATE_SCHEMA,
            "request_identity": identity.request_identity,
            "identity": identity.to_dict(),
        }
        try:
            atomic_write_json(
                self.states,
                filename,
                value,
                max_bytes=MAX_RUNTIME_CACHE_STATE_BYTES,
            )
        except PathPolicyError as exc:
            raise RuntimeCacheStoreError(str(exc)) from exc


class RuntimeCacheResolver:
    def __init__(
        self,
        runtime: ContainerRuntime,
        *,
        data_root: Path,
        provider: ControlledBuildProvider | None = None,
        build_timeout_seconds: int = 6 * 60 * 60,
        retry_delay_seconds: int = 300,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.runtime = runtime
        self.provider = provider
        self.store = RuntimeCacheStateStore(data_root)
        self.build_timeout_seconds = max(60, min(int(build_timeout_seconds), 24 * 60 * 60))
        self.retry_delay_seconds = max(1, min(int(retry_delay_seconds), 24 * 60 * 60))
        self._clock = clock

    def _now(self) -> int:
        return int(self._clock())

    def _verify_image(
        self,
        identity: RuntimeIdentity,
        cache_ref: str,
        *,
        expected_revision: str | None = None,
    ) -> VerifiedImage:
        verified = self.runtime.ensure_image(
            cache_ref, required_labels=identity.required_labels()
        )
        if not isinstance(verified, VerifiedImage) or not IMAGE_ID_RE.fullmatch(
            verified.immutable_ref
        ):
            raise ImageVerificationError(
                "runtime cache did not resolve to a canonical immutable image ID"
            )
        revision = str(verified.get("org.opencontainers.image.revision") or "").lower()
        if not COMMIT_RE.fullmatch(revision):
            raise ImageVerificationError(
                "runtime cache provenance revision is missing or invalid"
            )
        if expected_revision is not None and revision != expected_revision:
            raise ImageVerificationError(
                "runtime cache provenance revision does not match controlled build"
            )
        return verified

    @staticmethod
    def _state_value(payload: dict[str, Any] | None) -> RuntimeCacheState | None:
        if payload is None:
            return None
        try:
            return RuntimeCacheState(str(payload.get("state") or ""))
        except ValueError as exc:
            raise RuntimeCacheStoreError("runtime-cache state value is invalid") from exc

    def _write(
        self,
        identity: RuntimeIdentity,
        cache_ref: str,
        state: RuntimeCacheState,
        **extra: Any,
    ) -> dict[str, Any]:
        payload = {
            "state": state.value,
            "cache_ref": cache_ref,
            "updated_at_epoch": self._now(),
            **extra,
        }
        self.store.write(identity, payload)
        return payload

    def _failed(
        self,
        identity: RuntimeIdentity,
        cache_ref: str,
        code: str,
        detail: str,
        *,
        retryable: bool = True,
    ) -> RuntimeCacheResolution:
        if not FAILURE_CODE_RE.fullmatch(code):
            code = "runtime_cache_failed"
        retry_after = self._now() + self.retry_delay_seconds if retryable else None
        self._write(
            identity,
            cache_ref,
            RuntimeCacheState.FAILED,
            failure_code=code,
            detail=detail,
            retryable=retryable,
            retry_after_epoch=retry_after,
        )
        return RuntimeCacheResolution(
            RuntimeCacheState.FAILED,
            identity.request_identity,
            cache_ref,
            failure_code=code,
            detail=detail,
            retry_after_epoch=retry_after,
        )

    def _provider_failure(
        self,
        identity: RuntimeIdentity,
        cache_ref: str,
        exc: ControlledBuildError,
    ) -> RuntimeCacheResolution:
        if isinstance(exc, ProviderAuthenticationError):
            return self._failed(
                identity,
                cache_ref,
                "provider_authentication_failed",
                "controlled build authentication failed",
            )
        if isinstance(exc, ProviderUnavailableError):
            return self._failed(
                identity,
                cache_ref,
                "provider_unavailable",
                "controlled build provider is unavailable",
            )
        if isinstance(exc, ProviderRequestError):
            return self._failed(
                identity,
                cache_ref,
                "provider_request_failed",
                "controlled build request failed",
            )
        return self._failed(
            identity,
            cache_ref,
            "provider_failed",
            "controlled build provider failed",
        )

    def _building(
        self,
        identity: RuntimeIdentity,
        cache_ref: str,
        payload: dict[str, Any],
        *,
        warning: str | None = None,
    ) -> RuntimeCacheResolution:
        if warning:
            payload = dict(payload)
            payload["warning"] = warning
            payload["updated_at_epoch"] = self._now()
            self.store.write(identity, payload)
        return RuntimeCacheResolution(
            RuntimeCacheState.BUILDING,
            identity.request_identity,
            cache_ref,
            warning=warning or str(payload.get("warning") or "") or None,
        )

    def _start_build(
        self, identity: RuntimeIdentity, cache_ref: str
    ) -> RuntimeCacheResolution:
        if self.provider is None:
            self._write(identity, cache_ref, RuntimeCacheState.BUILD_REQUIRED)
            return RuntimeCacheResolution(
                RuntimeCacheState.BUILD_REQUIRED,
                identity.request_identity,
                cache_ref,
                detail="exact runtime cache is not available",
            )
        started = self._now()
        payload = self._write(
            identity,
            cache_ref,
            RuntimeCacheState.BUILDING,
            provider_namespace=self.provider.namespace,
            provider_handle=None,
            started_at_epoch=started,
            deadline_epoch=started + self.build_timeout_seconds,
        )
        # Reconcile before every submit, including retries after a prior
        # ambiguous transport result. Provider-side acceptance may become
        # visible only after the first reconciliation attempt; submitting first
        # on retry would knowingly permit duplicate builds after restart or
        # eventual-consistency delay.
        try:
            existing = self.provider.reconcile(
                identity, identity.request_identity
            )
        except ControlledBuildError as exc:
            return self._provider_failure(identity, cache_ref, exc)
        if existing is not None:
            if existing.namespace != self.provider.namespace:
                return self._failed(
                    identity,
                    cache_ref,
                    "provider_contract_failed",
                    "controlled build provider returned an incompatible handle",
                    retryable=False,
                )
            payload["provider_handle"] = existing.to_private_dict()
            payload["updated_at_epoch"] = self._now()
            self.store.write(identity, payload)
            return self._building(identity, cache_ref, payload)
        try:
            handle = self.provider.submit(identity, identity.request_identity)
        except ControlledBuildError as exc:
            # The provider may have accepted the request before the transport
            # response was lost. Reconcile by the provider-independent identity
            # before declaring failure so retries cannot knowingly duplicate it.
            try:
                recovered = self.provider.reconcile(
                    identity, identity.request_identity
                )
            except ControlledBuildError:
                recovered = None
            if recovered is not None:
                if recovered.namespace != self.provider.namespace:
                    return self._failed(
                        identity,
                        cache_ref,
                        "provider_contract_failed",
                        "controlled build provider returned an incompatible handle",
                        retryable=False,
                    )
                payload["provider_handle"] = recovered.to_private_dict()
                payload["updated_at_epoch"] = self._now()
                self.store.write(identity, payload)
                return self._building(identity, cache_ref, payload)
            return self._provider_failure(identity, cache_ref, exc)
        if handle.namespace != self.provider.namespace:
            return self._failed(
                identity,
                cache_ref,
                "provider_contract_failed",
                "controlled build provider returned an incompatible handle",
                retryable=False,
            )
        payload["provider_handle"] = handle.to_private_dict()
        payload["updated_at_epoch"] = self._now()
        self.store.write(identity, payload)
        return self._building(identity, cache_ref, payload)

    def _resume_build(
        self,
        identity: RuntimeIdentity,
        cache_ref: str,
        payload: dict[str, Any],
    ) -> RuntimeCacheResolution:
        if self.provider is None:
            return self._failed(
                identity,
                cache_ref,
                "provider_unavailable",
                "controlled build provider is unavailable",
            )
        if payload.get("provider_namespace") != self.provider.namespace:
            return self._failed(
                identity,
                cache_ref,
                "provider_changed",
                "controlled build provider configuration changed",
            )
        try:
            deadline = int(payload.get("deadline_epoch") or 0)
        except (TypeError, ValueError):
            raise RuntimeCacheStoreError("runtime-cache deadline is invalid")
        raw_handle = payload.get("provider_handle")
        handle: ProviderBuildHandle | None = None
        if raw_handle is not None:
            try:
                handle = ProviderBuildHandle.from_private_dict(raw_handle)
            except (TypeError, ValueError) as exc:
                raise RuntimeCacheStoreError("runtime-cache provider handle is invalid") from exc
        if deadline <= self._now():
            if handle is not None:
                try:
                    self.provider.cancel(handle)
                except ControlledBuildError:
                    pass
            return self._failed(
                identity,
                cache_ref,
                "build_timeout",
                "controlled runtime-cache build timed out",
            )
        if handle is None:
            try:
                handle = self.provider.reconcile(identity, identity.request_identity)
            except ProviderPollingError:
                return self._building(
                    identity,
                    cache_ref,
                    payload,
                    warning="controlled build reconciliation is temporarily unavailable",
                )
            except ControlledBuildError as exc:
                return self._provider_failure(identity, cache_ref, exc)
            if handle is None:
                return self._building(
                    identity,
                    cache_ref,
                    payload,
                    warning="controlled build request is awaiting reconciliation",
                )
            payload = dict(payload)
            payload["provider_handle"] = handle.to_private_dict()
            payload["updated_at_epoch"] = self._now()
            self.store.write(identity, payload)
        try:
            status = self.provider.status(
                handle, identity, identity.request_identity
            )
        except ProviderPollingError:
            return self._building(
                identity,
                cache_ref,
                payload,
                warning="controlled build status is temporarily unavailable",
            )
        except ControlledBuildError as exc:
            return self._provider_failure(identity, cache_ref, exc)
        if status.state is ProviderBuildState.BUILDING:
            return self._building(identity, cache_ref, payload)
        if status.state is ProviderBuildState.FAILED:
            code = status.failure_code or "build_failed"
            if not FAILURE_CODE_RE.fullmatch(code):
                code = "build_failed"
            return self._failed(
                identity,
                cache_ref,
                code,
                "controlled runtime-cache build failed",
            )
        if status.state is not ProviderBuildState.SUCCEEDED or status.source_revision is None:
            return self._failed(
                identity,
                cache_ref,
                "provider_contract_failed",
                "controlled build provider returned an invalid success state",
                retryable=False,
            )
        try:
            verified = self._verify_image(
                identity, cache_ref, expected_revision=status.source_revision
            )
        except ImageUnavailableError:
            return self._building(
                identity,
                cache_ref,
                payload,
                warning="verified runtime-cache image is not yet available locally",
            )
        except (ImageVerificationError, RuntimeErrorSafe):
            return self._failed(
                identity,
                cache_ref,
                "image_verification_failed",
                "published runtime-cache image failed immutable verification",
                retryable=False,
            )
        self._write(
            identity,
            cache_ref,
            RuntimeCacheState.READY,
            image_id=verified.immutable_ref,
            source_revision=status.source_revision,
        )
        return RuntimeCacheResolution(
            RuntimeCacheState.READY,
            identity.request_identity,
            cache_ref,
            image=verified,
        )

    def resolve(
        self, identity: RuntimeIdentity, cache_ref: str
    ) -> RuntimeCacheResolution:
        with self.store.lock(identity.request_identity):
            try:
                verified = self._verify_image(identity, cache_ref)
            except ImageUnavailableError:
                verified = None
            except ImageVerificationError:
                return self._failed(
                    identity,
                    cache_ref,
                    "image_verification_failed",
                    "runtime-cache image failed immutable verification",
                    retryable=False,
                )
            except RuntimeErrorSafe:
                return self._failed(
                    identity,
                    cache_ref,
                    "runtime_lookup_failed",
                    "container runtime could not inspect the runtime cache",
                )
            if verified is not None:
                self._write(
                    identity,
                    cache_ref,
                    RuntimeCacheState.READY,
                    image_id=verified.immutable_ref,
                    source_revision=verified.get("org.opencontainers.image.revision"),
                )
                return RuntimeCacheResolution(
                    RuntimeCacheState.READY,
                    identity.request_identity,
                    cache_ref,
                    image=verified,
                )
            payload = self.store.read(identity)
            state = self._state_value(payload)
            if payload is not None and payload.get("cache_ref") != cache_ref:
                raise RuntimeCacheStoreError("runtime-cache reference changed for identity")
            if state is RuntimeCacheState.BUILDING:
                return self._resume_build(identity, cache_ref, payload or {})
            if state is RuntimeCacheState.FAILED:
                retryable = bool((payload or {}).get("retryable"))
                retry_after = int((payload or {}).get("retry_after_epoch") or 0)
                if not retryable or self._now() < retry_after:
                    return RuntimeCacheResolution(
                        RuntimeCacheState.FAILED,
                        identity.request_identity,
                        cache_ref,
                        failure_code=str((payload or {}).get("failure_code") or "runtime_cache_failed"),
                        detail=str((payload or {}).get("detail") or "runtime cache resolution failed"),
                        retry_after_epoch=retry_after or None,
                    )
            return self._start_build(identity, cache_ref)
