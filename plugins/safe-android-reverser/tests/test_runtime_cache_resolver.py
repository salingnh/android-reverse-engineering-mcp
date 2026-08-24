#!/usr/bin/env python3
from __future__ import annotations

import json
import multiprocessing
import stat
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
LIB_ROOT = PLUGIN_ROOT / "lib"
if str(LIB_ROOT) not in sys.path:
    sys.path.insert(0, str(LIB_ROOT))

from safe_reverser.controlled_build import (
    BuildAttempt,
    ProviderAuthenticationError,
    ProviderBuildHandle,
    ProviderBuildState,
    ProviderBuildStatus,
    ProviderPollingError,
    ProviderRequestError,
    ProviderSubmissionAmbiguousError,
    ProviderUnavailableError,
)
from safe_reverser.runtime import ImageUnavailableError, VerifiedImage
from safe_reverser.runtime_cache import (
    RuntimeCacheResolver,
    RuntimeCacheState,
    RuntimeIdentity,
)

REVISION = "e" * 40
CACHE_REF = "example.invalid/flutter:dart-fixture"


def identity(**changes):
    values = {
        "dart_version": "3.11.1",
        "snapshot_hash": "a" * 32,
        "arch": "arm64",
        "os": "android",
        "compressed_pointers": True,
        "blutter_commit": "b" * 40,
        "runtime_cache_schema": 3,
        "capability_api": 1,
        "worker_abi": 1,
    }
    values.update(changes)
    return RuntimeIdentity(**values)


def image_for(value: RuntimeIdentity, *, revision: str = REVISION, digest: str = "c"):
    labels = value.required_labels()
    labels["org.opencontainers.image.revision"] = revision
    return VerifiedImage(
        requested_ref=CACHE_REF,
        immutable_ref="sha256:" + digest * 64,
        labels=labels,
    )


class FakeClock:
    def __init__(self, value=1_000_000):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class FakeRuntime:
    def __init__(self):
        self.images = {}
        self.ensure_calls = 0
        self.lock = threading.Lock()

    def ensure_image(self, image, *, required_labels):
        with self.lock:
            self.ensure_calls += 1
            value = self.images.get(image)
        if value is None:
            raise ImageUnavailableError("fixture cache miss")
        if isinstance(value, Exception):
            raise value
        for key, expected in required_labels.items():
            if value.labels.get(key) != expected:
                from safe_reverser.runtime import ImageVerificationError

                raise ImageVerificationError("fixture provenance mismatch")
        return value


class AttemptFactory:
    def __init__(self, start=1):
        self.value = start
        self.lock = threading.Lock()

    def __call__(self):
        with self.lock:
            value = self.value
            self.value += 1
        return f"{value:032x}"


class FakeProvider:
    namespace = "fixture-provider-v1"

    def __init__(self, *, clock=time.time):
        self.clock = clock
        self.submit_count = 0
        self.status_count = 0
        self.reconcile_count = 0
        self.cancel_count = 0
        self.submit_error = None
        self.status_error = None
        self.status_value = ProviderBuildStatus(ProviderBuildState.BUILDING)
        self.reconcile_handle = None
        self.reconcile_values = None
        self.submit_delay = 0
        self.status_hook = None
        self.reconcile_hook = None
        self.submitted_attempts = []
        self.status_attempts = []
        self.reconcile_attempts = []
        self.lock = threading.Lock()

    def submit(self, _identity, _request_identity, attempt):
        with self.lock:
            self.submit_count += 1
            self.submitted_attempts.append(attempt)
        if self.submit_delay:
            time.sleep(self.submit_delay)
        if self.submit_error:
            raise self.submit_error
        return ProviderBuildHandle(
            self.namespace, f"fixture-{attempt.attempt_identity}"
        )

    def status(self, _handle, _identity, _request_identity, attempt):
        with self.lock:
            self.status_count += 1
            self.status_attempts.append(attempt)
        if self.status_error:
            raise self.status_error
        if self.status_hook:
            self.status_hook()
        return self.status_value

    def reconcile(self, _identity, _request_identity, attempt):
        self.reconcile_count += 1
        self.reconcile_attempts.append(attempt)
        if self.reconcile_hook is not None:
            return self.reconcile_hook(attempt)
        if self.reconcile_values is not None:
            return self.reconcile_values.pop(0)
        return self.reconcile_handle

    def cancel(self, _handle):
        self.cancel_count += 1


class ProcessProvider:
    namespace = "process-provider-v1"

    def __init__(self, counter_path):
        self.counter_path = Path(counter_path)

    def submit(self, _identity, _request_identity, attempt):
        with self.counter_path.open("a", encoding="utf-8") as handle:
            handle.write(f"submit {attempt.attempt_identity}\n")
        return ProviderBuildHandle(self.namespace, "process-1")

    def status(self, _handle, _identity, _request_identity, _attempt):
        return ProviderBuildStatus(ProviderBuildState.BUILDING)

    def reconcile(self, _identity, _request_identity, _attempt):
        return None

    def cancel(self, _handle):
        return None


def _process_resolve(data_path, counter_path, start_event, result_queue):
    start_event.wait(10)
    resolver = RuntimeCacheResolver(
        FakeRuntime(),
        data_root=Path(data_path),
        provider=ProcessProvider(counter_path),
    )
    result_queue.put(resolver.resolve(identity(), CACHE_REF).state.value)


class RuntimeCacheResolverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data = Path(self.tmp.name)
        self.runtime = FakeRuntime()
        self.clock = FakeClock()
        self.attempts = AttemptFactory()

    def tearDown(self):
        self.tmp.cleanup()

    def resolver(self, provider=None):
        return RuntimeCacheResolver(
            self.runtime,
            data_root=self.data,
            provider=provider,
            build_timeout_seconds=60,
            retry_delay_seconds=5,
            clock=self.clock,
            attempt_identity_factory=self.attempts,
        )

    def test_cache_hit_and_valid_immutable_image_are_ready(self):
        runtime_identity = identity()
        self.runtime.images[CACHE_REF] = image_for(runtime_identity)
        result = self.resolver().resolve(runtime_identity, CACHE_REF)
        self.assertEqual(result.state, RuntimeCacheState.READY)
        self.assertEqual(result.image.immutable_ref, "sha256:" + "c" * 64)

    def test_cache_miss_without_provider_is_build_required(self):
        result = self.resolver().resolve(identity(), CACHE_REF)
        self.assertEqual(result.state, RuntimeCacheState.BUILD_REQUIRED)

    def test_cache_miss_with_provider_requests_one_build(self):
        provider = FakeProvider(clock=self.clock)
        result = self.resolver(provider).resolve(identity(), CACHE_REF)
        self.assertEqual(result.state, RuntimeCacheState.BUILDING)
        self.assertEqual(provider.submit_count, 1)
        self.assertEqual(provider.reconcile_count, 1)

    def test_existing_provider_request_is_reconciled_before_submit(self):
        provider = FakeProvider(clock=self.clock)
        provider.reconcile_handle = ProviderBuildHandle(
            provider.namespace, "existing-request", int(self.clock())
        )
        result = self.resolver(provider).resolve(identity(), CACHE_REF)
        self.assertEqual(result.state, RuntimeCacheState.BUILDING)
        self.assertEqual(provider.reconcile_count, 1)
        self.assertEqual(provider.submit_count, 0)

    def test_successful_build_is_verified_before_ready(self):
        runtime_identity = identity()
        provider = FakeProvider(clock=self.clock)
        resolver = self.resolver(provider)
        self.assertEqual(
            resolver.resolve(runtime_identity, CACHE_REF).state,
            RuntimeCacheState.BUILDING,
        )
        provider.status_value = ProviderBuildStatus(
            ProviderBuildState.SUCCEEDED, source_revision=REVISION
        )
        provider.status_hook = lambda: self.runtime.images.__setitem__(
            CACHE_REF, image_for(runtime_identity)
        )
        result = resolver.resolve(runtime_identity, CACHE_REF)
        self.assertEqual(result.state, RuntimeCacheState.READY)
        self.assertTrue(result.image.immutable_ref.startswith("sha256:"))

    def test_provider_unavailable_authentication_and_request_failures(self):
        cases = (
            (ProviderUnavailableError("secret"), "provider_unavailable"),
            (ProviderAuthenticationError("secret"), "provider_authentication_failed"),
            (ProviderRequestError("secret"), "provider_request_failed"),
        )
        for index, (error, code) in enumerate(cases):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as data:
                provider = FakeProvider(clock=self.clock)
                provider.submit_error = error
                resolver = RuntimeCacheResolver(
                    self.runtime,
                    data_root=Path(data),
                    provider=provider,
                    retry_delay_seconds=5,
                    clock=self.clock,
                )
                result = resolver.resolve(identity(snapshot_hash=f"{index + 1:032x}"), CACHE_REF)
                self.assertEqual(result.state, RuntimeCacheState.FAILED)
                self.assertEqual(result.failure_code, code)
                self.assertNotIn("secret", json.dumps(result.public_status()))

    def test_build_failure(self):
        provider = FakeProvider(clock=self.clock)
        resolver = self.resolver(provider)
        resolver.resolve(identity(), CACHE_REF)
        provider.status_value = ProviderBuildStatus(
            ProviderBuildState.FAILED,
            failure_code="build_failed",
            detail="untrusted provider detail",
        )
        result = resolver.resolve(identity(), CACHE_REF)
        self.assertEqual(result.state, RuntimeCacheState.FAILED)
        self.assertEqual(result.failure_code, "build_failed")
        self.assertNotIn("untrusted", result.detail)

    def test_build_timeout_is_persistent_and_cancel_is_best_effort(self):
        provider = FakeProvider(clock=self.clock)
        resolver = self.resolver(provider)
        resolver.resolve(identity(), CACHE_REF)
        self.clock.advance(61)
        result = resolver.resolve(identity(), CACHE_REF)
        self.assertEqual(result.failure_code, "build_timeout")
        self.assertEqual(provider.cancel_count, 1)

    def test_status_polling_failure_keeps_building(self):
        provider = FakeProvider(clock=self.clock)
        resolver = self.resolver(provider)
        resolver.resolve(identity(), CACHE_REF)
        provider.status_error = ProviderPollingError("credential-never-copy")
        result = resolver.resolve(identity(), CACHE_REF)
        self.assertEqual(result.state, RuntimeCacheState.BUILDING)
        self.assertIn("temporarily", result.warning)
        self.assertNotIn("credential-never-copy", result.warning)

    def test_historical_failed_attempt_retry_creates_new_attempt(self):
        provider = FakeProvider(clock=self.clock)
        provider.submit_error = ProviderRequestError("failed")
        resolver = self.resolver(provider)
        first = resolver.resolve(identity(), CACHE_REF)
        request_identity = first.request_identity
        self.assertEqual(first.state, RuntimeCacheState.FAILED)
        self.assertEqual(provider.submit_count, 1)
        first_attempt = provider.submitted_attempts[0].attempt_identity
        self.assertEqual(resolver.resolve(identity(), CACHE_REF).state, RuntimeCacheState.FAILED)
        self.assertEqual(provider.submit_count, 1)
        self.clock.advance(5)
        provider.submit_error = None
        retry = resolver.resolve(identity(), CACHE_REF)
        self.assertEqual(retry.state, RuntimeCacheState.BUILDING)
        self.assertEqual(provider.submit_count, 2)
        self.assertEqual(retry.request_identity, request_identity)
        self.assertNotEqual(
            provider.submitted_attempts[1].attempt_identity, first_attempt
        )

    def test_ambiguous_submit_reconciles_same_current_attempt(self):
        provider = FakeProvider(clock=self.clock)
        provider.submit_error = ProviderSubmissionAmbiguousError(
            "ambiguous transport result"
        )
        provider.reconcile_values = [
            None,
            ProviderBuildHandle(provider.namespace, "accepted-current-attempt"),
        ]
        result = self.resolver(provider).resolve(identity(), CACHE_REF)
        self.assertEqual(result.state, RuntimeCacheState.BUILDING)
        self.assertEqual(provider.submit_count, 1)
        self.assertEqual(provider.reconcile_count, 2)
        submitted = provider.submitted_attempts[0].attempt_identity
        self.assertEqual(
            {item.attempt_identity for item in provider.reconcile_attempts},
            {submitted},
        )

    def test_restart_resumes_persisted_build(self):
        provider = FakeProvider(clock=self.clock)
        first = self.resolver(provider)
        first.resolve(identity(), CACHE_REF)
        second = self.resolver(provider)
        result = second.resolve(identity(), CACHE_REF)
        self.assertEqual(result.state, RuntimeCacheState.BUILDING)
        self.assertEqual(provider.submit_count, 1)
        self.assertEqual(provider.status_count, 1)

    def test_lost_handle_is_reconciled_after_restart(self):
        runtime_identity = identity()
        provider = FakeProvider(clock=self.clock)
        provider.reconcile_handle = ProviderBuildHandle(
            provider.namespace, "recovered", int(self.clock())
        )
        resolver = self.resolver(provider)
        with resolver.store.lock(runtime_identity.request_identity):
            resolver.store.write(
                runtime_identity,
                {
                    "state": "BUILDING",
                    "cache_ref": CACHE_REF,
                    "provider_namespace": provider.namespace,
                    "provider_handle": None,
                    "build_attempt": BuildAttempt(
                        "4" * 32,
                        int(self.clock()),
                        int(self.clock()) + 60,
                    ).to_private_dict(),
                    "updated_at_epoch": int(self.clock()),
                },
            )
        result = resolver.resolve(runtime_identity, CACHE_REF)
        self.assertEqual(result.state, RuntimeCacheState.BUILDING)
        self.assertEqual(provider.reconcile_count, 1)
        self.assertEqual(provider.status_count, 1)

    def test_lost_submit_response_reconciles_before_failure_or_retry(self):
        provider = FakeProvider(clock=self.clock)
        provider.submit_error = ProviderSubmissionAmbiguousError(
            "ambiguous transport result"
        )
        provider.reconcile_values = [
            None,
            ProviderBuildHandle(
                provider.namespace, "accepted-before-disconnect", int(self.clock())
            ),
        ]
        result = self.resolver(provider).resolve(identity(), CACHE_REF)
        self.assertEqual(result.state, RuntimeCacheState.BUILDING)
        self.assertEqual(provider.submit_count, 1)
        self.assertEqual(provider.reconcile_count, 2)

    def test_ambiguous_submit_restart_recovers_same_current_attempt(self):
        provider = FakeProvider(clock=self.clock)
        provider.submit_error = ProviderSubmissionAmbiguousError(
            "response lost after acceptance"
        )
        provider.reconcile_values = [None, None]
        first_resolver = self.resolver(provider)
        first = first_resolver.resolve(identity(), CACHE_REF)
        self.assertEqual(first.state, RuntimeCacheState.BUILDING)
        persisted = first_resolver.store.read(identity())
        current_attempt = BuildAttempt.from_private_dict(
            persisted["build_attempt"]
        )

        resumed_provider = FakeProvider(clock=self.clock)
        resumed_provider.reconcile_hook = lambda value: (
            ProviderBuildHandle(resumed_provider.namespace, "recovered-after-restart")
            if value.attempt_identity == current_attempt.attempt_identity
            else None
        )
        resumed = self.resolver(resumed_provider).resolve(identity(), CACHE_REF)
        self.assertEqual(resumed.state, RuntimeCacheState.BUILDING)
        self.assertEqual(resumed_provider.submit_count, 0)
        self.assertEqual(
            resumed_provider.reconcile_attempts[0].attempt_identity,
            current_attempt.attempt_identity,
        )

    def test_historical_success_without_image_eventually_retries_new_attempt(self):
        runtime_identity = identity()
        provider = FakeProvider(clock=self.clock)
        resolver = self.resolver(provider)
        first = resolver.resolve(runtime_identity, CACHE_REF)
        self.assertEqual(first.state, RuntimeCacheState.BUILDING)
        first_attempt = provider.submitted_attempts[0]
        provider.status_value = ProviderBuildStatus(
            ProviderBuildState.SUCCEEDED, source_revision=REVISION
        )
        waiting = resolver.resolve(runtime_identity, CACHE_REF)
        self.assertEqual(waiting.state, RuntimeCacheState.BUILDING)
        self.assertIn("not yet available", waiting.warning)
        self.clock.advance(61)
        timed_out = resolver.resolve(runtime_identity, CACHE_REF)
        self.assertEqual(timed_out.failure_code, "build_timeout")
        self.clock.advance(5)
        retry = resolver.resolve(runtime_identity, CACHE_REF)
        self.assertEqual(retry.state, RuntimeCacheState.BUILDING)
        self.assertEqual(retry.request_identity, first.request_identity)
        self.assertEqual(provider.submit_count, 2)
        self.assertNotEqual(
            provider.submitted_attempts[1].attempt_identity,
            first_attempt.attempt_identity,
        )

    def test_concurrent_calls_submit_exactly_one_build(self):
        provider = FakeProvider(clock=self.clock)
        provider.submit_delay = 0.05
        resolver = self.resolver(provider)
        barrier = threading.Barrier(8)

        def call():
            barrier.wait()
            return resolver.resolve(identity(), CACHE_REF).state

        with ThreadPoolExecutor(max_workers=8) as pool:
            states = list(pool.map(lambda _item: call(), range(8)))
        self.assertEqual(set(states), {RuntimeCacheState.BUILDING})
        self.assertEqual(provider.submit_count, 1)
        self.assertEqual(len(provider.submitted_attempts), 1)

    def test_concurrent_processes_submit_exactly_one_build(self):
        context = multiprocessing.get_context("fork")
        start = context.Event()
        results = context.Queue()
        counter = self.data / "submissions.txt"
        processes = [
            context.Process(
                target=_process_resolve,
                args=(str(self.data), str(counter), start, results),
            )
            for _item in range(3)
        ]
        for process in processes:
            process.start()
        start.set()
        states = [results.get(timeout=10) for _item in processes]
        for process in processes:
            process.join(timeout=10)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(set(states), {"BUILDING"})
        lines = counter.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertRegex(lines[0], r"^submit [0-9a-f]{32}$")

    def test_published_image_wins_before_provider_reconciliation(self):
        runtime_identity = identity()
        provider = FakeProvider(clock=self.clock)
        resolver = self.resolver(provider)
        resolver.resolve(runtime_identity, CACHE_REF)
        self.runtime.images[CACHE_REF] = image_for(runtime_identity)
        result = resolver.resolve(runtime_identity, CACHE_REF)
        self.assertEqual(result.state, RuntimeCacheState.READY)
        self.assertEqual(provider.status_count, 0)

    def test_every_exact_identity_label_mismatch_is_rejected(self):
        baseline = identity()
        self.runtime.images[CACHE_REF] = image_for(baseline)
        mismatches = {
            "dart_version": "3.11.2",
            "snapshot_hash": "d" * 32,
            "arch": "x86_64",
            "os": "linux",
            "compressed_pointers": False,
            "blutter_commit": "f" * 40,
            "runtime_cache_schema": 4,
            "capability_api": 2,
            "worker_abi": 2,
        }
        for field, value in mismatches.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as data:
                resolver = RuntimeCacheResolver(self.runtime, data_root=Path(data))
                result = resolver.resolve(identity(**{field: value}), CACHE_REF)
                self.assertEqual(result.state, RuntimeCacheState.FAILED)
                self.assertEqual(result.failure_code, "image_verification_failed")

    def test_wrong_mutable_collision_and_revision_are_rejected(self):
        runtime_identity = identity()
        self.runtime.images[CACHE_REF] = image_for(
            runtime_identity, revision="not-a-revision"
        )
        result = self.resolver().resolve(runtime_identity, CACHE_REF)
        self.assertEqual(result.failure_code, "image_verification_failed")

    def test_provider_success_revision_must_match_image(self):
        runtime_identity = identity()
        provider = FakeProvider(clock=self.clock)
        resolver = self.resolver(provider)
        resolver.resolve(runtime_identity, CACHE_REF)
        provider.status_value = ProviderBuildStatus(
            ProviderBuildState.SUCCEEDED, source_revision=REVISION
        )
        provider.status_hook = lambda: self.runtime.images.__setitem__(
            CACHE_REF, image_for(runtime_identity, revision="f" * 40)
        )
        result = resolver.resolve(runtime_identity, CACHE_REF)
        self.assertEqual(result.failure_code, "image_verification_failed")

    def test_credential_text_is_absent_from_private_state(self):
        secret = "ghp_fixture_should_never_persist"
        provider = FakeProvider(clock=self.clock)
        provider.submit_error = ProviderRequestError(secret)
        result = self.resolver(provider).resolve(identity(), CACHE_REF)
        self.assertNotIn(secret, json.dumps(result.public_status()))
        state_text = "".join(
            path.read_text(encoding="utf-8")
            for path in self.data.rglob("*.json")
        )
        self.assertNotIn(secret, state_text)

    def test_attempt_identity_is_private_but_persisted_before_submit(self):
        provider = FakeProvider(clock=self.clock)
        provider.submit_error = ProviderSubmissionAmbiguousError("lost response")
        provider.reconcile_values = [None, None]
        resolver = self.resolver(provider)
        result = resolver.resolve(identity(), CACHE_REF)
        persisted = resolver.store.read(identity())
        attempt_identity = persisted["build_attempt"]["attempt_identity"]
        self.assertRegex(attempt_identity, r"^[0-9a-f]{32}$")
        self.assertEqual(
            attempt_identity, provider.submitted_attempts[0].attempt_identity
        )
        self.assertNotIn(attempt_identity, json.dumps(result.public_status()))

    def test_persistent_state_and_locks_are_private(self):
        self.resolver().resolve(identity(), CACHE_REF)
        for path in self.data.rglob("*"):
            if path.is_file():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
