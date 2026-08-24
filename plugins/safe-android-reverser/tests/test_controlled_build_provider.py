#!/usr/bin/env python3
from __future__ import annotations

import io
import json
import sys
import unittest
import urllib.error
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
LIB_ROOT = PLUGIN_ROOT / "lib"
if str(LIB_ROOT) not in sys.path:
    sys.path.insert(0, str(LIB_ROOT))

from safe_reverser.controlled_build import (
    GITHUB_API_VERSION,
    BuildAttempt,
    GitHubActionsControlledBuildProvider,
    ProviderAuthenticationError,
    ProviderBuildHandle,
    ProviderBuildState,
    ProviderPollingError,
    ProviderRequestError,
    ProviderSubmissionAmbiguousError,
)
from safe_reverser.runtime_cache import RuntimeIdentity

CREATED_AT = "2023-11-14T22:13:20Z"
CREATED_AT_EPOCH = 1_700_000_000


def identity():
    return RuntimeIdentity(
        dart_version="3.11.1",
        snapshot_hash="a" * 32,
        arch="arm64",
        os="android",
        compressed_pointers=True,
        blutter_commit="b" * 40,
        runtime_cache_schema=3,
        capability_api=1,
        worker_abi=1,
    )


def attempt(value: str = "1" * 32):
    return BuildAttempt(
        attempt_identity=value,
        started_at_epoch=CREATED_AT_EPOCH,
        deadline_epoch=CREATED_AT_EPOCH + 3600,
    )


def dispatch_response(run_id: int = 42):
    return {
        "workflow_run_id": run_id,
        "run_url": (
            "https://api.github.com/repos/salingnh/"
            f"android-reverse-engineering-mcp/actions/runs/{run_id}"
        ),
        "html_url": (
            "https://github.com/salingnh/"
            f"android-reverse-engineering-mcp/actions/runs/{run_id}"
        ),
    }


def run_payload(
    provider,
    runtime_identity,
    build_attempt,
    *,
    run_id: int = 42,
    created_at: str = CREATED_AT,
    status: str = "completed",
    conclusion: str = "success",
):
    return {
        "id": run_id,
        "event": "workflow_dispatch",
        "display_title": provider._run_title(
            runtime_identity.request_identity, build_attempt
        ),
        "created_at": created_at,
        "status": status,
        "conclusion": conclusion,
        "head_sha": "c" * 40,
    }


class FakeResponse:
    def __init__(self, payload, status=200):
        self.status = status
        self.raw = json.dumps(payload).encode("utf-8") if payload is not None else b""

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit):
        return self.raw[:limit]


class QueueOpener:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append((request, timeout))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class GitHubActionsProviderTests(unittest.TestCase):
    def provider(self, opener):
        return GitHubActionsControlledBuildProvider(
            token="stage-a-secret-token",
            repository="salingnh/android-reverse-engineering-mcp",
            workflow="build-flutter-runtime-cache.yml",
            ref="feat/0.4-runtime-cache-resolver",
            opener=opener,
        )

    def test_api_2026_03_10_dispatch_has_exact_current_request_shape(self):
        opener = QueueOpener(FakeResponse(dispatch_response()))
        runtime_identity = identity()
        build_attempt = attempt()
        self.provider(opener).submit(
            runtime_identity, runtime_identity.request_identity, build_attempt
        )
        request = opener.requests[0][0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.headers["X-github-api-version"], GITHUB_API_VERSION)
        payload = json.loads(request.data)
        self.assertEqual(set(payload), {"ref", "inputs"})
        self.assertNotIn("return_run_details", payload)
        self.assertEqual(payload["ref"], "feat/0.4-runtime-cache-resolver")
        inputs = payload["inputs"]
        self.assertEqual(inputs["request_identity"], runtime_identity.request_identity)
        self.assertEqual(inputs["attempt_identity"], build_attempt.attempt_identity)
        self.assertEqual(inputs["dart_version"], "3.11.1")
        self.assertEqual(inputs["snapshot_hash"], "a" * 32)
        self.assertEqual(inputs["arch"], "arm64")
        self.assertEqual(inputs["os"], "android")
        self.assertIs(inputs["compressed_pointers"], True)
        self.assertEqual(inputs["blutter_commit"], "b" * 40)
        self.assertEqual(inputs["runtime_cache_schema"], "3")
        self.assertEqual(inputs["capability_api"], "1")
        self.assertEqual(inputs["worker_abi"], "1")
        self.assertNotIn("stage-a-secret-token", json.dumps(payload))

    def test_api_2026_03_10_http_200_run_details_are_parsed(self):
        opener = QueueOpener(FakeResponse(dispatch_response(77), status=200))
        runtime_identity = identity()
        handle = self.provider(opener).submit(
            runtime_identity, runtime_identity.request_identity, attempt()
        )
        self.assertEqual(handle.opaque_id, "77")
        self.assertIsNone(handle.provider_created_at_epoch)

    def test_api_2026_03_10_invalid_run_details_are_ambiguous(self):
        response = dispatch_response()
        response["run_url"] = "https://api.github.com/wrong-run"
        provider = self.provider(QueueOpener(FakeResponse(response)))
        with self.assertRaises(ProviderSubmissionAmbiguousError):
            provider.submit(identity(), identity().request_identity, attempt())

    def test_namespace_binds_persisted_handle_to_nonsecret_configuration(self):
        first = self.provider(QueueOpener())
        second = GitHubActionsControlledBuildProvider(
            token="rotated-secret-token",
            repository="salingnh/android-reverse-engineering-mcp",
            workflow="build-flutter-runtime-cache.yml",
            ref="feat/0.4-runtime-cache-resolver",
            opener=QueueOpener(),
        )
        changed = GitHubActionsControlledBuildProvider(
            token="stage-a-secret-token",
            repository="salingnh/android-reverse-engineering-mcp",
            workflow="build-flutter-runtime-cache.yml",
            ref="master",
            opener=QueueOpener(),
        )
        self.assertEqual(first.namespace, second.namespace)
        self.assertNotEqual(first.namespace, changed.namespace)
        self.assertNotIn("secret", first.namespace)

    def test_submit_rejects_noncanonical_request_identity(self):
        provider = self.provider(QueueOpener(FakeResponse(dispatch_response())))
        with self.assertRaises(ProviderRequestError):
            provider.submit(identity(), "0" * 64, attempt())

    def test_status_maps_github_state_and_validates_creation_metadata(self):
        runtime_identity = identity()
        build_attempt = attempt()
        provider = self.provider(QueueOpener())
        provider._opener = QueueOpener(
            FakeResponse(run_payload(provider, runtime_identity, build_attempt))
        )
        status = provider.status(
            ProviderBuildHandle(provider.namespace, "42"),
            runtime_identity,
            runtime_identity.request_identity,
            build_attempt,
        )
        self.assertEqual(status.state, ProviderBuildState.SUCCEEDED)
        self.assertEqual(status.source_revision, "c" * 40)

    def test_status_rejects_run_identity_mismatch(self):
        provider = self.provider(
            QueueOpener(
                FakeResponse(
                    {
                        "id": 42,
                        "event": "workflow_dispatch",
                        "display_title": "another attempt",
                        "created_at": CREATED_AT,
                        "status": "queued",
                    }
                )
            )
        )
        with self.assertRaises(ProviderPollingError):
            provider.status(
                ProviderBuildHandle(provider.namespace, "42"),
                identity(),
                identity().request_identity,
                attempt(),
            )

    def test_reconcile_selects_current_attempt_not_historical_attempt(self):
        runtime_identity = identity()
        old_attempt = attempt("2" * 32)
        current_attempt = attempt("3" * 32)
        provider = self.provider(QueueOpener())
        current_run = run_payload(
            provider, runtime_identity, current_attempt, run_id=77
        )
        historical_run = run_payload(
            provider, runtime_identity, old_attempt, run_id=76
        )
        provider._opener = QueueOpener(
            FakeResponse({"workflow_runs": [historical_run, current_run]})
        )
        handle = provider.reconcile(
            runtime_identity,
            runtime_identity.request_identity,
            current_attempt,
        )
        self.assertEqual(handle.opaque_id, "77")
        self.assertEqual(handle.provider_created_at_epoch, CREATED_AT_EPOCH)

    def test_reconcile_rejects_historical_created_at_without_local_now(self):
        runtime_identity = identity()
        build_attempt = attempt()
        provider = self.provider(QueueOpener())
        historical = run_payload(
            provider,
            runtime_identity,
            build_attempt,
            run_id=75,
            created_at="2020-01-01T00:00:00Z",
        )
        provider._opener = QueueOpener(
            FakeResponse({"workflow_runs": [historical]})
        )
        with self.assertRaises(ProviderPollingError):
            provider.reconcile(
                runtime_identity,
                runtime_identity.request_identity,
                build_attempt,
            )

    def test_reconcile_is_bounded_and_rejects_duplicate_current_attempt(self):
        runtime_identity = identity()
        build_attempt = attempt()
        provider = self.provider(QueueOpener())
        duplicate = run_payload(provider, runtime_identity, build_attempt)
        provider._opener = QueueOpener(
            FakeResponse({"workflow_runs": [duplicate, duplicate]})
        )
        with self.assertRaises(ProviderPollingError):
            provider.reconcile(
                runtime_identity,
                runtime_identity.request_identity,
                build_attempt,
            )
        provider._opener = QueueOpener(
            FakeResponse({"workflow_runs": [{} for _item in range(101)]})
        )
        with self.assertRaises(ProviderPollingError):
            provider.reconcile(
                runtime_identity,
                runtime_identity.request_identity,
                build_attempt,
            )

    def test_auth_error_is_redacted(self):
        error = urllib.error.HTTPError(
            "https://api.github.com/redacted",
            401,
            "stage-a-secret-token",
            {},
            io.BytesIO(b"stage-a-secret-token"),
        )
        provider = self.provider(QueueOpener(error))
        with self.assertRaises(ProviderAuthenticationError) as raised:
            provider.submit(identity(), identity().request_identity, attempt())
        self.assertNotIn("stage-a-secret-token", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
