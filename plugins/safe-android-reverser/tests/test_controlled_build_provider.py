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
    GitHubActionsControlledBuildProvider,
    ProviderAuthenticationError,
    ProviderBuildState,
    ProviderPollingError,
)
from safe_reverser.runtime_cache import RuntimeIdentity


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
            clock=lambda: 1234,
        )

    def test_submit_translates_exact_identity_behind_provider_boundary(self):
        opener = QueueOpener(FakeResponse({"workflow_run_id": 42}))
        runtime_identity = identity()
        handle = self.provider(opener).submit(
            runtime_identity, runtime_identity.request_identity
        )
        self.assertEqual(handle.opaque_id, "42")
        request = opener.requests[0][0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.headers["X-github-api-version"], GITHUB_API_VERSION)
        payload = json.loads(request.data)
        self.assertEqual(payload["ref"], "feat/0.4-runtime-cache-resolver")
        inputs = payload["inputs"]
        self.assertEqual(inputs["request_identity"], runtime_identity.request_identity)
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

    def test_submit_rejects_noncanonical_request_identity(self):
        provider = self.provider(QueueOpener(FakeResponse({"workflow_run_id": 42})))
        from safe_reverser.controlled_build import ProviderRequestError

        with self.assertRaises(ProviderRequestError):
            provider.submit(identity(), "0" * 64)

    def test_status_maps_github_state_to_provider_neutral_state(self):
        runtime_identity = identity()
        title = f"Runtime cache {runtime_identity.request_identity}"
        opener = QueueOpener(
            FakeResponse(
                {
                    "event": "workflow_dispatch",
                    "display_title": title,
                    "status": "completed",
                    "conclusion": "success",
                    "head_sha": "c" * 40,
                }
            )
        )
        provider = self.provider(opener)
        from safe_reverser.controlled_build import ProviderBuildHandle

        status = provider.status(
            ProviderBuildHandle(provider.namespace, "42", 1234),
            runtime_identity,
            runtime_identity.request_identity,
        )
        self.assertEqual(status.state, ProviderBuildState.SUCCEEDED)
        self.assertEqual(status.source_revision, "c" * 40)

    def test_status_rejects_run_identity_mismatch(self):
        opener = QueueOpener(
            FakeResponse(
                {
                    "event": "workflow_dispatch",
                    "display_title": "another request",
                    "status": "queued",
                }
            )
        )
        provider = self.provider(opener)
        from safe_reverser.controlled_build import ProviderBuildHandle

        with self.assertRaises(ProviderPollingError):
            provider.status(
                ProviderBuildHandle(provider.namespace, "42", 1234),
                identity(),
                identity().request_identity,
            )

    def test_reconcile_finds_request_by_provider_independent_identity(self):
        runtime_identity = identity()
        title = f"Runtime cache {runtime_identity.request_identity}"
        opener = QueueOpener(
            FakeResponse(
                {
                    "workflow_runs": [
                        {"id": 77, "display_title": title},
                        {"id": 76, "display_title": "Runtime cache unrelated"},
                    ]
                }
            )
        )
        handle = self.provider(opener).reconcile(
            runtime_identity, runtime_identity.request_identity
        )
        self.assertEqual(handle.opaque_id, "77")
        self.assertIn("event=workflow_dispatch", opener.requests[0][0].full_url)

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
            provider.submit(identity(), identity().request_identity)
        self.assertNotIn("stage-a-secret-token", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
