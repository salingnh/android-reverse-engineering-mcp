#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PLUGIN_ROOT.parents[1]
LIB_ROOT = PLUGIN_ROOT / "lib"
if str(LIB_ROOT) not in sys.path:
    sys.path.insert(0, str(LIB_ROOT))

from safe_reverser import CAPABILITY_API_VERSION, WORKER_ABI_VERSION
from safe_reverser.flutter import RUNTIME_CACHE_SCHEMA
from safe_reverser.runtime_cache import RuntimeIdentity


def _load_flutter_cache_identity():
    path = REPO_ROOT / "frameworks" / "flutter" / "cache_identity.py"
    spec = importlib.util.spec_from_file_location("flutter_cache_identity_contract", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Flutter cache identity module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CrossWorkerContractTests(unittest.TestCase):
    def test_flutter_cache_identity_matches_host_platform_contract(self):
        cache = _load_flutter_cache_identity()
        self.assertEqual(cache.CAPABILITY_API_VERSION, CAPABILITY_API_VERSION)
        self.assertEqual(cache.WORKER_ABI_VERSION, WORKER_ABI_VERSION)
        self.assertEqual(cache.CACHE_SCHEMA_VERSION, RUNTIME_CACHE_SCHEMA)

    def test_runtime_cache_tag_changes_when_platform_abi_changes(self):
        cache = _load_flutter_cache_identity()
        kwargs = {
            "dart_version": "3.5.4",
            "snapshot_hash": "a" * 32,
            "arch": "arm64",
            "os_name": "android",
            "compressed_pointers": True,
            "blutter_commit": "b" * 40,
        }
        baseline = cache.runtime_cache_tag(**kwargs)
        old = cache.WORKER_ABI_VERSION
        cache.WORKER_ABI_VERSION = old + 1
        try:
            changed = cache.runtime_cache_tag(**kwargs)
        finally:
            cache.WORKER_ABI_VERSION = old
        self.assertNotEqual(baseline, changed)

    def test_worker_and_host_derive_the_same_exact_cache_tag(self):
        cache = _load_flutter_cache_identity()
        runtime = RuntimeIdentity(
            dart_version="3.11.1",
            snapshot_hash="a" * 32,
            arch="arm64",
            os="android",
            compressed_pointers=True,
            blutter_commit="b" * 40,
            runtime_cache_schema=RUNTIME_CACHE_SCHEMA,
            capability_api=CAPABILITY_API_VERSION,
            worker_abi=WORKER_ABI_VERSION,
        )
        self.assertEqual(
            runtime.cache_tag,
            cache.runtime_cache_tag(
                dart_version=runtime.dart_version,
                snapshot_hash=runtime.snapshot_hash,
                arch=runtime.arch,
                os_name=runtime.os,
                compressed_pointers=runtime.compressed_pointers,
                blutter_commit=runtime.blutter_commit,
            ),
        )
        self.assertEqual(
            runtime.request_identity,
            cache.runtime_request_identity(
                dart_version=runtime.dart_version,
                snapshot_hash=runtime.snapshot_hash,
                arch=runtime.arch,
                os_name=runtime.os,
                compressed_pointers=runtime.compressed_pointers,
                blutter_commit=runtime.blutter_commit,
            ),
        )


if __name__ == "__main__":
    unittest.main()
