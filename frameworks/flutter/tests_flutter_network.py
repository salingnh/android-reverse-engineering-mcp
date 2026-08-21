#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import flutter_network as network
import flutter_semantic as semantic


class FlutterNetworkModelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "job"
        (self.root / "asm" / "app").mkdir(parents=True)
        (self.root / "asm" / "app" / "api.dart").write_text(
            """// lib: , url: package:app/api.dart

// class id: 101, size: 0x20
class ApiClient extends Object {
  Future login(String user) {
    // ** addr: 0x1234, size: 0x50
    0x1234: bl 0x2000 ; [package:dio/src/dio.dart] Dio::post -> Future
    // \"https://api.example.com/v1/login?token=super-secret&lang=en\"
    // \"/api/v1/profile?access_token=do-not-return\"
    // \"Authorization: Bearer super-secret-token\"
    // \"Content-Type\"
    // \"HMAC-SHA256\"
    // \"AES encrypt\"
  }
}
""",
            encoding="utf-8",
        )
        (self.root / "asm" / "app" / "third_party.dart").write_text(
            """// lib: , url: package:app/third_party.dart
// class id: 102, size: 0x20
class Telemetry extends Object {
  void send() {
    // ** addr: 0x2000, size: 0x20
    // \"https://api.segment.io/v1/batch\"
  }
}
""",
            encoding="utf-8",
        )
        (self.root / "asm" / "dio").mkdir(parents=True)
        (self.root / "asm" / "dio" / "dio.dart").write_text(
            """// lib: , url: package:dio/src/dio.dart
// class id: 201, size: 0x20
class Dio extends Object {
  Future post(String path) {
    // ** addr: 0x3000, size: 0x20
  }
}
""",
            encoding="utf-8",
        )
        (self.root / "pp.txt").write_text(
            '0x10: "refresh_token"\n'
            '0x18: "X-Signature"\n'
            '0x20: "PBKDF2"\n',
            encoding="utf-8",
        )
        (self.root / "objs.txt").write_text(
            'Object: "wss://socket.example.com/ws?auth=secret"\n',
            encoding="utf-8",
        )
        self.index = self.root / "flutter-index.sqlite"
        semantic.build_flutter_index(
            self.root,
            self.index,
            analysis_id="flutter-aot:" + "b" * 64,
            artifact_sha256="a" * 64,
            blutter_commit="c" * 40,
            runtime={"dart_version": "3.5.4", "arch": "arm64"},
            image_version="0.3.0-test",
            build_commit="f" * 40,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def model(self, limit=100):
        return network.extract_flutter_network_model(self.index, limit=limit)

    def test_extracts_sanitized_first_party_endpoint_with_function_context(self):
        result = self.model()
        endpoint = next(
            item for item in result["endpoints"]
            if item.get("host") == "api.example.com"
        )
        self.assertEqual(endpoint["classification"], "first-party-candidate")
        self.assertEqual(endpoint["path"], "/v1/login")
        self.assertEqual(endpoint["query_keys"], ["token", "lang"])
        self.assertNotIn("super-secret", endpoint["sanitized_url"])
        self.assertEqual(endpoint["evidence"]["function"]["name"], "login")
        self.assertEqual(
            endpoint["evidence"]["function"]["native_offset_hex"], "0x1234"
        )

    def test_known_third_party_host_is_classified_conservatively(self):
        result = self.model()
        host = next(item for item in result["hosts"] if item["host"] == "api.segment.io")
        self.assertEqual(host["classification"], "known-third-party")

    def test_path_candidate_keeps_query_keys_but_not_values(self):
        result = self.model()
        endpoint = next(
            item for item in result["endpoints"]
            if item.get("classification") == "path-candidate"
            and item["path"] == "/api/v1/profile"
        )
        self.assertEqual(endpoint["query_keys"], ["access_token"])
        self.assertNotIn("do-not-return", json.dumps(endpoint))

    def test_auth_signing_crypto_signals_never_return_secret_literal(self):
        result = self.model()
        encoded = json.dumps(
            {
                "headers": result["headers"],
                "auth": result["auth_signals"],
                "signing": result["signing_signals"],
                "crypto": result["crypto_signals"],
            }
        )
        self.assertNotIn("super-secret-token", encoded)
        self.assertTrue(
            any(item["signal"] == "bearer-auth" for item in result["auth_signals"])
        )
        self.assertTrue(
            any(item["signal"] == "refresh-token" for item in result["auth_signals"])
        )
        self.assertTrue(
            any(item["signal"] == "hmac" for item in result["signing_signals"])
        )
        self.assertTrue(
            any(item["signal"] == "pbkdf2" for item in result["crypto_signals"])
        )
        self.assertTrue(
            all(item["secret_value_returned"] is False for item in result["auth_signals"])
        )

    def test_headers_return_names_not_header_values(self):
        result = self.model()
        names = {item["name"] for item in result["headers"]}
        self.assertIn("Authorization", names)
        self.assertIn("Content-Type", names)
        self.assertIn("X-Signature", names)

    def test_http_client_xref_identifies_calling_app_function(self):
        result = self.model()
        xref = next(
            item for item in result["http_clients"]
            if item["client"] == "dio"
            and item["evidence_kind"] == "xref-call-adjacency"
        )
        self.assertEqual(xref["caller"]["name"], "login")
        self.assertEqual(xref["caller"]["native_offset_hex"], "0x1234")
        self.assertEqual(xref["target"]["library_url"], "package:dio/src/dio.dart")

    def test_object_pool_endpoint_has_no_fabricated_function_owner(self):
        result = self.model()
        endpoint = next(
            item for item in result["endpoints"]
            if item.get("host") == "socket.example.com"
        )
        self.assertIsNone(endpoint["evidence"]["function"])
        self.assertIn("auth", endpoint["query_keys"])
        self.assertNotIn("secret", endpoint["sanitized_url"])

    def test_provenance_and_flow_limitation_are_preserved(self):
        result = self.model()
        self.assertEqual(result["provenance"]["artifact_sha256"], "a" * 64)
        self.assertEqual(result["provenance"]["blutter_commit"], "c" * 40)
        self.assertEqual(result["provenance"]["image_version"], "0.3.0-test")
        self.assertIn("not proof of value flow", result["limitations"][0])

    def test_category_limit_is_hard_bounded_and_reports_truncation(self):
        result = self.model(limit=1)
        self.assertLessEqual(len(result["endpoints"]), 1)
        self.assertEqual(result["limit_per_category"], 1)
        self.assertTrue(result["endpoints_truncated"])

    def test_secret_like_path_segment_is_redacted(self):
        endpoint = network._safe_endpoint_from_url(
            "https://api.example.com/users/0123456789abcdef0123456789abcdef?x=y"
        )
        self.assertIsNotNone(endpoint)
        self.assertEqual(endpoint["path"], "/users/{redacted}")
        self.assertNotIn("0123456789abcdef", endpoint["sanitized_url"])

    def test_url_userinfo_is_not_returned(self):
        endpoint = network._safe_endpoint_from_url(
            "https://alice:password@example.com/api/v1"
        )
        self.assertEqual(endpoint["sanitized_url"], "https://example.com/api/v1")
        self.assertNotIn("alice", json.dumps(endpoint))
        self.assertNotIn("password", json.dumps(endpoint))

    def test_secret_like_query_key_is_redacted(self):
        endpoint = network._safe_endpoint_from_url(
            "https://api.example.com/v1?eyJ012345678901234567890123456789=value"
        )
        self.assertEqual(endpoint["query_keys"], ["{redacted-key}"])
        self.assertNotIn("eyJ0123456789", json.dumps(endpoint))

    def test_percent_encoded_secret_path_segment_is_redacted(self):
        endpoint = network._safe_endpoint_from_url(
            "https://api.example.com/users/%30%31%32%33%34%35%36%37%38%39%61%62%63%64%65%66%30%31%32%33%34%35%36%37%38%39%61%62%63%64%65%66"
        )
        self.assertEqual(endpoint["path"], "/users/{redacted}")

    def test_short_crypto_terms_require_token_boundaries(self):
        self.assertEqual(network._keyword_hits("versatile", network.CRYPTO_TERMS), [])
        self.assertIn("rsa", network._keyword_hits("RSA encrypt", network.CRYPTO_TERMS))
        self.assertIn("aes", network._keyword_hits("AES/GCM", network.CRYPTO_TERMS))

    def test_package_specific_http_client_library_is_sufficient_evidence(self):
        self.assertEqual(
            network._client_name("package:http/src/client.dart", "Response", "get"),
            "package:http",
        )
        self.assertIsNone(network._client_name("dart:io", "File", "open"))

    def test_candidate_text_memory_budget_is_reported(self):
        with mock.patch.object(network, "MAX_CANDIDATE_TEXT_BYTES", 1):
            result = self.model()
        self.assertTrue(result["scan"]["candidate_text_bytes_truncated"])
        self.assertEqual(result["scan"]["candidate_text_bytes_limit"], 1)

    def test_wall_clock_budget_interrupts_analysis(self):
        with mock.patch.object(network, "MAX_NETWORK_SECONDS", -1.0):
            with self.assertRaises(network.FlutterNetworkError):
                self.model()

    def test_model_does_not_return_raw_candidate_string_values(self):
        result = self.model()
        encoded = json.dumps(result)
        self.assertNotIn("do-not-return", encoded)
        self.assertNotIn("super-secret-token", encoded)


if __name__ == "__main__":
    unittest.main()
