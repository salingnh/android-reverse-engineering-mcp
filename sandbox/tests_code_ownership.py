#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pu_ownership as ownership


MANIFEST = '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
  <application android:name=".App">
    <activity android:name=".MainActivity" />
    <service android:name="a.a" />
    <provider android:name="com.google.firebase.provider.FirebaseInitProvider" />
  </application>
</manifest>
'''


class CodeOwnershipTests(unittest.TestCase):
    def make_job(self, manifest: str | None = MANIFEST):
        tmp = tempfile.TemporaryDirectory()
        job = Path(tmp.name) / "job"
        job.mkdir()
        if manifest is not None:
            target = job / "jadx" / "resources"
            target.mkdir(parents=True)
            (target / "AndroidManifest.xml").write_text(manifest, encoding="utf-8")
        return tmp, job

    def test_manifest_context_is_bounded_and_resolves_components(self):
        tmp, job = self.make_job()
        try:
            context = ownership.ownership_context(job)
            self.assertEqual(context.application_package, "com.example.app")
            self.assertEqual(context.manifest_status, "parsed")
            self.assertIn("com.example.app.App", context.manifest_components)
            self.assertIn("com.example.app.MainActivity", context.manifest_components)
            self.assertIn("a.a", context.manifest_components)
            self.assertIn(
                "com.google.firebase.provider.FirebaseInitProvider",
                context.manifest_components,
            )
        finally:
            tmp.cleanup()

    def test_first_party_vendor_platform_generated_and_unknown_are_distinct(self):
        tmp, job = self.make_job()
        try:
            classifier = ownership.CodeOwnershipClassifier.for_job(job)
            self.assertEqual(
                classifier.classify("com.example.app.auth.LoginRepository")["scope"],
                "FIRST_PARTY",
            )
            firebase = classifier.classify("com.google.firebase.auth.FirebaseAuth")
            self.assertEqual(firebase["scope"], "THIRD_PARTY")
            self.assertEqual(firebase["sdk"], "Firebase")
            self.assertEqual(
                classifier.classify("android.app.Activity")["scope"], "PLATFORM"
            )
            self.assertEqual(
                classifier.classify("androidx.lifecycle.ViewModel")["scope"],
                "PLATFORM",
            )
            self.assertEqual(
                classifier.classify("com.example.app.Hilt_MainActivity")["scope"],
                "GENERATED",
            )
            self.assertEqual(
                classifier.classify("com.example.app.DaggerAppComponent")["scope"],
                "GENERATED",
            )
            self.assertEqual(
                classifier.classify("z.q.HiddenThing")["scope"], "UNKNOWN"
            )
        finally:
            tmp.cleanup()

    def test_obfuscated_manifest_component_is_first_party_without_namespace_guessing(self):
        tmp, job = self.make_job()
        try:
            classifier = ownership.CodeOwnershipClassifier.for_job(job)
            result = classifier.classify("a.a")
            self.assertEqual(result["scope"], "FIRST_PARTY")
            self.assertIn("manifest_component", result["classification_reasons"])
            unknown = classifier.classify("b.c")
            self.assertEqual(unknown["scope"], "UNKNOWN")
        finally:
            tmp.cleanup()

    def test_merged_vendor_manifest_component_stays_third_party(self):
        tmp, job = self.make_job()
        try:
            result = ownership.CodeOwnershipClassifier.for_job(job).classify(
                "com.google.firebase.provider.FirebaseInitProvider"
            )
            self.assertEqual(result["scope"], "THIRD_PARTY")
            self.assertEqual(result["sdk"], "Firebase")
            self.assertNotIn("manifest_component", result["classification_reasons"])
        finally:
            tmp.cleanup()

    def test_more_specific_application_namespace_can_live_below_vendor_prefix(self):
        context = ownership.OwnershipContext(
            "com.google.firebase.demo",
            frozenset({"com.google.firebase.demo.MainActivity"}),
            "parsed",
            "fixture",
        )
        classifier = ownership.CodeOwnershipClassifier(context)
        self.assertEqual(
            classifier.classify("com.google.firebase.demo.MainActivity")["scope"],
            "FIRST_PARTY",
        )
        self.assertEqual(
            classifier.classify("com.google.firebase.demo.auth.Session")["scope"],
            "FIRST_PARTY",
        )
        self.assertEqual(
            classifier.classify("com.google.firebase.auth.FirebaseAuth")["scope"],
            "THIRD_PARTY",
        )

    def test_external_is_not_an_ownership_classifier(self):
        classifier = ownership.CodeOwnershipClassifier(
            ownership.OwnershipContext(None, frozenset(), "missing", None)
        )
        result = classifier.classify("x.y.ExternalOnly", external=True)
        self.assertEqual(result["scope"], "UNKNOWN")
        self.assertIn("external_method_is_not_ownership", result["classification_reasons"])

    def test_generic_impl_suffix_is_not_misclassified_as_generated(self):
        context = ownership.OwnershipContext(
            "com.example.app", frozenset(), "parsed", "fixture"
        )
        result = ownership.CodeOwnershipClassifier(context).classify(
            "com.example.app.AuthRepository_Impl"
        )
        self.assertEqual(result["scope"], "FIRST_PARTY")

    def test_query_scope_policy_is_explicit_and_conservative(self):
        classifier = ownership.CodeOwnershipClassifier(
            ownership.OwnershipContext("com.example", frozenset(), "parsed", "fixture")
        )
        first_party = classifier.classify("com.example.Login")
        unknown = classifier.classify("a.b.C")
        third_party = classifier.classify("com.facebook.FacebookSdk")
        generated = classifier.classify("com.example.BuildConfig")
        self.assertTrue(ownership.scope_accepts(first_party, "application"))
        self.assertTrue(ownership.scope_accepts(unknown, "application"))
        self.assertFalse(ownership.scope_accepts(third_party, "application"))
        self.assertFalse(ownership.scope_accepts(generated, "application"))
        self.assertTrue(ownership.scope_accepts(third_party, "third_party"))
        self.assertTrue(ownership.scope_accepts(generated, "generated"))
        self.assertTrue(ownership.scope_accepts(third_party, "all"))
        with self.assertRaises(ownership.OwnershipModelError):
            ownership.validate_query_scope("vendor")

    def test_rules_and_context_descriptors_are_deterministic(self):
        tmp, job = self.make_job()
        try:
            first = ownership.CodeOwnershipClassifier.for_job(job).descriptor()
            second = ownership.CodeOwnershipClassifier.for_job(job).descriptor()
            self.assertEqual(first, second)
            self.assertEqual(first["model_version"], ownership.OWNERSHIP_MODEL_VERSION)
            self.assertRegex(first["rules_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(first["context"]["application_package"], "com.example.app")
        finally:
            tmp.cleanup()

    def test_missing_or_invalid_manifest_degrades_to_unknown_not_guess(self):
        tmp, job = self.make_job(None)
        try:
            classifier = ownership.CodeOwnershipClassifier.for_job(job)
            self.assertEqual(classifier.context.manifest_status, "missing")
            self.assertEqual(classifier.classify("a.a.Hidden")["scope"], "UNKNOWN")
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
