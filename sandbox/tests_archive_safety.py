#!/usr/bin/env python3
from __future__ import annotations

import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import archive_safety


class ArchiveSafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def make_zip(self, path: Path, members: dict[str, bytes]) -> None:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, data in members.items():
                zf.writestr(name, data)

    def apk_bytes(self, members: dict[str, bytes]) -> bytes:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, data in members.items():
                zf.writestr(name, data)
        return stream.getvalue()

    def test_direct_apk_is_validated_before_yield(self):
        apk = self.root / "app.apk"
        self.make_zip(apk, {"classes.dex": b"dex", "AndroidManifest.xml": b"manifest"})
        rows = []
        for name, zf in archive_safety.nested_apks(apk):
            rows.append((name, sorted(info.filename for info in zf.infolist())))
        self.assertEqual(rows[0][0], "app.apk")
        self.assertIn("classes.dex", rows[0][1])

    def test_bundle_nested_count_is_bounded(self):
        bundle = self.root / "app.xapk"
        nested = self.apk_bytes({"classes.dex": b"dex"})
        with zipfile.ZipFile(bundle, "w") as zf:
            zf.writestr("a.apk", nested)
            zf.writestr("b.apk", nested)
        with mock.patch.object(archive_safety, "MAX_NESTED_APKS", 1):
            with self.assertRaises(archive_safety.ArchiveSafetyError):
                list(archive_safety.nested_apks(bundle))

    def test_nested_apk_aggregate_is_bounded(self):
        bundle = self.root / "app.apks"
        nested = self.apk_bytes({"classes.dex": b"x" * 1024})
        with zipfile.ZipFile(bundle, "w") as zf:
            zf.writestr("a.apk", nested)
            zf.writestr("b.apk", nested)
        with mock.patch.object(
            archive_safety, "MAX_TOTAL_NESTED_APK_BYTES", len(nested)
        ):
            with self.assertRaises(archive_safety.ArchiveSafetyError):
                list(archive_safety.nested_apks(bundle))

    def test_apk_entry_count_is_bounded(self):
        apk = self.root / "many.apk"
        self.make_zip(apk, {"a": b"1", "b": b"2"})
        with mock.patch.object(archive_safety, "MAX_APK_ENTRIES", 1):
            with self.assertRaises(archive_safety.ArchiveSafetyError):
                list(archive_safety.nested_apks(apk))

    def test_declared_uncompressed_bytes_are_bounded(self):
        apk = self.root / "large.apk"
        self.make_zip(apk, {"payload.bin": b"x" * 128})
        with mock.patch.object(archive_safety, "MAX_APK_DECLARED_BYTES", 64):
            with self.assertRaises(archive_safety.ArchiveSafetyError):
                list(archive_safety.nested_apks(apk))

    def test_member_name_length_is_bounded(self):
        apk = self.root / "name.apk"
        self.make_zip(apk, {"a" * 32: b"x"})
        with mock.patch.object(archive_safety, "MAX_MEMBER_NAME", 16):
            with self.assertRaises(archive_safety.ArchiveSafetyError):
                list(archive_safety.nested_apks(apk))

    def test_invalid_bundle_is_explicit(self):
        bad = self.root / "bad.xapk"
        bad.write_bytes(b"not-a-zip")
        with self.assertRaises(archive_safety.ArchiveSafetyError):
            list(archive_safety.nested_apks(bad))


if __name__ == "__main__":
    unittest.main()
