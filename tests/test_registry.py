"""Contract tests do not require network or external dependencies."""

import json
import unittest
from pathlib import Path

from phicloud.registry import ManifestError, load_manifest, validate_manifest

MANIFEST = Path(__file__).resolve().parent.parent / "config" / "services.json"


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def test_sample_is_valid(self):
        self.assertEqual(load_manifest(MANIFEST)["schema"], "phicloud.services.v0.1")

    def test_duplicate_ids_rejected(self):
        self.manifest["services"].append(dict(self.manifest["services"][0]))
        with self.assertRaises(ManifestError):
            validate_manifest(self.manifest)

    def test_unexpected_fields_rejected(self):
        self.manifest["services"][0]["live"] = True
        with self.assertRaises(ManifestError):
            validate_manifest(self.manifest)

    def test_remote_insecure_http_rejected(self):
        self.manifest["services"][0]["endpoint_hint"] = "http://example.com"
        with self.assertRaises(ManifestError):
            validate_manifest(self.manifest)

    def test_url_credentials_rejected(self):
        self.manifest["services"][0]["endpoint_hint"] = "https://admin:pw@example.com"
        with self.assertRaises(ManifestError):
            validate_manifest(self.manifest)

    def test_http_loopback_allowed_as_hint(self):
        self.manifest["services"][0]["endpoint_hint"] = "http://127.0.0.1:11435"
        self.assertEqual(validate_manifest(self.manifest)["schema"], "phicloud.services.v0.1")

    def test_schema_mismatch_rejected(self):
        self.manifest["schema"] = "future"
        with self.assertRaises(ManifestError):
            validate_manifest(self.manifest)

    def test_invalid_stage_rejected(self):
        self.manifest["services"][0]["stage"] = "online"
        with self.assertRaises(ManifestError):
            validate_manifest(self.manifest)

    def test_non_mapping_rejected(self):
        with self.assertRaises(ManifestError):
            validate_manifest([])


if __name__ == "__main__":
    unittest.main()
