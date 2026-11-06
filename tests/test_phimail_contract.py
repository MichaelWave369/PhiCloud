"""Pin PhiCloud's PhiID/PhiMail public registry contract without inventing a service."""
import unittest
from pathlib import Path

from phicloud.registry import load_manifest

MANIFEST = Path(__file__).resolve().parent.parent / "config" / "services.json"


class PhiMailCompatibilityTests(unittest.TestCase):
    def test_identity_and_mail_declarations_have_repos_but_no_active_endpoints(self):
        services = {entry["id"]: entry for entry in load_manifest(MANIFEST)["services"]}
        phiid = services["phiid"]
        phimail = services["phimail"]
        self.assertEqual(phiid["role"], "identity")
        self.assertEqual(phiid["stage"], "planned")
        self.assertEqual(phiid["repository"], "https://github.com/MichaelWave369/PhiID")
        self.assertEqual(phimail["role"], "mail")
        self.assertEqual(phimail["stage"], "integration-needed")
        self.assertEqual(phimail["repository"], "https://github.com/MichaelWave369/PhiMail")
        for service in (phiid, phimail):
            self.assertIsNone(service["endpoint_hint"])
            self.assertNotIn("authenticated", service)
            self.assertNotIn("healthy", service)
            self.assertNotIn("permissions", service)


if __name__ == "__main__":
    unittest.main()
