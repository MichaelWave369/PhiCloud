"""PhiCloud R2 safety boundary: the declarative R0 server is NOT an auth/mail gateway."""
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import urlopen

from phicloud.server import LOOPBACK, make_handler


class IdentityHandoffBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        manifest = {"schema": "phicloud.services.v0.1", "services": [
            {"id": "phiid", "title": "PhiID", "role": "identity",
             "stage": "planned", "repository": "https://github.com/MichaelWave369/PhiID",
             "endpoint_hint": None}
        ]}
        cls.server = ThreadingHTTPServer((LOOPBACK, 0), make_handler(manifest))
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def test_inventory_is_not_an_authority_claim(self):
        with urlopen(f"http://{LOOPBACK}:{self.port}/v1/services", timeout=2) as response:
            self.assertEqual(response.status, 200)
            data = json.load(response)
        service = data["services"][0]
        for key in ("authenticated", "healthy", "token", "grants", "permissions", "claims"):
            self.assertNotIn(key, service)
        self.assertEqual(service["stage"], "planned")

    def test_identity_and_mail_endpoints_are_not_implemented(self):
        for path in (
            "/v1/identity/session", "/v1/mail/messages",
            "/v1/oauth/callback", "/v1/identity/authorize",
            "/v1/tokens/validate", "/.well-known/openid-configuration",
        ):
            with self.subTest(path=path), self.assertRaises(HTTPError) as err:
                urlopen(f"http://{LOOPBACK}:{self.port}{path}", timeout=2)
            self.assertEqual(err.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
