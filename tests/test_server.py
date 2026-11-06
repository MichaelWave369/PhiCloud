"""Only verify the local prototype's read-only behavior; no cloud claims."""

import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import urlopen

from phicloud.server import LOOPBACK, make_handler


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = {"schema": "phicloud.services.v0.1", "services": [
            {"id":"phiid","title":"PhiID","role":"identity","stage":"planned",
             "repository":None,"endpoint_hint":None}
        ]}
        cls.server = ThreadingHTTPServer((LOOPBACK, 0), make_handler(cls.manifest))
        cls.port = cls.server.server_address[1]
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=3)

    def get(self, path):
        with urlopen(f"http://{LOOPBACK}:{self.port}{path}", timeout=2) as response:
            return response.status, response.headers, json.load(response)

    def test_health_is_only_about_registry_process(self):
        code, headers, obj = self.get("/healthz")
        self.assertEqual(code, 200)
        self.assertEqual(obj["scope"], "local_registry_process_only")
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_manifest_is_declarative(self):
        code, _, obj = self.get("/v1/services")
        self.assertEqual(code, 200)
        self.assertEqual(obj["services"][0]["stage"], "planned")

    def test_other_paths_do_not_expose_actions(self):
        with self.assertRaises(HTTPError) as ctx:
            self.get("/v1/users")
        self.assertEqual(ctx.exception.code, 404)

    def test_query_string_rejected(self):
        with self.assertRaises(HTTPError) as ctx:
            self.get("/v1/services?probe=true")
        self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
