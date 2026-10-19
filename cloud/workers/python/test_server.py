"""Standalone C1 worker checks. No decoder imports or fixtures."""
from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from server import WorkerHandler


class WorkerStubTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), WorkerHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = "http://127.0.0.1:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def invoke(self, path, method="GET", data=None):
        request = urllib.request.Request(self.base_url + path, data=data, method=method)
        try:
            result = urllib.request.urlopen(request, timeout=3)
        except urllib.error.HTTPError as exc:
            result = exc
        with result:
            return result.status, json.loads(result.read())

    def test_liveness_is_success_but_not_readiness(self):
        status, response = self.invoke("/health")
        self.assertEqual(status, 200)
        self.assertEqual(response["status"], "alive")
        status, response = self.invoke("/ready")
        self.assertEqual(status, 503)
        self.assertEqual(response["status"], "not_ready")

    def test_decoding_stays_disabled_even_for_uploads(self):
        for method in ("POST", "PUT"):
            status, response = self.invoke("/decode", method, b"untrusted-input")
            self.assertEqual(status, 503)
            self.assertEqual(response["error"]["code"], "DECODERS_DISABLED")

    def test_unknown_path_not_available(self):
        status, response = self.invoke("/private")
        self.assertEqual(status, 404)
        self.assertEqual(response["error"]["code"], "NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
