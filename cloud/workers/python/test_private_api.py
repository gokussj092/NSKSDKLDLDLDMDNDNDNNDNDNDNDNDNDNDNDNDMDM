"""Network-loopback integration checks for the C2 worker internal API."""
from __future__ import annotations

import base64
import json
import os
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from server import WorkerHandler

TEST_TOKEN = "integration-test-token-not-production-111111111"

class PrivateWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.previous = os.environ.get("CLOUD_WORKER_TOKEN")
        os.environ["CLOUD_WORKER_TOKEN"] = TEST_TOKEN
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), WorkerHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = "http://127.0.0.1:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        if cls.previous is None:
            os.environ.pop("CLOUD_WORKER_TOKEN", None)
        else:
            os.environ["CLOUD_WORKER_TOKEN"] = cls.previous

    def request(self, endpoint, payload=None, token=None):
        data = None if payload is None else json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["X-SP-Worker-Token"] = token
        req = Request(self.url + endpoint, data=data, headers=headers, method="POST" if data is not None else "GET")
        try:
            resp = urlopen(req, timeout=5)
        except HTTPError as exc:
            resp = exc
        with resp:
            return resp.status, json.loads(resp.read())

    def test_inventory_is_private(self):
        self.assertEqual(self.request("/internal/v1/capabilities")[0], 403)
        status, result = self.request("/internal/v1/capabilities", token=TEST_TOKEN)
        self.assertEqual(status, 200)
        self.assertEqual(result["fileRouteCount"], 240)
        self.assertTrue(result["exporterCertified"] is False)

    def test_failed_and_unauthorized_decoding(self):
        payload = {"format": "tls", "dataBase64": base64.b64encode(b"not-a-config").decode()}
        self.assertEqual(self.request("/internal/v1/decode/file", payload)[0], 403)
        status, result = self.request("/internal/v1/decode/file", payload, TEST_TOKEN)
        self.assertEqual(status, 422)
        self.assertEqual(result["error"]["code"], "DECODE_FAILED")
        status, result = self.request("/internal/v1/decode/file", {"format": "??", "dataBase64": "dGVzdA=="}, TEST_TOKEN)
        self.assertEqual(status, 422)
        self.assertEqual(result["error"]["code"], "UNSUPPORTED_FORMAT")

    def test_text_endpoint_rejects_invalid_and_unsupported(self):
        self.assertEqual(self.request("/internal/v1/decode/text", {"text": "invalid"})[0], 403)
        status, result = self.request("/internal/v1/decode/text", {"text": "no matching protocol"}, TEST_TOKEN)
        self.assertEqual(status, 422)
        self.assertEqual(result["error"]["code"], "DECODE_FAILED")

if __name__ == "__main__":
    unittest.main()
