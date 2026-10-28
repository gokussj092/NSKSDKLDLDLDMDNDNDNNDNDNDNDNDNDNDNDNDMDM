"""Capacity is enforced in the worker independently of Redis sessions/leases."""
import json
import threading
import unittest
from unittest.mock import Mock, patch
from http.server import ThreadingHTTPServer
import urllib.error
import urllib.request

from server import WorkerHandler, ACTIVE_JOBS

class WorkerCapacityTests(unittest.TestCase):
    def test_full_capacity_rejects_authorized_job_and_auth_still_runs_first(self):
        held = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), WorkerHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for _ in range(4):
                self.assertTrue(ACTIVE_JOBS.acquire(blocking=False))
                held.append(True)
            with patch.dict("os.environ", {"CLOUD_WORKER_TOKEN": "w" * 48}):
                for token, expected in (("w" * 48, 503), ("invalid", 403)):
                    request = urllib.request.Request(
                        f"http://127.0.0.1:{server.server_port}/internal/v1/decode/file",
                        data=b"{}", headers={"X-SP-Worker-Token": token}, method="POST")
                    with self.assertRaises(urllib.error.HTTPError) as caught:
                        urllib.request.urlopen(request, timeout=3)
                    self.assertEqual(caught.exception.code, expected)
                    with caught.exception as response:
                        self.assertIn("error", json.loads(response.read()))
        finally:
            for _ in held:
                ACTIVE_JOBS.release()
            server.shutdown(); server.server_close(); thread.join(timeout=3)

    def test_failed_execution_releases_capacity(self):
        handler = object.__new__(WorkerHandler)
        handler.path = "/internal/v1/decode/file"
        handler.connection = Mock()
        with patch.object(WorkerHandler, "_authorized", return_value=True), \
             patch.object(WorkerHandler, "_execute_post", side_effect=RuntimeError("synthetic")):
            with self.assertRaises(RuntimeError):
                handler.do_POST()
        acquired = []
        try:
            for _ in range(4):
                self.assertTrue(ACTIVE_JOBS.acquire(blocking=False))
                acquired.append(True)
        finally:
            for _ in acquired:
                ACTIVE_JOBS.release()
