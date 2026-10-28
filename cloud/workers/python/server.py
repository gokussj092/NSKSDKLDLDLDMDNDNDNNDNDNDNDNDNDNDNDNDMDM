#!/usr/bin/env python3
"""C2 private worker: internal authenticated execution; never directly internet-facing."""
from __future__ import annotations

import base64
import hmac
import json
import os
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from engine import ROOT, DecodeFailure, MAX_INPUT_BYTES, decode_file, decode_text, decode_catalog, decode_provider_catalog, load_file_engines

# Input is JSON + base64; accept at most bounded overhead. C3 owns public upload parsing.
MAX_JSON_BYTES = (MAX_INPUT_BYTES * 4 // 3) + 65536
# The approved MKK bundle carries up to four fixed-source envelopes and
# is itself Base64-wrapped by the internal broker. Not a public upload limit.
MAX_MKK_BUNDLE_BYTES = 45 * 1024 * 1024
MAX_SERVER_VPN_JSON_BYTES = max(MAX_JSON_BYTES, ((MAX_MKK_BUNDLE_BYTES + 2) // 3) * 4 + 65536)


# Independent of session rotation, Redis leases, or multiple web replicas.
ACTIVE_JOBS = threading.BoundedSemaphore(4)

class WorkerHandler(BaseHTTPRequestHandler):
    server_version = "SPDecodeWorker/0.2"
    sys_version = ""
    protocol_version = "HTTP/1.0"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, fmt: str, *args: object) -> None:
        # Deliberately no paths, payloads or headers in logs.
        return

    def _json(self, status: int, body: dict) -> None:
        response = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(response)

    def _authorized(self) -> bool:
        expected = os.environ.get("CLOUD_WORKER_TOKEN", "")
        supplied = self.headers.get("X-SP-Worker-Token", "")
        # Fail closed even for localhost when no worker secret is provisioned.
        return len(expected) >= 32 and len(supplied) == len(expected) and hmac.compare_digest(supplied, expected)

    def do_GET(self) -> None:
        if self.path == "/health":
            return self._json(200, {"service": "spdecode-worker", "status": "alive", "phase": "C2"})
        if self.path == "/ready":
            enabled = bool(os.environ.get("CLOUD_WORKER_TOKEN", "") and len(os.environ["CLOUD_WORKER_TOKEN"]) >= 32)
            if not enabled:
                return self._json(503, {"service": "spdecode-worker", "status": "not_ready", "reason": "CREDENTIALS_NOT_PROVISIONED"})
            try:
                count = len(load_file_engines())
            except (ValueError, OSError, RuntimeError):
                return self._json(503, {"service": "spdecode-worker", "status": "not_ready", "reason": "ENGINE_INVENTORY_FAILED"})
            return self._json(200, {"service": "spdecode-worker", "status": "ready", "fileRoutes": count, "certified": False})
        if self.path == "/internal/v1/capabilities":
            if not self._authorized():
                return self._json(403, {"error": {"code": "FORBIDDEN"}})
            return self._json(200, {
                "fileRoutes": sorted(load_file_engines()),
                "fileRouteCount": 240,
                "exporterCertified": False,
                "textDecodingEnabled": True,
                "cloudImportsEnabled": False,
                "nurCatalogEnabled": True,
            })
        return self._json(404, {"error": {"code": "NOT_FOUND"}})

    def do_POST(self) -> None:
        if self.path not in ("/internal/v1/npvs/identity", "/internal/v1/decode/file", "/internal/v1/decode/text", "/internal/v1/decode/import/catalog", "/internal/v1/decode/import/server-vpn"):
            return self._json(503, {"error": {"code": "DECODERS_DISABLED"}})
        if not self._authorized():
            return self._json(403, {"error": {"code": "FORBIDDEN"}})
        if not ACTIVE_JOBS.acquire(blocking=False):
            return self._json(503, {"error": {"code": "ENGINE_UNAVAILABLE"}})
        try:
            WorkerHandler._execute_post(self)
        finally:
            ACTIVE_JOBS.release()

    def _execute_post(self) -> None:
        if self.path not in ("/internal/v1/npvs/identity", "/internal/v1/decode/file", "/internal/v1/decode/text", "/internal/v1/decode/import/catalog", "/internal/v1/decode/import/server-vpn"):
            return self._json(503, {"error": {"code": "DECODERS_DISABLED"}})
        if not self._authorized():
            return self._json(403, {"error": {"code": "FORBIDDEN"}})
        declared = self.headers.get("Content-Length", "")
        route_limit = (128 if self.path == "/internal/v1/npvs/identity" else
            MAX_SERVER_VPN_JSON_BYTES if self.path == "/internal/v1/decode/import/server-vpn" else MAX_JSON_BYTES)
        if not declared.isascii() or not declared.isdecimal() or int(declared) > route_limit:
            return self._json(413, {"error": {"code": "INPUT_TOO_LARGE"}})
        try:
            request = json.loads(self.rfile.read(int(declared)))
            if not isinstance(request, dict):
                raise ValueError("schema")
            if self.path == "/internal/v1/npvs/identity":
                if request != {"consent": True}:
                    raise ValueError("identity schema")
                if str(ROOT) not in sys.path:
                    sys.path.insert(0, str(ROOT))
                from decoders.Python.npvs_identity import generate
                return self._json(200, {"identity": generate()})
            if self.path == "/internal/v1/decode/text":
                if "text" not in request or set(request) - {"text", "credentials"} or not isinstance(request["text"], str):
                    raise ValueError("text schema")
                result = decode_text(request["text"], credentials=request.get("credentials"))
            elif self.path == "/internal/v1/decode/import/server-vpn":
                if set(request) != {"providerId", "dataBase64"} or not isinstance(request["providerId"], str):
                    raise ValueError("provider schema")
                encoded=request["dataBase64"]
                provider=request["providerId"]
                limit=MAX_MKK_BUNDLE_BYTES if provider=="mkk-hyper" else MAX_INPUT_BYTES
                if not isinstance(encoded,str) or len(encoded) > ((limit+2)//3)*4:
                    raise DecodeFailure("INPUT_TOO_LARGE")
                result=decode_provider_catalog(provider,base64.b64decode(encoded,validate=True))
            elif self.path == "/internal/v1/decode/import/catalog":
                if set(request) != {"dataBase64"} or not isinstance(request["dataBase64"], str):
                    raise ValueError("catalog schema")
                encoded = request["dataBase64"]
                if len(encoded) > (MAX_INPUT_BYTES * 4 // 3 + 8):
                    raise DecodeFailure("INPUT_TOO_LARGE")
                result = decode_catalog(base64.b64decode(encoded, validate=True))
            else:
                if not {"format", "dataBase64"} <= set(request) or set(request) - {"format", "dataBase64", "credentials", "compatibleExport"}:
                    raise ValueError("file schema")
                encoded = request["dataBase64"]
                if not isinstance(encoded, str) or len(encoded) > (MAX_INPUT_BYTES * 4 // 3 + 8):
                    raise DecodeFailure("INPUT_TOO_LARGE")
                contents = base64.b64decode(encoded, validate=True)
                result = decode_file(request["format"], contents,
                                     credentials=request.get("credentials"), full_hat=True, compatible_export=request.get("compatibleExport"))
        except (ValueError, TypeError, base64.binascii.Error):
            return self._json(400, {"error": {"code": "INVALID_REQUEST"}})
        except DecodeFailure as error:
            # Stable HTTP semantics for Android 1.1.19: incompatible exporter
            # methods are expected 422 responses; bad input is 400; worker
            # outages are 503/504. Never promote a crypto failure to an outage.
            status = {"INPUT_TOO_LARGE": 413, "OUTPUT_TOO_LARGE": 413,
                      "INVALID_REQUEST": 400, "INVALID_INPUT": 400,
                      "INVALID_BASE64": 400, "INVALID_CREDENTIALS": 400,
                      "CREDENTIALS_NOT_ALLOWED": 400,
                      "UNSUPPORTED_FORMAT": 422, "UNSUPPORTED_VERSION": 422,
                      "UNSUPPORTED_METHOD": 422, "UNSUPPORTED_VARIANT": 422,
                      "NPVS_PROTECTION_UNSUPPORTED": 422,
                      "PASSWORD_REQUIRED": 422, "HWID_REQUIRED": 422,
                      "HWID_PASSWORD_REQUIRED": 422, "AUTH_FAILED": 422,
                      "PRIVATE_KEY_REQUIRED": 422, "RECIPIENT_MISMATCH": 422,
                      "NPVS_APPKEY_AUTH_FAILED": 422,
                      "ENGINE_TIMEOUT": 504, "ENGINE_UNAVAILABLE": 503,
                      }.get(error.code, 422)
            return self._json(status, {"error": {"code": error.code}})
        return self._json(200, result)

    def do_PUT(self) -> None:
        self._json(503, {"error": {"code": "DECODERS_DISABLED"}})


def main() -> None:
    host = os.environ.get("WORKER_BIND_HOST", "127.0.0.1")
    port = int(os.environ.get("WORKER_PORT", "8787"))
    ThreadingHTTPServer((host, port), WorkerHandler).serve_forever()


if __name__ == "__main__":
    main()
