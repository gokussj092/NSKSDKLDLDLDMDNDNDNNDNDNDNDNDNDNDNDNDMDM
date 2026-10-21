"""Regression: real worker HTTP handler accepts bounded MKK private transport."""
from __future__ import annotations

import base64
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cloud.workers.python import server as worker


class ServerVpnTransportTests(unittest.TestCase):
    def request(self, path, body):
        results=[]
        fake=SimpleNamespace(
            path=path,headers={"Content-Length":str(len(body))},
            rfile=io.BytesIO(body),
            _authorized=lambda:True,
            _json=lambda status,body:results.append((status,body)),
        )
        worker.WorkerHandler.do_POST(fake)
        self.assertEqual(len(results),1)
        return results[0]

    def test_only_server_vpn_route_has_extended_envelope_limit(self):
        encoded=base64.b64encode(b"x"*160).decode()
        raw=json.dumps({"providerId":"mkk-hyper","dataBase64":encoded}).encode()
        self.assertGreater(len(raw),128)
        with patch.object(worker,"MAX_JSON_BYTES",128),patch.object(
            worker,"MAX_SERVER_VPN_JSON_BYTES",1024
        ),patch.object(worker,"decode_provider_catalog",return_value={
            "status":"success","structuredJson":{"servers":[{"id":1}]}
        }) as decode:
            status,result=self.request("/internal/v1/decode/import/server-vpn",raw)
            self.assertEqual(status,200)
            self.assertEqual(result["status"],"success")
            decode.assert_called_once_with("mkk-hyper",b"x"*160)
            status,error=self.request("/internal/v1/decode/file",raw)
            self.assertEqual(status,413)
            self.assertEqual(error["error"]["code"],"INPUT_TOO_LARGE")

    def test_mkk_bundle_limit_is_bounded_without_shrinking_other_providers(self):
        self.assertEqual(worker.MAX_MKK_BUNDLE_BYTES,45*1024*1024)
        self.assertGreater(worker.MAX_MKK_BUNDLE_BYTES,worker.MAX_INPUT_BYTES)
        self.assertGreaterEqual(worker.MAX_SERVER_VPN_JSON_BYTES,worker.MAX_JSON_BYTES)


if __name__=="__main__":
    unittest.main()
