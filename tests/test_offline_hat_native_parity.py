#!/usr/bin/env python3
"""Independent host parity for the existing Hat Tunnel file algorithm.

Synthetic samples verify audited source keys, protected profilev5 values
and fail-closed malformed/unsupported input. Real-world export QA remains
separate and must not be claimed by this suite.
"""
from __future__ import annotations
import base64
import json
import subprocess
import sys
import unittest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

KEY=base64.b64decode("zbNkuNCGSLivpEuep3BcNA==")
XOR="**rVg7EkL~c2"+chr(96)+"D[aNn"

def pack_file(doc: dict) -> bytes:
    raw=json.dumps(doc,ensure_ascii=False,separators=(",",":")).encode("utf8")
    return base64.b64encode(AES.new(KEY,AES.MODE_ECB).encrypt(pad(raw,16)))

def lock_v5(value: str) -> str:
    source=value.encode("utf8")
    locked=bytes(x ^ ord(XOR[i%len(XOR)]) for i,x in enumerate(source))
    return base64.b64encode(locked).decode("ascii")

class HatNativeParity(unittest.TestCase):
    cli=""
    def read(self,source:bytes,success=True):
        job=subprocess.run([self.cli],input=source,capture_output=True,timeout=10)
        if success:
            self.assertEqual(job.returncode,0,job.stderr.decode())
            return json.loads(job.stdout.decode())
        self.assertNotEqual(job.returncode,0)
        self.assertTrue(job.stderr.decode().startswith("HAT_"))
    def test_legacy_profile_complete(self):
        profile={"profile":{"connection_mode":2,"custom_sni":"hello.example",
            "custom_payload":"GET / HTTP/1.1\\r\\nHost: hello","private":"secret"},
            "description":"example","protextras":{"password":True,"id_lock":True},
            "meta":{"meta_vendor_msg":"not truncated"}}
        self.assertEqual(self.read(pack_file(profile)),profile)
    def test_v5_xor_fields(self):
        expected={"connection_mode":"Imported Config","custom_payload":"CONNECT demo",
            "custom_sni":"vpn.example.com","custom_host":"Host:example"}
        encrypted={name:lock_v5(value) for name,value in expected.items()}
        obj={"profilev5":encrypted,"descriptionv5":"alpha"}
        output=self.read(pack_file(obj))
        self.assertEqual(output["profilev5"],encrypted)
        self.assertEqual(output["decodedProfileV5"],expected)
        self.assertEqual(output["descriptionv5"],"alpha")
    def test_large_json_no_truncation(self):
        document={"configuration":{"server_host":"server.example","server_username":"u"},
                  "long":list(range(512))}
        self.assertEqual(self.read(pack_file(document)),document)
    def test_invalid_file_rejected(self):
        for raw in [b"",b"bad",b"AA==",base64.b64encode(b"A"*16),
                    pack_file({"wrong":"document"}),
                    pack_file({"profile":"not object"})[:13]]:
            with self.subTest(raw=raw[:10]):self.read(raw,False)

if __name__=="__main__":
    HatNativeParity.cli=sys.argv[1]
    unittest.main(argv=[sys.argv[0]])
