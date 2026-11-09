#!/usr/bin/env python3
"""Differential host parity of Dark Tunnel protected legacy and open envelope.

These are generated fixtures, NOT proof of compatibility with every real
vendor export. No network, APK keys, secrets or untrusted code execution.
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import unittest

from Crypto.Cipher import AES
import msgpack

OUTER = b"$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd"
INNER = b"F)J@NcRfUjXn2r4u7x!A%D*G"
IV = bytes.fromhex("232e39185523184a5723586242200e05")

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def aes_cfb(data: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_CFB, IV, segment_size=128).encrypt(data)

def pack(data) -> bytes:
    return msgpack.packb(data, use_bin_type=True)

def encode_document(obj: dict, encrypted: bool = False, prefix: str = "") -> bytes:
    if encrypted:
        obj = {"encryptedLockedConfig": b64(aes_cfb(pack(obj), OUTER)),
               "Label": "Dark", "Password": "must be removed"}
    return (prefix + b64(json.dumps(obj, ensure_ascii=False).encode())).encode()

class NativeDarkParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cli = sys.argv[1]
        sys.argv = sys.argv[:1]

    def run_cli(self, value: bytes, succeeds=True):
        completed = subprocess.run([self.cli], input=value, capture_output=True,
                                   timeout=10)
        if succeeds:
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            return json.loads(completed.stdout.decode("utf-8"))
        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue(completed.stderr.decode().startswith("DARK_"))

    def test_open_dark_envelope_and_password_filter(self):
        doc = {"Name": "Demo", "Allowed": ["vpn", "local"],
               "Password": "hidden", "nested": {"Password":"secret", "port": 443}}
        result = self.run_cli(encode_document(doc))
        self.assertEqual(result, {"Name":"Demo","Allowed":["vpn","local"],
                                  "nested":{"port":443}})

    def test_file_legacy_outer_msgpack(self):
        payload = {"Server": "example.org", "SNI": "vpn.example.org",
                   "Note": "Privado", "Binary": b"\x01\x02\xff",
                   "Password":"suppressed"}
        output = self.run_cli(encode_document(payload, True))
        inside = output["encryptedLockedConfig"]
        self.assertEqual(inside["Server"], "example.org")
        self.assertEqual(inside["Note"], "Privado")
        self.assertEqual(inside["Binary"], [1,2,255])
        self.assertNotIn("Password", inside)
        self.assertNotIn("Password", output)

    def test_nested_encrypted_fields_and_unicode(self):
        internal = {"EncryptedHost": aes_cfb("🇲🇽vpn.example".encode("utf8"),INNER),
                    "Plain":"hello", "Password":"concealed",
                    "nested":{"EncryptedNote":aes_cfb(b"alpha",INNER)}}
        outer = {"EncryptedLockedConfig": aes_cfb(pack(internal),INNER),
                 "Description": "one"}
        result = self.run_cli(encode_document(outer,True,"dt://"))
        part = result["encryptedLockedConfig"]["EncryptedLockedConfig"]
        self.assertEqual(part["EncryptedHost"],"🇲🇽vpn.example")
        self.assertEqual(part["nested"]["EncryptedNote"],"alpha")
        self.assertEqual(part["Plain"],"hello")
        self.assertNotIn("Password",part)

    def test_known_dark_text_schemes(self):
        payload = {"Host":"app.local","Port":443}
        for scheme in ["dt","dtunnel","dark","darktunnel","dark-tunnel"]:
            with self.subTest(scheme=scheme):
                result=self.run_cli(encode_document(payload,True,scheme+"://"))
                self.assertEqual(result["encryptedLockedConfig"]["Host"],"app.local")

    def test_urlsafeb64_and_plain_json(self):
        fixture = encode_document({"encryptedLockedConfig":None,"Host":"x"})
        safe = fixture.decode().rstrip("=").replace("+","-").replace("/","_")
        self.assertEqual(self.run_cli(safe.encode())["Host"],"x")
        self.assertEqual(self.run_cli(b'{"Host":"demo", "Port":80}')["Port"],80)

    def test_wrong_envelopes_fail_closed(self):
        for payload in [b"", b"!not-base64!", b"dt://", b"foo://AAAA",
                        b64(b'["not a map"]').encode(),
                        b64(b'{"encryptedLockedConfig":"AAAA"}').encode(),
                        b64(b'{"encryptedLockedConfig":123}').encode()]:
            with self.subTest(payload=payload):
                self.run_cli(payload,False)

if __name__=="__main__":
    unittest.main()
