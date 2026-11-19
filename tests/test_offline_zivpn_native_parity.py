#!/usr/bin/env python3
"""Differential host parity of the offline native ZIVPN decoder.

Seals synthetic .ziv files and zivpn:// links with PyCryptodome (the
independent oracle) and compares them against the native CLI built from
android/app/src/main/cpp/spdecode_zivpn.cpp. These are generated
fixtures, NOT proof of compatibility with every real vendor export: a
real .ziv file exported by the app was supplied 2026-11-18 and opens in
the CLI (see analysis/com.zi.zivpn/184/RESULTS.md, section 9), but no
real zivpn:// link has been supplied yet. No network.

Usage: python3 tests/test_offline_zivpn_native_parity.py /tmp/spdecode-zivpn-native
"""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from Crypto.Cipher import AES, DES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad

FIXED_PASSWORD = "SecurePart1SecurePart2SecurePart3SecurePart4SecurePart5"
LEGACY_PASSWORD = "fubvx788b46v"
DES_KEY = b"#ipt!2022/H"
TEXT_PASSWORD = base64.b64decode(
    "dTlxdXdscWs4ODFkaTFneGpuMWF1YnkzZmFmdm9tOXQ=").decode("utf-8")
SALT = bytes(range(32))
IV = bytes(range(12))
PROPS = {
    "tunnelType": "4",
    "udpserver": "udp-test.example",
    "sshServer": "ssh-test.example",
    "sshPort": "443",
    "sshPortaLocal": "1080",
    "file.appVersionCode": "184",
    "file.askLogin": "0",
    "alpha": "0",
    "beta": "0",
    "gamma": "0",
}


def properties_xml(props: dict) -> bytes:
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">',
             '<properties>',
             '<comment>Configuration File</comment>']
    for key in sorted(props):
        lines.append('<entry key="%s">%s</entry>' % (key, props[key]))
    lines.append('</properties>')
    return ("\n".join(lines) + "\n").encode("utf-8")


def seal_ziv_xml(xml: bytes, password: str, legacy: bool) -> bytes:
    inner = DES.new(DES_KEY[:8], DES.MODE_ECB).encrypt(pad(xml, 8)) if legacy else xml
    key = PBKDF2(password.encode(), SALT, dkLen=16, count=1000,
                 hmac_hash_module=SHA256)
    cipher = AES.new(key, AES.MODE_GCM, nonce=IV)
    ct, tag = cipher.encrypt_and_digest(inner)
    parts = (base64.b64encode(SALT), base64.b64encode(IV),
             base64.b64encode(ct + tag))
    return b".".join(parts)


def seal_ziv(props: dict, password: str, legacy: bool) -> bytes:
    return seal_ziv_xml(properties_xml(props), password, legacy)


def java_escape_astral(xml: str) -> str:
    """java.util.Properties writes astral characters (emoji) as
    surrogate-pair numeric references (&#55356;&#56808;) instead of raw
    UTF-8 — the shape a real app export takes in file.msg."""
    out = []
    for ch in xml:
        cp = ord(ch)
        if cp > 0xFFFF:
            cp -= 0x10000
            out.append("&#%d;&#%d;" % (0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF)))
        else:
            out.append(ch)
    return "".join(out)


def seal_zivpn_text(plain: str) -> bytes:
    key = hashlib.sha256(TEXT_PASSWORD.encode()).digest()
    ct = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(pad(plain.encode(), 16))
    return b"zivpn://" + base64.b64encode(ct)


class NativeZivpnParity(unittest.TestCase):
    cli: str = ""

    def run_cli(self, value: bytes, *args: str, succeeds=True):
        completed = subprocess.run([self.cli, *args], input=value,
                                   capture_output=True, timeout=10)
        if succeeds:
            self.assertEqual(completed.returncode, 0,
                             completed.stderr.decode())
            return json.loads(completed.stdout.decode("utf-8"))
        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue(completed.stderr.decode().startswith("ZIV_"),
                        completed.stderr.decode())

    def test_legacy_file_des_layer(self):
        self.assertEqual(
            self.run_cli(seal_ziv(PROPS, FIXED_PASSWORD, legacy=True)), PROPS)

    def test_export_style_file_lf1_only(self):
        self.assertEqual(
            self.run_cli(seal_ziv(PROPS, FIXED_PASSWORD, legacy=False)), PROPS)

    def test_legacy_password_fallback(self):
        self.assertEqual(
            self.run_cli(seal_ziv(PROPS, LEGACY_PASSWORD, legacy=False)), PROPS)

    def test_emoji_surrogate_pair_references(self):
        # file.msg with emoji written as surrogate-pair numeric references,
        # the way java.util.Properties writes them in a real export.
        props = dict(PROPS)
        props["file.msg"] = "test flag \U0001F1E8\U0001F1F2 ok"
        xml = java_escape_astral(properties_xml(props).decode("utf-8"))
        self.assertEqual(
            self.run_cli(seal_ziv_xml(xml.encode(), FIXED_PASSWORD, False)),
            props)

    def test_lone_surrogate_rejected(self):
        xml = properties_xml(PROPS).decode("utf-8").replace(
            "</properties>",
            '<entry key="file.msg">test &#55356; lone</entry>\n</properties>')
        self.run_cli(seal_ziv_xml(xml.encode(), FIXED_PASSWORD, False),
                     succeeds=False)

    def test_plain_properties_xml(self):
        self.assertEqual(self.run_cli(properties_xml(PROPS)), PROPS)

    def test_dossier_golden_fixture(self):
        root = Path(__file__).resolve().parent.parent
        fixture = root / "analysis/com.zi.zivpn/184/tests/fixtures/ziv-golden.ziv"
        expected = root / "analysis/com.zi.zivpn/184/tests/fixtures/ziv-golden.expected.json"
        self.assertEqual(self.run_cli(fixture.read_bytes()),
                         json.loads(expected.read_text()))

    def test_zivpn_text_xml_link(self):
        token = seal_zivpn_text(properties_xml(PROPS).decode("utf-8"))
        self.assertEqual(self.run_cli(token, "text"), PROPS)

    def test_zivpn_text_json_link(self):
        doc = {"host": "json-test.example", "port": 443}
        token = seal_zivpn_text(json.dumps(doc))
        self.assertEqual(self.run_cli(token, "text"), doc)

    def test_zivpn_text_bare_token(self):
        token = seal_zivpn_text(properties_xml(PROPS).decode("utf-8"))
        self.assertEqual(self.run_cli(token[len("zivpn://"):], "text"), PROPS)

    def test_wrong_password_rejected(self):
        sealed = seal_ziv(PROPS, "wrong-password-test", legacy=False)
        self.run_cli(sealed, succeeds=False)

    def test_tampered_tag_rejected(self):
        sealed = seal_ziv(PROPS, FIXED_PASSWORD, legacy=False).decode()
        parts = sealed.split(".")
        parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
        self.run_cli(".".join(parts).encode(), succeeds=False)

    def test_garbage_rejected(self):
        self.run_cli(b"NOT A PROFILE", succeeds=False)
        self.run_cli(b"", succeeds=False)
        self.run_cli(b"AAAA.AAAA", succeeds=False)
        self.run_cli(b"zivpn://!!", "text", succeeds=False)
        self.run_cli(b"zivpn://AAAA", "text", succeeds=False)


if __name__ == "__main__":
    NativeZivpnParity.cli = sys.argv[1]
    del sys.argv[1]
    unittest.main()
