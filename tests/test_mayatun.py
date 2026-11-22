"""MAYA TUN PRO 43.0 cloud catalog: synthetic fixtures through the real worker.

The catalog uses the NoobCrypt route (``decoders/Python/apps/Maya_Tun_Pro/codec.py``):
outer AES-256-XTS (mode 5), inner AES-256-GCM (mode 0) / AES-256-CBC
(modes 1/4) with the ``"maya"`` key imported from the existing
``decoders/Python/_noobcrypt.py``. Fixtures are built with the inverse
generators below. All values are fictitious (test.invalid); no live
catalog bytes or decrypted credentials are stored here.

The ``.maya`` file route is the existing frozen C0 route
(``decoders/Python/maya.py``); the ``maya://`` text route encrypts the
``.maya`` file bytes with ChaCha20-Poly1305 (mode 3). Both are exercised
with synthetic fixtures only — no real export or link has been supplied.
"""
import base64
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from decoders.Python.apps.Maya_Tun_Pro import codec
from decoders.Python.apps.Maya_Tun_Pro import server_catalog_decoder as catalog
from decoders.Python import maya as maya_file
from decoders.Python import _noobcrypt
from cloud.workers.python.engine import decode_provider_catalog
from cloud.workers.python import text_bridge

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = json.loads((ROOT / "tests/golden/mayatun_catalog_vectors.json").read_text())
GOLDEN_RAW = GOLDEN["catalog"].encode("ascii")  # worker input is the Base64 body text
GOLDEN_EXPECTED = GOLDEN["expected"]

XTS_KEY = bytes.fromhex(codec.XTS_KEY_HEX)
MAYA_KEY = codec.MAYA_KEY


def _gcm_field(clear: str) -> str:
    nonce = os.urandom(12)
    return base64.b64encode(
        nonce + AESGCM(MAYA_KEY).encrypt(nonce, clear.encode("utf-8"), None)).decode("ascii")


def _cbc_field(clear: str) -> str:
    iv = os.urandom(16)
    blob = clear.encode("utf-8")
    pad = 16 - len(blob) % 16
    blob += bytes([pad]) * pad
    encryptor = Cipher(algorithms.AES(MAYA_KEY), modes.CBC(iv)).encryptor()
    return base64.b64encode(iv + encryptor.update(blob) + encryptor.finalize()).decode("ascii")


def _xts_blob(doc: dict) -> bytes:
    tweak = os.urandom(16)
    encryptor = Cipher(algorithms.AES(XTS_KEY), modes.XTS(tweak)).encryptor()
    ciphertext = encryptor.update(json.dumps(doc).encode("utf-8")) + encryptor.finalize()
    return base64.b64encode(tweak + ciphertext)


def build_catalog():
    """(raw envelope bytes, expected plaintext document)."""
    encrypted = {
        "Version": "1.3.41-test",
        "DefUpdateURL": "https://jezvpn.xyz/api/app?json=38FD5AC7020E09D8203F",
        "show_release": True,
        "defTime": 30,
        "Servers": [{
            "Name": _gcm_field("Test Server"), "Flag": "xx",
            "Info": _gcm_field("Test info"),
            "ServerIPHost": _gcm_field("test.invalid"),
            "ServerHTTPHost": _gcm_field("test.invalid"),
            "NoobLevel": 0, "Protocol": 1, "OpenVPNUDPPort": "1194",
            "Username": _gcm_field("synthetic-user"),
            "Password": _gcm_field("synthetic-pass"),
        }],
        "Tweaks": [{
            "Name": _cbc_field("Test Tweak"), "Flag": "xx", "Mode": 2,
            "Sni": _cbc_field("[host]"), "Payload": _cbc_field("GET / HTTP/1.1"),
            "CustomProxy": _cbc_field("test.invalid:8080"),
        }],
        "Message": ["line one"],
    }
    expected = {
        "Version": "1.3.41-test",
        "DefUpdateURL": "https://jezvpn.xyz/api/app?json=38FD5AC7020E09D8203F",
        "show_release": True,
        "defTime": 30,
        "Servers": [{
            "Name": "Test Server", "Flag": "xx", "Info": "Test info",
            "ServerIPHost": "test.invalid", "ServerHTTPHost": "test.invalid",
            "NoobLevel": 0, "Protocol": 1, "OpenVPNUDPPort": "1194",
            "Username": "synthetic-user", "Password": "synthetic-pass",
        }],
        "Tweaks": [{
            "Name": "Test Tweak", "Flag": "xx", "Mode": 2,
            "Sni": "[host]", "Payload": "GET / HTTP/1.1",
            "CustomProxy": "test.invalid:8080",
        }],
        "Message": ["line one"],
    }
    return _xts_blob(encrypted), expected


RAW, EXPECTED = build_catalog()


def build_maya_file(profile: dict) -> bytes:
    """Synthetic .maya file with the repo scheme (outer CBC + inner GCM)."""
    inner = dict(profile)
    nonce = b"\x00" * 12
    inner["ServerIPHost"] = base64.b64encode(
        nonce + AESGCM(MAYA_KEY).encrypt(nonce, b"example.org", None)).decode("ascii")
    blob = json.dumps(inner).encode("utf-8")
    pad = 16 - len(blob) % 16
    blob += bytes([pad]) * pad
    iv = b"\x01" * 16
    encryptor = Cipher(algorithms.AES(MAYA_KEY), modes.CBC(iv)).encryptor()
    return base64.b64encode(iv + encryptor.update(blob) + encryptor.finalize())


def build_maya_link(profile: dict) -> str:
    """Synthetic maya:// link: ChaCha20-Poly1305 (mode 3) over .maya bytes."""
    nonce = os.urandom(12)
    sealed = ChaCha20Poly1305(MAYA_KEY).encrypt(nonce, build_maya_file(profile), None)
    return "maya://" + base64.b64encode(nonce + sealed).decode("ascii")


PROFILE = {"Name": "SYNTHETIC MAYA", "Protocol": 1, "ServerIPHost": ""}


class MayaTunProCatalogTests(unittest.TestCase):
    def test_synthetic_catalog_codec_cli_and_isolated_worker(self):
        self.assertEqual(json.loads(catalog.run(RAW)), EXPECTED)
        result = decode_provider_catalog("maya-tun-pro", RAW)
        self.assertEqual(result["structuredJson"], EXPECTED)
        self.assertEqual(json.loads(result["rawText"]), EXPECTED)
        self.assertFalse(result["isPartial"])
        path = ROOT / "decoders/Python/apps/Maya_Tun_Pro/server_catalog_decoder.py"
        proc = subprocess.run(
            [sys.executable, str(path), "--stdin"], input=RAW,
            cwd="/tmp", capture_output=True, check=True)
        self.assertEqual(json.loads(proc.stdout), EXPECTED)

    def test_golden_vector_opens_through_codec(self):
        self.assertEqual(json.loads(catalog.run(GOLDEN_RAW)), GOLDEN_EXPECTED)

    def test_existing_c0_maya_file_route(self):
        # The .maya file route is NOT in this module: it stays on the
        # frozen C0 matrix (decoders/Python/maya.py). A synthetic file
        # must open through that existing route, unchanged.
        file_bytes = build_maya_file(PROFILE)
        self.assertEqual(_noobcrypt.decrypt_profile(file_bytes, "maya")["Name"],
                         "SYNTHETIC MAYA")
        self.assertEqual(_noobcrypt.decrypt_profile(file_bytes, "maya")["ServerIPHost"],
                         "example.org")
        rendered = maya_file.run(file_bytes)
        self.assertIsNotNone(rendered)
        self.assertIn("SYNTHETIC MAYA", rendered)
        self.assertIn("example.org", rendered)
        with self.assertRaises(ValueError):
            _noobcrypt.decrypt_profile(b"not-base64!!!", "maya")

    def test_text_route_maya_link_synthetic_round_trip(self):
        link = build_maya_link(PROFILE)
        doc = json.loads(codec.decode_text(link))
        self.assertEqual(doc["application"], "Maya Tunnel")
        self.assertEqual(doc["protocol"], "maya://")
        self.assertEqual(doc["config"]["Name"], "SYNTHETIC MAYA")
        self.assertEqual(doc["config"]["ServerIPHost"], "example.org")
        # Same link through the real text dispatcher.
        dispatched = json.loads(text_bridge.dispatch(link))
        self.assertEqual(dispatched["config"]["Name"], "SYNTHETIC MAYA")
        self.assertEqual(dispatched["config"]["ServerIPHost"], "example.org")
        # Case-insensitive scheme, and non-links stay None.
        self.assertIsNotNone(codec.decode_text(link.replace("maya://", "MAYA://", 1)))
        self.assertIsNone(codec.decode_text("netfluxvpn://AAAA"))
        self.assertIsNone(codec.decode_text("maya://"))

    def test_corruption_rejects_entire_catalog(self):
        no_servers = dict(json.loads(json.dumps(EXPECTED)))
        del no_servers["Servers"]
        no_tweaks = dict(json.loads(json.dumps(EXPECTED)))
        del no_tweaks["Tweaks"]
        for invalid in (b"", b"<html/>", RAW[:-5],
                        _xts_blob(no_servers), _xts_blob(no_tweaks)):
            with self.subTest(length=len(invalid)):
                with self.assertRaises(codec.DecodeError):
                    catalog.run(invalid)
        # Same envelope under a different XTS key must not open.
        other_key = bytes([XTS_KEY[0] ^ 0xFF]) + XTS_KEY[1:]
        raw_blob = base64.b64decode(RAW)
        encryptor = Cipher(algorithms.AES(other_key), modes.XTS(raw_blob[:16])).encryptor()
        wrong = base64.b64encode(
            raw_blob[:16] + encryptor.update(b'{"Version": "x", "Servers": [], "Tweaks": []}') + encryptor.finalize())
        with self.assertRaises(codec.DecodeError):
            catalog.run(wrong)
        with self.assertRaises(codec.DecodeError):
            catalog._NoRedirect().redirect_request(None, None, None, None, None, None)

    def test_tampered_maya_link_returns_none(self):
        link = build_maya_link(PROFILE)
        tampered = link[:-4] + ("AAAA" if not link.endswith("AAAA") else "BBBB")
        self.assertIsNone(codec.decode_text(tampered))
        self.assertIsNone(text_bridge.dispatch(tampered))
        self.assertIsNone(codec.decode_text("maya://not-base64!!!"))


if __name__ == "__main__":
    unittest.main()
