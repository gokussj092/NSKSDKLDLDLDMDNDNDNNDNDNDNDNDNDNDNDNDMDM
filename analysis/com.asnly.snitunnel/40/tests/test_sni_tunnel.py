"""Tests del metodo SNI Tunnel 1.3.7 (build 40).

Vectores SINTETICOS con un par de claves P-256 de prueba generado en
el propio test (SNI_TUNNEL_APP_PRIV_B64 / SNI_TUNNEL_APP_PUB_B64);
ningun secreto real, ningun servidor real, ninguna red. El registro
"app-open" se abre con la clave de prueba, igual que con la clave
incrustada en el APK.
"""
import base64
import json
import os
import sys
import time
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import sni_tunnel as sni

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return fh.read()


def install_test_app_key():
    """Genera un par P-256 de prueba y lo instala como clave de app."""
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    priv_b = priv.private_numbers().private_value.to_bytes(32, "big")
    pub_b = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    os.environ["SNI_TUNNEL_APP_PRIV_B64"] = base64.b64encode(priv_b).decode()
    os.environ["SNI_TUNNEL_APP_PUB_B64"] = base64.b64encode(pub_b).decode()
    return priv_b, pub_b


TEST_LINK = ("vless://11111111-1111-4111-8111-111111111111@example.com:443"
             "?security=tls&type=ws&path=%2Fws#TestWs")


class TestV2rcSealOpen(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_test_app_key()

    def test_positive_seal_open_app_open_record(self):
        sealed = sni.seal_v2rc(TEST_LINK, "Test")
        self.assertTrue(sealed.startswith("v2rc://"))
        res = sni.open_v2rc(sealed)
        self.assertEqual(res["record_kind"], "app-open")
        self.assertEqual(res["config"], TEST_LINK)
        self.assertEqual(res["name"], "Test")
        self.assertFalse(res["expired"])

    def test_positive_seal_open_with_password(self):
        sealed = sni.seal_v2rc(TEST_LINK, "Locked", password="testpass")
        res = sni.open_v2rc(sealed)
        self.assertIsNone(res["config"])
        self.assertIsNotNone(res["password_envelope"])
        res2 = sni.open_v2rc(sealed, password="testpass")
        self.assertEqual(res2["config"], TEST_LINK)

    def test_negative_wrong_password(self):
        sealed = sni.seal_v2rc(TEST_LINK, "Locked", password="testpass")
        with self.assertRaises(sni.SniError):
            sni.open_v2rc(sealed, password="wrongpass")

    def test_positive_expired_link(self):
        past = time.time() - 3600
        sealed = sni.seal_v2rc(TEST_LINK, "Old", expires_at_unix=past)
        res = sni.open_v2rc(sealed)
        self.assertTrue(res["expired"])

    def test_positive_device_record(self):
        did_priv, did = sni.device_keypair("test-android-id-1234")
        sealed = sni.seal_v2rc(TEST_LINK, "ForDevice", device_ids=[did])
        res = sni.open_v2rc(sealed, android_id="test-android-id-1234")
        self.assertEqual(res["record_kind"], "device")
        self.assertEqual(res["config"], TEST_LINK)
        # Otro dispositivo cae al registro abierto, no al de dispositivo.
        res2 = sni.open_v2rc(sealed, android_id="other-android-id")
        self.assertEqual(res2["record_kind"], "app-open")

    def test_positive_device_id_deterministic(self):
        _p1, did1 = sni.device_keypair("test-android-id-1234")
        _p2, did2 = sni.device_keypair("test-android-id-1234")
        self.assertEqual(did1, did2)
        self.assertEqual(sni.device_id_hash(did1),
                         sni.device_id_hash(did2))


class TestLinkParsing(unittest.TestCase):
    def test_positive_links(self):
        for line in load_fixture("synthetic_links.txt").splitlines():
            if not line.strip():
                continue
            doc = sni.parse_link(line)
            self.assertIn("type", doc)
        vless = sni.parse_link(TEST_LINK)
        self.assertEqual(vless["type"], "vless")
        self.assertEqual(vless["address"], "example.com")

    def test_negative_unsupported_link(self):
        with self.assertRaises(sni.SniError):
            sni.parse_link("unknown://example.com:443")


if __name__ == "__main__":
    unittest.main()
