"""Tests del metodo Fx Tunnel (build 39).

Vectores SINTETICOS con claves de prueba generadas aqui mismo; no hay
credenciales reales, ni servidores reales, ni red. La criptografia con
parametros reales esta cubierta por la reproduccion del empaquetado
desde base.apk y por el --self-test del script operativo (ver
RESULTS.md).
"""
import base64
import json
import os
import sys
import unittest

HERE = os.path.dirname(__file__)
STAGED = os.path.join(HERE, "..", "..", "..", "..", "decoders", "Python", "apps", "Fx_Tunnel")
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
sys.path.insert(0, os.path.abspath(STAGED))

from xxtea_pure import encrypt as xxtea_encrypt, decrypt as xxtea_decrypt  # noqa: E402
import Fx_Tunnel as catalog  # noqa: E402
import Fx_Tunnel_archivos as files  # noqa: E402

TEST_KEY_16 = b"TEST-ONLY-KEY-16"
FIXTURES = os.path.join(HERE, "fixtures")


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


class TestFxCatalog(unittest.TestCase):
    def test_xxtea_round_trip_with_test_key(self):
        plain = b'{"Version":"TEST","Free_servers":[]}'
        self.assertEqual(xxtea_decrypt(xxtea_encrypt(plain, TEST_KEY_16), TEST_KEY_16), plain)

    def test_catalog_json_accepts_synthetic_fixture(self):
        doc = catalog._catalog_json(json.dumps(load_fixture("synthetic_catalog.json")))
        self.assertEqual(doc.get("Version"), "TEST")
        self.assertEqual(len(doc.get("Free_servers", [])), 1)
        self.assertEqual(len(doc.get("Payloads", [])), 1)

    def test_catalog_json_rejects_document_without_lists(self):
        with self.assertRaises(catalog.DecodeError):
            catalog._catalog_json('{"Version": "TEST"}')

    def test_catalog_json_rejects_non_list_field(self):
        with self.assertRaises(catalog.DecodeError):
            catalog._catalog_json('{"Version": "TEST", "Free_servers": "nope"}')

    def test_decode_rejects_garbage_base64(self):
        with self.assertRaises(catalog.DecodeError):
            catalog.decode("esto no es base64!!!")

    def test_staged_bundled_json_structure(self):
        with open(os.path.join(os.path.abspath(STAGED), "bundled.json"), encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(doc.get("Version"), "10288")
        self.assertEqual(len(doc.get("Free_servers", [])), 29)
        self.assertEqual(len(doc.get("Payloads", [])), 1353)


class TestFxFiles(unittest.TestCase):
    def test_fxt_round_trip_synthetic_profile(self):
        profile = load_fixture("synthetic_profile.json")
        text = json.dumps(profile, ensure_ascii=False)
        encrypted = files.encrypt_profile_text(text)
        self.assertEqual(files.decode(encrypted), profile)

    def test_fxt_round_trip_uppercase_hex(self):
        profile = load_fixture("synthetic_profile.json")
        text = json.dumps(profile, ensure_ascii=False)
        encrypted = files.encrypt_profile_text(text).upper()
        self.assertEqual(files.decode(encrypted), profile)

    def test_fxt_rejects_non_hex(self):
        with self.assertRaises(files.DecodeError):
            files.decode("ZZZ-no-es-hex")

    def test_fxt_run_returns_none_on_bad_input(self):
        self.assertIsNone(files.run("ZZZ-no-es-hex"))

    def test_fxt_summary_lists_keys_only(self):
        profile = load_fixture("synthetic_profile.json")
        text = json.dumps(profile, ensure_ascii=False)
        doc = files.decode(files.encrypt_profile_text(text))
        self.assertEqual(sorted(doc.keys()), sorted(profile.keys()))


if __name__ == "__main__":
    unittest.main()
