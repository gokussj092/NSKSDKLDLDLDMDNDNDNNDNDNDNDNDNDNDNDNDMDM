"""Tests del metodo ALTAUFIK VPN (build 44).

Vectores SINTETICOS; no hay credenciales reales, ni servidores reales,
ni red. El descifrado con parametros reales esta cubierto por el
--self-test del script operativo y por la re-corrida en vivo
byte-identica (ver RESULTS.md). Requiere PyCryptodome (el script
operativo la importa); ejecutar con el venv documentado en
REPRODUCE.md.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..",
                                "..", "decoders", "Python", "apps", "Altaufik_VPN"))

import Altaufik_VPN as mod

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


class TestAltaufik(unittest.TestCase):
    def test_synthetic_envelope_opens(self):
        doc = mod.decode(mod._SELF_TEST_VECTOR)
        self.assertEqual(doc.get("Version"), "99.9")
        self.assertEqual(len(doc.get("Servers", [])), 1)
        self.assertEqual(len(doc.get("Tweaks", [])), 1)

    def test_plain_json_passthrough(self):
        doc = mod.decode(json.dumps(load_fixture("synthetic_catalog.json")))
        self.assertEqual(doc.get("Version"), "99.9")
        self.assertEqual(len(doc.get("Servers", [])), 1)

    def test_dead_free_body_rejected(self):
        with self.assertRaises(mod.DecodeError):
            mod.decode("ff")

    def test_truncated_envelope_rejected(self):
        with self.assertRaises(mod.DecodeError):
            mod.decode("U2FsdGVkX18BAgMEBQYHCA")

    def test_wrong_document_rejected(self):
        with self.assertRaises(mod.DecodeError):
            mod.decode('{"Version":"1.0","Other":[]}')

    def test_summary_counts_only(self):
        doc = mod.decode(json.dumps(load_fixture("synthetic_catalog.json")))
        summary = mod.summary(doc)
        self.assertEqual(summary["Version"], "99.9")
        self.assertEqual(summary["Servers"], 1)
        self.assertEqual(summary["Tweaks"], 1)
        self.assertEqual(summary["Payloads"], 1)

    def test_run_returns_none_on_bad_input(self):
        self.assertIsNone(mod.run("ff"))


if __name__ == "__main__":
    unittest.main()
