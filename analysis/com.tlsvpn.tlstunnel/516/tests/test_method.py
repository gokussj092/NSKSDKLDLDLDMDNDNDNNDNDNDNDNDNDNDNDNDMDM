"""Tests for the TLS Tunnel offline dossier (Python oracle + fixtures).

Covers the same ground as the repo suite tests/test_tls_decoder.py but
against this dossier's own fixtures: all six key profiles open, the
legacy profile keeps the old DNS names, tls:// links open, short
plaintexts get defaults, invalid inner Base64 is preserved, and tampered
/ truncated / garbage / empty inputs are rejected. The C++ comparison
lives in tools/run_harness.py; this file tests the oracle itself.

Run from the dossier directory:
  <venv python> -m unittest tests.test_method -v
"""
import base64
import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

DOSSIER = Path(__file__).resolve().parents[1]
REPO_ROOT = DOSSIER.parents[2]
FIXTURES = DOSSIER / "tests" / "fixtures"

TLS_PY = REPO_ROOT / "decoders" / "Python" / "TLS.py"
spec = importlib.util.spec_from_file_location("tls_dossier_oracle", TLS_PY)
tls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tls)

sys.dont_write_bytecode = True


def load(name):
    return (FIXTURES / name).read_bytes().decode("utf-8-sig")


def decode(name):
    return tls._render_config(tls.decrypt_tls_payload(load(name)))


class DossierTests(unittest.TestCase):
    def test_all_six_profiles_open(self):
        for profile in range(1, 7):
            name = (f"tls-profile{profile}.tls" if profile < 6
                    else "tls-profile6-legacy.tls")
            with self.subTest(profile=profile):
                result = decode(name)
                if profile < 6:
                    self.assertEqual(result["_tls"]["key_profile"], profile)
                    self.assertEqual(result["_tls"]["field_count"], 28)
                else:
                    self.assertNotIn("_tls", result)
                self.assertEqual(result["tlsvpnVersion"],
                                 516 if profile < 6 else 300)
                self.assertEqual(result["sshuser"],
                                 "usuario-prueba" if profile < 6
                                 else "usuario-antiguo")

    def test_legacy_named_fields(self):
        result = decode("tls-profile6-legacy.tls")
        self.assertEqual(result["legacy_dns_mode"], 2)
        self.assertEqual(result["dnsP"], "dns.ejemplo.test")
        self.assertEqual(result["dns_port"], "53")
        self.assertEqual(result["nameserver"], "8.8.8.8")
        self.assertEqual(result["public_key"], "clave-publica-antigua")

    def test_modern_profiles_keep_positional_fields(self):
        result = decode("tls-profile1.tls")
        self.assertNotIn("legacy_dns_mode", result)
        self.assertEqual(result["_tls"]["fields"][20]["raw"], "true")
        self.assertEqual(result["_tls"]["fields"][4]["value"], "usuario-prueba")

    def test_tls_link_and_short_plaintext(self):
        link = decode("tls-link.txt")
        self.assertEqual(link["_tls"]["key_profile"], 1)
        self.assertEqual(link["sshhost"], "ejemplo.test")
        short = decode("tls-short.tls")
        self.assertEqual(short["sshuser"], "solo-usuario")
        self.assertEqual(short["port"], 443)
        self.assertEqual(short["metodo"], 0)

    def test_invalid_inner_base64_preserved(self):
        result = decode("tls-profile3-bad-inner-b64.tls")
        self.assertEqual(result["sshuser"], "!!!no-es-base64!!!")

    def test_negatives_rejected(self):
        for name in ("tls-tampered.tls", "tls-truncated.tls",
                     "tls-garbage.tls", "tls-empty.tls"):
            with self.subTest(fixture=name):
                with self.assertRaises(ValueError):
                    tls.decrypt_tls_payload(load(name))

    def test_output_schema(self):
        result = decode("tls-profile1.tls")
        for key in ("tlsvpnVersion", "server", "port", "pserver", "sshuser",
                    "sshpass", "sshhost", "metodo", "upayload", "payload",
                    "usnihost", "snihost", "bloqmc"):
            self.assertIn(key, result)
        json.dumps(result)  # must be JSON-serializable
        manifest = json.loads((FIXTURES / "fixtures.json").read_text())
        for name, entry in manifest.items():
            if "sha256" in entry:
                data = (FIXTURES / name).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(),
                                 entry["sha256"], name)


if __name__ == "__main__":
    unittest.main()
