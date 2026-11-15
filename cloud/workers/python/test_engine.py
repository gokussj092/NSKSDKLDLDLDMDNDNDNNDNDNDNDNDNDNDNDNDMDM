"""C2 deterministic validation: no runtime names, shell paths, or secrets from callers."""
from __future__ import annotations

import os
import json
import importlib.util
import tempfile
import unittest
from pathlib import Path

from engine import (
    DecodeFailure, MAX_INPUT_BYTES, ROOT, _child_env,
    _is_beevpn_bee, _is_eut_new_sza, _is_eut_payload, _C8_GENERIC_FALLBACK,
    decode_file, decode_text, load_file_engines, load_runtime_file_engines,
)

CATALOGS = Path.home() / "workspace" / "catalogs"


def _read_sample(path):
    return Path(path).read_bytes()


class ContentDiscriminatorTests(unittest.TestCase):
    """Shared-suffix content dispatch (2026-11-15 batch).

    Predicates inspect bytes only; real samples are read, never copied.
    Sample-based cases skip when the work samples are absent (CI without
    ~/workspace/catalogs); synthetic vectors always run.
    """

    def test_runtime_map_has_new_suffixes(self):
        engines = load_runtime_file_engines()
        for suffix in ("hs", "bbtun", "bee", "wyr", "tcx", "eut"):
            self.assertIn(suffix, engines)
        self.assertEqual(engines["hs"]["phase"], "C8")
        self.assertEqual(engines["bbtun"]["phase"], "C8")

    def test_fallback_keeps_frozen_c0_for_shared_suffixes(self):
        for suffix in ("bee", "wyr", "tcx", "eut"):
            self.assertIn(suffix, _C8_GENERIC_FALLBACK)

    def test_bee_marker_shape(self):
        import base64
        blob = base64.b64encode(bytes(44)).decode()
        self.assertFalse(_is_beevpn_bee(blob.encode()))
        marked = blob[:3] + "Q" + blob[3:]
        self.assertEqual(len(marked) % 4, 1)
        self.assertTrue(_is_beevpn_bee(marked.encode()))
        self.assertFalse(_is_beevpn_bee((blob[:3] + "7" + blob[3:]).encode()))
        for bad in (b"abcd", b"", b"not base64 at all!!!", b"\x00\x01\x02\x03\x04"):
            self.assertFalse(_is_beevpn_bee(bad))

    @unittest.skipUnless((CATALOGS / "beevpn" / "muestra.bee").is_file(),
                         "BeeVPN real sample absent")
    def test_bee_real_sample_is_marker_shaped(self):
        raw = _read_sample(CATALOGS / "beevpn" / "muestra.bee")
        self.assertTrue(_is_beevpn_bee(raw))
        text = raw.decode().strip()
        self.assertEqual(len(text) % 4, 1)
        self.assertTrue(text[3].isalpha())
        self.assertFalse(_is_beevpn_bee((text[:3] + text[4:]).encode()))

    @unittest.skipUnless((CATALOGS / "beevpn" / "muestra.bee").is_file() and
                         importlib.util.find_spec("argon2") is not None,
                         "BeeVPN sample or argon2-cffi absent")
    def test_bee_marker_sample_opens_by_new_route(self):
        expected = json.loads((CATALOGS / "beevpn" / "muestra.bee.json").read_text("utf-8"))
        decoded = decode_file("bee", _read_sample(CATALOGS / "beevpn" / "muestra.bee"))
        self.assertEqual(decoded["status"], "success")
        self.assertEqual(decoded["structuredJson"], expected)

    def test_bee_plain_envelope_stays_on_frozen_route(self):
        import base64
        blob = base64.b64encode(bytes(44))
        with self.assertRaises(DecodeFailure) as caught:
            decode_file("bee", blob)
        self.assertEqual(caught.exception.code, "DECODE_FAILED")

    def test_eut_new_sza_shape(self):
        import base64
        iv = base64.b64encode(bytes(range(16))).decode()
        ct = base64.b64encode(bytes(32)).decode()
        self.assertFalse(_is_eut_new_sza(f"{ct}:{iv}".encode()))
        self.assertFalse(_is_eut_new_sza(f"eut-settings://{ct}:{iv}".encode()))
        self.assertFalse(_is_eut_new_sza(b"hello world"))
        self.assertFalse(_is_eut_new_sza(b"eut-settings://onlyonefield"))
        self.assertFalse(_is_eut_payload(b"eut-settings://AAAA:BBBB"))
        self.assertTrue(_is_eut_payload(b"eut-payload://AAAA"))
        self.assertFalse(_is_eut_payload(b"wyrvpn://AAAA"))

    @unittest.skipUnless((CATALOGS / "eut" / "muestras" / "sample_settings.eut").is_file(),
                         "EUT real sample absent")
    def test_eut_real_samples_route_new(self):
        raw = _read_sample(CATALOGS / "eut" / "muestras" / "sample_settings.eut")
        self.assertTrue(_is_eut_new_sza(raw))
        self.assertFalse(_is_eut_payload(raw))
        payload = _read_sample(CATALOGS / "eut" / "muestras" / "sample_payload.txt")
        self.assertTrue(_is_eut_payload(payload))
        self.assertFalse(_is_eut_new_sza(payload))

    @unittest.skipUnless((CATALOGS / "eut" / "muestras" / "sample_settings.eut").is_file(),
                         "EUT real sample absent")
    def test_eut_new_sza_sample_opens_by_new_route(self):
        expected = json.loads((CATALOGS / "eut" / "muestras" / "sample_settings.json").read_text("utf-8"))
        decoded = decode_file("eut", _read_sample(CATALOGS / "eut" / "muestras" / "sample_settings.eut"))
        self.assertEqual(decoded["status"], "success")
        self.assertEqual(decoded["structuredJson"], expected)

    @unittest.skipUnless((CATALOGS / "eut" / "muestras" / "sample_payload.txt").is_file(),
                         "EUT real sample absent")
    def test_eut_payload_link_opens_by_new_route(self):
        expected = json.loads((CATALOGS / "eut" / "muestras" / "sample_payload.json").read_text("utf-8"))
        text = (CATALOGS / "eut" / "muestras" / "sample_payload.txt").read_text("utf-8")
        decoded = decode_text(text)
        self.assertEqual(decoded["status"], "success")
        self.assertEqual(decoded["structuredJson"], expected)

    @unittest.skipUnless((CATALOGS / "jkvpn" / "samples" / "test_vector.hs").is_file(),
                         "JK VPN real sample absent")
    def test_hs_jk_vector_opens_by_jk_route(self):
        decoded = decode_file("hs", _read_sample(CATALOGS / "jkvpn" / "samples" / "test_vector.hs"))
        self.assertEqual(decoded["status"], "success")
        structured = decoded["structuredJson"]
        self.assertIsInstance(structured, dict)
        self.assertIn("Version", structured)
        self.assertIsInstance(structured.get("Servers"), list)

    @unittest.skipUnless((CATALOGS / "rhtunnel" / "samples" / "muestra-sintetica.hs").is_file(),
                         "RH Tunnel Lite real sample absent")
    def test_hs_rh_sample_opens_by_rh_route(self):
        decoded = decode_file("hs", _read_sample(CATALOGS / "rhtunnel" / "samples" / "muestra-sintetica.hs"))
        self.assertEqual(decoded["status"], "success")
        self.assertIn("Name", decoded["structuredJson"])

    @unittest.skipUnless((CATALOGS / "wyrvpn" / "Tanzania_-_Vodacom_FR_2_26_0_8vue.wyr").is_file(),
                         "WyrVPN real sample absent")
    def test_wyr_real_file_opens_by_new_route(self):
        decoded = decode_file("wyr", _read_sample(CATALOGS / "wyrvpn" / "Tanzania_-_Vodacom_FR_2_26_0_8vue.wyr"))
        self.assertEqual(decoded["status"], "success")
        self.assertIsInstance(decoded["structuredJson"], list)
        self.assertEqual(len(decoded["structuredJson"]), 1)

class FileEngineTests(unittest.TestCase):
    def test_catalog_contains_240_source_exact_paths(self):
        engines = load_file_engines()
        self.assertEqual(len(engines), 240)
        self.assertEqual(engines["solid"]["runtime"], "python")
        self.assertEqual(engines["hat"]["runtime"], "node")
        self.assertIn("php", {row["runtime"] for row in engines.values()})
        self.assertTrue(all(Path(entry["source"]).is_file() for entry in engines.values()))

    def test_invalid_format_never_falls_back_to_other_key(self):
        for ext in ("../tls", "tls;cat", ".tls", "", "unlisted", "/tmp/input.tls"):
            with self.subTest(ext=ext), self.assertRaises(DecodeFailure) as caught:
                decode_file(ext, b"arbitrary")
            self.assertEqual(caught.exception.code, "UNSUPPORTED_FORMAT")

    def test_input_size_and_empty_bytes(self):
        for payload, code in [(b"", "INVALID_INPUT"), (b"x" * (MAX_INPUT_BYTES + 1), "INPUT_TOO_LARGE")]:
            with self.subTest(code=code), self.assertRaises(DecodeFailure) as caught:
                decode_file("tls", payload)
            self.assertEqual(caught.exception.code, code)

    @unittest.skipUnless(importlib.util.find_spec("Crypto") is not None,
                         "PyCryptodome absent in dependency-free C1 checks")
    def test_signed_npvs_worker_matches_source_decoder(self):
        """Actual signed v5 bytes, through the Cloud child-process adapter."""
        from scripts.android_npvs_fixture_export import export

        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)
            export(output)
            contents=(output/"npvs-v5-appkey.npvs").read_bytes()
            expected=json.loads((output/"npvs-v5-appkey.json").read_text("utf-8"))
            received=decode_file("npvs", contents)
            self.assertEqual(received["status"], "success")
            self.assertFalse(received["isPartial"])
            self.assertEqual(json.loads(received["rawText"]), expected)
            self.assertEqual(received["structuredJson"], expected)

    @unittest.skipUnless(importlib.util.find_spec("Crypto") is not None,
                         "PyCryptodome absent in dependency-free C1 checks")
    def test_ultra_custom_file_and_text_password_contract(self):
        """Only verified Ultra Custom vectors can trigger and unlock UAP1."""
        fixture=json.loads((ROOT/"tests/golden/ultra_custom_52_vectors.json").read_text("utf-8"))
        vectors={entry["name"]:entry["data"] for entry in fixture["vectors"]}
        password=fixture["password"]
        for name in ("single-password","bundle-mixed-password"):
            raw=vectors[name].encode("utf-8")
            with self.subTest(name=name), self.assertRaises(DecodeFailure) as caught:
                decode_file("ua",raw)
            self.assertEqual(caught.exception.code,"PASSWORD_REQUIRED")
            with self.assertRaises(DecodeFailure) as caught:
                decode_file("ua",raw,credentials={"password":"incorrect"})
            self.assertEqual(caught.exception.code,"AUTH_FAILED")
            decoded=decode_file("ua",raw,credentials={"password":password})
            self.assertEqual(decoded["status"],"success")
            self.assertIsNotNone(decoded["structuredJson"])
        link="ua://"+vectors["link-password"]
        with self.assertRaises(DecodeFailure) as caught:
            decode_text(link)
        self.assertEqual(caught.exception.code,"PASSWORD_REQUIRED")
        with self.assertRaises(DecodeFailure) as caught:
            decode_text(link,credentials={"password":"incorrect"})
        self.assertEqual(caught.exception.code,"AUTH_FAILED")
        decoded=decode_text(link,credentials={"password":password})
        self.assertEqual(decoded["status"],"success")
        with self.assertRaises(DecodeFailure) as caught:
            decode_text("tls://abcd",credentials={"password":password})
        self.assertEqual(caught.exception.code,"INVALID_CREDENTIALS")
        with self.assertRaises(DecodeFailure) as caught:
            decode_file("npvs",b"unrelated",credentials={"hwid":"unsupported"})
        self.assertEqual(caught.exception.code,"CREDENTIALS_NOT_ALLOWED")

    def test_npvs_appkey_failure_is_ambiguous_variant_not_private_key(self):
        """Worker output is allowlisted; a signed app-key failure is not ECDH."""
        from unittest.mock import patch

        def process_for(code):
            class FakeProcess:
                returncode = 3
                def __init__(self, *args, stdout, **kwargs):
                    stdout.write(json.dumps({"workerError": code}).encode("utf-8"))
                    stdout.flush()
                def communicate(self, *, input, timeout):
                    return b"", b""
            return FakeProcess

        for raw_code, expected in (
            ("NPVS_APPKEY_AUTH_FAILED", "UNSUPPORTED_VARIANT"),
            ("PRIVATE_KEY_REQUIRED", "PRIVATE_KEY_REQUIRED"),
            ("AUTH_FAILED", "AUTH_FAILED"),
            ("UNSUPPORTED_METHOD", "UNSUPPORTED_METHOD"),
            ("INVALID_INPUT", "INVALID_INPUT"),
        ):
            with self.subTest(code=raw_code):
                with patch("engine.subprocess.Popen", process_for(raw_code)):
                    with self.assertRaises(DecodeFailure) as caught:
                        decode_file("npvs", b"opaque-envelope")
                self.assertEqual(caught.exception.code, expected)

    def test_subprocess_environment_removes_secrets(self):
        os.environ["CLOUD_WORKER_TOKEN"] = "private-test-only-do-not-ship"
        try:
            env = _child_env("/tmp/private")
            self.assertNotIn("CLOUD_WORKER_TOKEN", env)
            self.assertNotIn("DATABASE_URL", env)
            self.assertEqual(env["PYTHONPATH"], str(ROOT))
            self.assertEqual(env["HOME"], "/tmp/private")
        finally:
            os.environ.pop("CLOUD_WORKER_TOKEN", None)

if __name__ == "__main__":
    unittest.main()
