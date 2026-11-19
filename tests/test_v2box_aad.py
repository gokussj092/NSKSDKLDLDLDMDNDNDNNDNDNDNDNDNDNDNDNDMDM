"""V2Box 6.2.3 — AAD regression tests (synthetic fixtures only).

Covers the 2026-11-19 correction: v2 GCM AAD is the Base64 header
string as it appears in the envelope (verified against a real v2
kdf-none file); the raw header JSON bytes remain as an unverified
fallback. No real file, no network, no secrets.
"""
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "v2box_archivos",
    ROOT / "decoders/Python/apps/V2Box/V2Box_archivos.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def _payload():
    return {"configs": [{"name": "Synthetic v2", "type": "link",
                         "value": "vmess://eyJ2IjoiMiJ9",
                         "profile": None, "raw": None}],
            "subscription": None, "locked": False, "lockMessage": ""}


class V2BoxAadTest(unittest.TestCase):
    def test_v2_none_opens_with_header_b64_aad(self):
        blob = MOD._selftest_encrypt_v2(_payload())
        result = MOD.decode_file(blob)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["kdf"], "none")
        self.assertEqual(result.get("aad"), "header-b64")
        self.assertEqual(result["profiles"][0]["type"], "link")

    def test_v2_none_fallback_header_bytes_aad(self):
        blob = MOD._selftest_encrypt_v2(_payload(), aad_raw_bytes=True)
        result = MOD.decode_file(blob)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result.get("aad"), "header-bytes")

    def test_v2_none_wrong_aad_is_tag_mismatch(self):
        header = {"v": 2, "kdf": "none", "salt": None, "iterations": None,
                  "expiresAt": None, "deviceIds": None, "recipients": None,
                  "createdAt": 1790000000}
        header_bytes = json.dumps(header, ensure_ascii=False).encode()
        nonce = bytes(range(12, 24))
        ct, tag = MOD._aes_gcm_encrypt(
            MOD.V2BOX_KEY, nonce,
            json.dumps(_payload(), ensure_ascii=False).encode(),
            aad=b"aad-que-no-es-ningun-candidato")
        blob = json.dumps(
            {"magic": MOD.MAGIC, "version": 2,
             "header": MOD._b64e(header_bytes), "nonce": MOD._b64e(nonce),
             "ciphertext": MOD._b64e(ct), "tag": MOD._b64e(tag)}).encode()
        with self.assertRaises(MOD.DecodeError) as ctx:
            MOD.decode_file(blob)
        self.assertEqual(ctx.exception.code, "TAG_MISMATCH")

    def test_v1_without_password_still_opens(self):
        payload = {"a": [{"remarks": "Synthetic v1", "configType": "Vmess",
                          "server": "1.2.3.4", "serverPort": "443"}], "b": {}}
        result = MOD.decode_file(MOD._selftest_encrypt_v1(payload))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["profiles"][0]["server"], "1.2.3.4")

    def test_v2_pbkdf2_uses_header_b64_aad(self):
        blob = MOD._selftest_encrypt_v2(_payload(), password="Secreto123")
        result = MOD.decode_file(blob, password="Secreto123")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["kdf"], "pbkdf2-sha256")
        self.assertEqual(result.get("aad"), "header-b64")


if __name__ == "__main__":
    unittest.main()
