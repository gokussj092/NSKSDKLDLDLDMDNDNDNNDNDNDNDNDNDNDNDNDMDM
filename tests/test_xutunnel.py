"""XU Tunnel 6.0 (com.technore.xrptunnelplus): .xu files only, no live catalog.

The .xu reader is the verified standalone script
decoders/Python/apps/XU_Tunnel/xutunnel_archivos.py (pure stdlib AES-256-CBC,
same format key as the repo's XUI Tunnel entry). PyCryptodome is used here
ONLY to build encryption vectors for the tests; the decoder never needs it.

Valid cases: the module's own TEST_VECTOR plus PyCryptodome-built round-trips
(full "XU Tunnel VPN" prefix and short "XU Tunnel" prefix). No real .xu file
has been supplied yet, so the file route is VERIFIED_SYNTHETIC. No live
catalog bytes or decrypted credentials are stored here.
"""
import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "decoders/Python/apps/XU_Tunnel"
spec = importlib.util.spec_from_file_location("xutunnel_archivos", APP / "xutunnel_archivos.py")
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)

try:
    from Crypto.Cipher import AES as _AES
    from Crypto.Util.Padding import pad as _pad
    _HAS_PYCRYPTODOME = True
except ImportError:  # Test-only vector builder; the decoder is stdlib-only.
    _HAS_PYCRYPTODOME = False

EXPECTED = {
    "ExpireDate": 1798761600000,
    "CFGMessage": "Test config",
    "SNIHost": "example.com",
    "ProxyPort": "8080",
    "isPassON": False,
}
FORBIDDEN = ("decoders/Python/", '"script":', "source_script", "privateKey")


def _encrypt_vector(prefix, doc, key=None):
    """Build a .xu wire (Base64) with PyCryptodome; IV 00..0f, fixed."""
    assert _HAS_PYCRYPTODOME
    plain = (prefix + json.dumps(doc, ensure_ascii=False)).encode("utf-8")
    cipher = _AES.new(key or reader.KEY_FIELD, _AES.MODE_CBC, bytes(range(16)))
    return base64.b64encode(bytes(range(16)) + cipher.encrypt(_pad(plain, 16))).decode("ascii")


class XUTunnelTests(unittest.TestCase):
    def test_self_test_vector_decodes(self):
        doc = reader.decode(reader.TEST_VECTOR)
        for key, value in EXPECTED.items():
            self.assertEqual(doc[key], value)
        out = reader.run(reader.TEST_VECTOR.encode())
        self.assertIsNotNone(out)
        self.assertEqual(json.loads(out), doc)

    def test_decoded_output_has_no_forbidden_strings(self):
        out = reader.run(reader.TEST_VECTOR.encode())
        self.assertIsNotNone(out)
        for forbidden in FORBIDDEN:
            self.assertNotIn(forbidden, out)

    @unittest.skipUnless(_HAS_PYCRYPTODOME, "PyCryptodome needed to build vectors")
    def test_round_trip_with_both_app_name_prefixes(self):
        doc = {"ExpireDate": 0, "CFGMessage": "hola", "SNIHost": "example.org"}
        for prefix in ("XU Tunnel VPN", "XU Tunnel"):
            wire = _encrypt_vector(prefix, doc)
            self.assertEqual(reader.decode(wire), doc)
            self.assertEqual(json.loads(reader.run(wire.encode())), doc)

    @unittest.skipUnless(_HAS_PYCRYPTODOME, "PyCryptodome needed to build vectors")
    def test_wrong_prefix_and_wrong_key_are_rejected(self):
        doc = {"ExpireDate": 0, "CFGMessage": "hola"}
        with self.assertRaises(reader.DecodeError) as failure:
            reader.decode(_encrypt_vector("Other Tunnel VPN", doc))
        self.assertEqual(failure.exception.code, "WRONG_DOCUMENT")
        self.assertIsNone(reader.run(_encrypt_vector("Other Tunnel VPN", doc).encode()))
        with self.assertRaises(reader.DecodeError):
            reader.decode(_encrypt_vector("XU Tunnel VPN", doc, key=b"\x00" * 32))

    def test_rejections_return_no_partial_result(self):
        raw = base64.b64decode(reader.TEST_VECTOR)
        corrupted = bytearray(raw)
        corrupted[-1] ^= 1
        cases = (
            b"",
            b"not-valid-base64!!!",
            reader.TEST_VECTOR[:40].encode(),
            base64.b64encode(bytes(corrupted)),
            b"<html/>",
            b"A" * (reader.MAX_BYTES + 1),
        )
        for wire in cases:
            with self.subTest(wire=wire[:24]):
                with self.assertRaises(reader.DecodeError):
                    reader.decode(wire)
                self.assertIsNone(reader.run(wire))

    def test_base64_line_breaks_are_supported(self):
        wire = reader.TEST_VECTOR
        wrapped = "\r\n".join(wire[i:i + 64] for i in range(0, len(wire), 64))
        self.assertEqual(reader.decode(wrapped), reader.decode(wire))

    def test_cli_self_test_and_file_run_outside_checkout(self):
        p = subprocess.run([sys.executable, str(APP / "xutunnel_archivos.py"), "--self-test"],
                           cwd="/tmp", capture_output=True, timeout=30)
        self.assertEqual(p.returncode, 0)
        self.assertIn(b"self-test OK", p.stdout)
        vector = Path("/tmp/xu-test-vector.xu")
        vector.write_bytes(reader.TEST_VECTOR.encode())
        try:
            p = subprocess.run([sys.executable, str(APP / "xutunnel_archivos.py"),
                                "--file", str(vector)], cwd="/tmp", capture_output=True, timeout=30)
            self.assertEqual(p.returncode, 0)
            self.assertEqual(json.loads(p.stdout), reader.decode(reader.TEST_VECTOR))
            self.assertEqual(p.stderr, b"")
        finally:
            vector.unlink(missing_ok=True)
        p = subprocess.run([sys.executable, str(APP / "xutunnel_archivos.py"),
                            "--file", str(vector)], cwd="/tmp",
                           capture_output=True, timeout=30)
        self.assertEqual(p.returncode, 1)
        self.assertEqual(p.stdout, b"")
        self.assertNotIn(b"sentinel", p.stderr)
        vector.write_bytes(b"private-input-sentinel")
        p = subprocess.run([sys.executable, str(APP / "xutunnel_archivos.py"),
                            "--file", str(vector)], cwd="/tmp",
                           capture_output=True, timeout=30)
        self.assertEqual(p.returncode, 1)
        self.assertEqual(p.stdout, b"")
        self.assertNotIn(b"sentinel", p.stderr)

    def test_cloud_worker_returns_whole_profile(self):
        from cloud.workers.python.engine import decode_file
        out = decode_file("xu", reader.TEST_VECTOR.encode())
        self.assertFalse(out["isPartial"])
        self.assertEqual(out["structuredJson"], reader.decode(reader.TEST_VECTOR))
        self.assertEqual(json.loads(out["rawText"]), reader.decode(reader.TEST_VECTOR))
        for forbidden in FORBIDDEN:
            self.assertNotIn(forbidden, out["rawText"])

    def test_cloud_rejects_corruption_and_unneeded_credentials(self):
        from cloud.workers.python.engine import decode_file, DecodeFailure
        raw = bytearray(base64.b64decode(reader.TEST_VECTOR))
        raw[-1] ^= 1
        with self.assertRaises(DecodeFailure) as failure:
            decode_file("xu", base64.b64encode(raw))
        self.assertEqual(failure.exception.code, "DECODE_FAILED")
        with self.assertRaises(DecodeFailure) as failure:
            decode_file("xu", reader.TEST_VECTOR.encode(), credentials={"hwid": "synthetic-id"})
        self.assertEqual(failure.exception.code, "CREDENTIALS_NOT_ALLOWED")

    def test_cloud_catalog_is_file_only_and_c0_is_unchanged(self):
        from cloud.workers.python.engine import load_file_engines, load_runtime_file_engines
        self.assertEqual(len(load_file_engines()), 240)
        # New unrelated verified providers may extend the runtime registry.
        self.assertGreaterEqual(len(load_runtime_file_engines()), 271)
        self.assertNotIn("xu", load_file_engines())
        extended = load_runtime_file_engines()
        self.assertIn("/apps/XU_Tunnel/xutunnel_archivos.py", extended["xu"]["source"])
        self.assertEqual(extended["xu"]["phase"], "C8")
        entries = json.loads((ROOT / "cloud/web/content/file-formats.json").read_text())["formats"]
        entry = next(x for x in entries if x["suffix"] == "xu")
        self.assertEqual(entry, {"suffix": "xu", "name": "XU Tunnel VPN 6.0", "kind": "file",
                                 "offlineSupported": False, "cloudSupported": True,
                                 "credentialFields": []})
        supplied = json.loads((ROOT / "cloud/web/content/supplied-integrations.json").read_text())
        item = next(x for x in supplied["apps"] if x["id"] == "xu-tunnel")
        self.assertEqual(item["catalogState"], "FILE_ONLY")
        self.assertEqual(item["requests"], [])
        self.assertEqual(item["extensions"], ["xu"])
        self.assertEqual(item["fileModule"], "xutunnel_archivos.py")
        self.assertEqual(item["textPrefixes"], [])
        self.assertNotIn("catalogModule", item)

    def test_catalog_decode_fails_closed_without_a_catalog(self):
        # FILES ONLY: no broker, no catalog module, no card. Asking the
        # catalog worker must fail closed, never return a partial catalog.
        from cloud.workers.python.engine import decode_provider_catalog, DecodeFailure
        with self.assertRaises(DecodeFailure) as failure:
            decode_provider_catalog("xu-tunnel", b"synthetic")
        self.assertEqual(failure.exception.code, "DECODE_FAILED")


if __name__ == "__main__":
    unittest.main()
