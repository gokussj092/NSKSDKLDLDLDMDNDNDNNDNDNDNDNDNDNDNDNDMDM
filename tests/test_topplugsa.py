"""TOP-PLUG-SA VPN 0.29.26 (mobi.ascensionrpg.khonavpn.activationtest): .tpc files only.

The .tpc reader is the standalone script
decoders/Python/apps/TopPlugSA/topplugsa.py (AES-256-GCM / PBKDF2-HMAC-SHA256 /
ECDSA P-256, format keys from the APK). PyCryptodome is used here ONLY to
build encryption vectors for the tests; the decoder needs it at runtime too
(see requirements.txt).

Verification states (honest, see README.md): TOPPLUG4 is VERIFIED_REAL
(real APK sample, GCM tag valid — the sample itself is NOT in the repo,
it carries credentials); TOPPLUG5 is a round-trip (no real sample yet);
TOPPLUG1 and TOPPLUG-MANUAL-V2 are VERIFIED_SYNTHETIC; TOPPLUG2 is
device-bound — its signature verifies but the profile is NEVER returned.
No live catalog bytes or decrypted credentials are stored here: every
vector below uses example.com and synthetic passwords.
"""
import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "decoders/Python/apps/TopPlugSA"
spec = importlib.util.spec_from_file_location("topplugsa", APP / "topplugsa.py")
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)

try:
    from Crypto.Cipher import AES as _AES
    from Crypto.Hash import SHA256 as _SHA256
    from Crypto.Protocol.KDF import PBKDF2 as _PBKDF2
    from Crypto.PublicKey import ECC as _ECC
    from Crypto.Signature import DSS as _DSS
    from Crypto.Util.asn1 import DerSequence as _DerSequence
    _HAS_PYCRYPTODOME = True
except ImportError:  # Test-only vector builder.
    _HAS_PYCRYPTODOME = False

DOC4 = {"format": "topplug", "version": 4,
        "id": "224b9616-8b46-4b21-9240-7b98ca1a1c77",
        "name": "prueba", "issued_at": 1794894665, "expires_at": 0,
        "device_id": "", "locked": True,
        "profile": {"protocol": "ssh", "server": "example.com", "port": 443,
                    "username": "u", "password": "p", "ssh_mode": "direct_tls"}}
PASSWORD = "contrasena-de-prueba"
FORBIDDEN = ("decoders/Python/", '"script":', "source_script", "privateKey")


def _der_sig(priv, message):
    h = _SHA256.new(message)
    sig = _DSS.new(priv, "fips-186-3").sign(h)
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    return _DerSequence([r, s]).encode()


def _encrypt_tpc5(doc, password):
    """Build a TOPPLUG5 wire (TOPPLUG4 inside) with PyCryptodome."""
    import os
    assert _HAS_PYCRYPTODOME
    inner = reader._encrypt_tpc4(doc)
    salt, nonce = os.urandom(16), os.urandom(12)
    key = _PBKDF2(password.encode("utf-8"), salt, dkLen=32, count=600000,
                  hmac_hash_module=_SHA256)
    cipher = _AES.new(key, _AES.MODE_GCM, nonce=nonce)
    cipher.update(b"TOPPLUG-PASSWORD-V5\n")
    ct, tag = cipher.encrypt_and_digest(inner.encode("utf-8"))
    return "TOPPLUG5\n" + base64.b64encode(salt + nonce + ct + tag).decode("ascii")


class TopPlugSATests(unittest.TestCase):
    def test_tpc4_roundtrip_decodes(self):
        wire = reader._encrypt_tpc4(DOC4)
        doc = reader.decrypt_tpc(wire)
        self.assertEqual(doc["kind"], "portable-v4")
        self.assertEqual(doc["profile"]["server"], "example.com")
        self.assertEqual(doc["profile"]["ssh_mode"], "direct_tls")
        out = reader.run(wire.encode())
        self.assertIsNotNone(out)
        self.assertEqual(json.loads(out), doc)

    @unittest.skipUnless(_HAS_PYCRYPTODOME, "PyCryptodome needed to build vectors")
    def test_tpc5_roundtrip_and_password_rules(self):
        wire = _encrypt_tpc5(DOC4, PASSWORD)
        doc = reader.decode(wire.encode(), password=PASSWORD)
        self.assertEqual(doc["kind"], "password-v5")
        self.assertTrue(doc["password_file"])
        self.assertEqual(doc["profile"]["server"], "example.com")
        with self.assertRaises(reader.TopPlugDecodeError) as failure:
            reader.decode(wire.encode())
        self.assertEqual(failure.exception.code, "PASSWORD_REQUIRED")
        with self.assertRaises(reader.TopPlugDecodeError) as failure:
            reader.decode(wire.encode(), password="corta")
        self.assertEqual(failure.exception.code, "INVALID_CREDENTIALS")
        with self.assertRaises(reader.TopPlugDecodeError) as failure:
            reader.decode(wire.encode(), password="clave-incorrecta")
        self.assertEqual(failure.exception.code, "AUTH_FAILED")

    @unittest.skipUnless(_HAS_PYCRYPTODOME, "PyCryptodome needed to build vectors")
    def test_tpc1_synthetic_signature_verifies(self):
        priv = _ECC.generate(curve="P-256")
        doc = {"format": "topplug", "version": 2, "id": "prueba-1",
               "name": "prueba1", "issued_at": 1794894665, "expires_at": 0,
               "device_id": "",
               "profile": {"protocol": "vless", "server": "example.com", "port": 443}}
        body = json.dumps(doc)
        der = _der_sig(priv, ("TOPPLUG-OFFLINE-V1\n" + body).encode("utf-8"))
        text = "TOPPLUG1\n" + der.hex() + "\n" + body
        out = reader._parse_tpc1(text, priv.public_key().export_key(format="DER"))
        self.assertEqual(out["kind"], "signed-offline-v2")
        self.assertEqual(out["profile"]["protocol"], "vless")
        # End to end through decode(): the generated key is NOT the issuer
        # key, so a synthetic TOPPLUG1 must fail closed here.
        with self.assertRaises(reader.TopPlugDecodeError):
            reader.decode(text.encode())

    @unittest.skipUnless(_HAS_PYCRYPTODOME, "PyCryptodome needed to build vectors")
    def test_tpc2_signature_verifies_but_profile_is_never_returned(self):
        priv = _ECC.generate(curve="P-256")
        doc = {"format": "topplug", "version": 3,
               "id": "0123456789abcdef0123456789abcdef",
               "name": "prueba2", "issued_at": 1794894665, "expires_at": 0,
               "device_id": "0123456789abcdef",
               "nonce": base64.b64encode(b"\x00" * 12).decode("ascii"),
               "ciphertext": base64.b64encode(b"\x00" * 32).decode("ascii")}
        body = json.dumps(doc)
        der = _der_sig(priv, ("TOPPLUG-SEALED-V3\n" + body).encode("utf-8"))
        text = "TOPPLUG2\n" + der.hex() + "\n" + body
        out = reader._parse_tpc2(text, priv.public_key().export_key(format="DER"))
        self.assertEqual(out["kind"], "sealed-v3-device-bound")
        self.assertIsNone(out["profile"])
        self.assertTrue(out["device_locked"])
        self.assertIn("teléfono dueño", out["note"])

    def test_manual_v2_cleartext(self):
        doc = {"format": "topplug", "version": 2, "name": "prueba-manual",
               "profile": {"protocol": "ssh", "server": "example.com", "port": 443}}
        out = reader.decode(("TOPPLUG-MANUAL-V2\n" + json.dumps(doc)).encode())
        self.assertEqual(out["kind"], "manual-v2")
        self.assertEqual(out["profile"]["server"], "example.com")

    def test_decoded_output_has_no_forbidden_strings(self):
        out = reader.run(reader._encrypt_tpc4(DOC4).encode())
        for forbidden in FORBIDDEN:
            self.assertNotIn(forbidden, out)

    def test_rejections_return_no_partial_result(self):
        wire = reader._encrypt_tpc4(DOC4)
        raw = bytearray(base64.b64decode(wire[len("TOPPLUG4\n"):]))
        raw[-1] ^= 1
        bad_version = dict(DOC4, version=5)
        cases = (
            b"",
            b"no-es-un-tpc",
            b"TOPPLUG4\nnot-valid-base64!!!",
            (wire[:40]).encode(),
            ("TOPPLUG4\n" + base64.b64encode(bytes(raw)).decode("ascii")).encode(),
            b"<html/>",
            b"A" * (reader.MAX_BYTES + 1),
            reader._encrypt_tpc4(bad_version).encode(),
        )
        for wire_case in cases:
            with self.subTest(wire=wire_case[:24]):
                with self.assertRaises(reader.TopPlugDecodeError):
                    reader.decode(wire_case)

    def test_cli_self_test_and_file_run_outside_checkout(self):
        p = subprocess.run([sys.executable, str(APP / "topplugsa.py"), "self-test"],
                           cwd="/tmp", capture_output=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout.decode("utf-8", "replace"))
        self.assertIn(b"self-test:", p.stdout)
        vector = Path("/tmp/topplug-test-vector.tpc")
        vector.write_text(reader._encrypt_tpc4(DOC4))
        try:
            p = subprocess.run([sys.executable, str(APP / "topplugsa.py"), str(vector)],
                               cwd="/tmp", input=b"{}", capture_output=True, timeout=30)
            self.assertEqual(p.returncode, 0)
            self.assertEqual(json.loads(p.stdout), reader.decode(vector.read_bytes()))
            self.assertEqual(p.stderr, b"")
        finally:
            vector.unlink(missing_ok=True)
        p = subprocess.run([sys.executable, str(APP / "topplugsa.py"), str(vector)],
                           cwd="/tmp", input=b"{}", capture_output=True, timeout=30)
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(p.stdout, b"")
        vector.write_bytes(b"private-input-sentinel")
        p = subprocess.run([sys.executable, str(APP / "topplugsa.py"), str(vector)],
                           cwd="/tmp", input=b"{}", capture_output=True, timeout=30)
        self.assertEqual(p.returncode, 1)
        self.assertEqual(p.stdout, b"")
        self.assertNotIn(b"sentinel", p.stderr)

    @unittest.skipUnless(_HAS_PYCRYPTODOME, "PyCryptodome needed to build vectors")
    def test_cli_password_required_exits_3_without_password(self):
        vector = Path("/tmp/topplug-test-vector5.tpc")
        vector.write_text(_encrypt_tpc5(DOC4, PASSWORD))
        try:
            p = subprocess.run([sys.executable, str(APP / "topplugsa.py"), str(vector)],
                               cwd="/tmp", input=b"{}", capture_output=True, timeout=60)
            self.assertEqual(p.returncode, 3)
            self.assertEqual(json.loads(p.stdout), {"workerError": "PASSWORD_REQUIRED"})
            p = subprocess.run([sys.executable, str(APP / "topplugsa.py"), str(vector)],
                               cwd="/tmp", input=json.dumps({"password": PASSWORD}).encode(),
                               capture_output=True, timeout=60)
            self.assertEqual(p.returncode, 0)
            self.assertEqual(json.loads(p.stdout)["profile"]["server"], "example.com")
        finally:
            vector.unlink(missing_ok=True)

    def test_cloud_worker_returns_whole_profile(self):
        from cloud.workers.python.engine import decode_file
        wire = reader._encrypt_tpc4(DOC4)
        out = decode_file("tpc", wire.encode())
        self.assertFalse(out["isPartial"])
        self.assertEqual(out["structuredJson"], reader.decode(wire.encode()))
        self.assertEqual(json.loads(out["rawText"]), reader.decode(wire.encode()))
        for forbidden in FORBIDDEN:
            self.assertNotIn(forbidden, out["rawText"])

    @unittest.skipUnless(_HAS_PYCRYPTODOME, "PyCryptodome needed to build vectors")
    def test_cloud_rejects_corruption_and_unneeded_credentials(self):
        from cloud.workers.python.engine import decode_file, DecodeFailure
        wire = reader._encrypt_tpc4(DOC4)
        raw = bytearray(base64.b64decode(wire[len("TOPPLUG4\n"):]))
        raw[-1] ^= 1
        corrupted = "TOPPLUG4\n" + base64.b64encode(bytes(raw)).decode("ascii")
        with self.assertRaises(DecodeFailure) as failure:
            decode_file("tpc", corrupted.encode())
        self.assertEqual(failure.exception.code, "DECODE_FAILED")
        wire5 = _encrypt_tpc5(DOC4, PASSWORD)
        with self.assertRaises(DecodeFailure) as failure:
            decode_file("tpc", wire5.encode())
        self.assertEqual(failure.exception.code, "PASSWORD_REQUIRED")
        with self.assertRaises(DecodeFailure) as failure:
            decode_file("tpc", wire5.encode(), credentials={"password": "clave-incorrecta"})
        self.assertEqual(failure.exception.code, "AUTH_FAILED")
        with self.assertRaises(DecodeFailure) as failure:
            decode_file("tpc", wire.encode(), credentials={"hwid": "synthetic-id"})
        self.assertEqual(failure.exception.code, "CREDENTIALS_NOT_ALLOWED")

    def test_cloud_catalog_is_file_only_and_c0_is_unchanged(self):
        from cloud.workers.python.engine import load_file_engines, load_runtime_file_engines
        self.assertEqual(len(load_file_engines()), 240)
        # New unrelated verified providers may extend the runtime registry.
        self.assertGreaterEqual(len(load_runtime_file_engines()), 283)
        self.assertNotIn("tpc", load_file_engines())
        extended = load_runtime_file_engines()
        self.assertIn("/apps/TopPlugSA/topplugsa.py", extended["tpc"]["source"])
        self.assertEqual(extended["tpc"]["phase"], "C8")
        entries = json.loads((ROOT / "cloud/web/content/file-formats.json").read_text())["formats"]
        entry = next(x for x in entries if x["suffix"] == "tpc")
        self.assertEqual(entry, {"suffix": "tpc", "name": "TOP-PLUG-SA VPN 0.29.26", "kind": "file",
                                 "offlineSupported": False, "cloudSupported": True,
                                 "credentialFields": ["password"]})
        supplied = json.loads((ROOT / "cloud/web/content/supplied-integrations.json").read_text())
        item = next(x for x in supplied["apps"] if x["id"] == "top-plug-sa")
        self.assertEqual(item["catalogState"], "FILE_ONLY")
        self.assertEqual(item["requests"], [])
        self.assertEqual(item["extensions"], ["tpc"])
        self.assertEqual(item["fileModule"], "topplugsa.py")
        self.assertEqual(item["textPrefixes"], [])
        self.assertNotIn("catalogModule", item)

    def test_catalog_decode_fails_closed_without_a_catalog(self):
        # FILE_ONLY: no broker, no catalog module, no card. Asking the
        # catalog worker must fail closed, never return a partial catalog.
        from cloud.workers.python.engine import decode_provider_catalog, DecodeFailure
        with self.assertRaises(DecodeFailure) as failure:
            decode_provider_catalog("top-plug-sa", b"synthetic")
        self.assertEqual(failure.exception.code, "DECODE_FAILED")


if __name__ == "__main__":
    unittest.main()
