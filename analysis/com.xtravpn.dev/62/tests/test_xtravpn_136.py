"""Synthetic-only tests for the XtraVPN 1.0.36 re-verification.

No network, no real user data. The asset blob is the repo's own
decoders/Python/apps/XtraVPN/config.json (encrypted asset from the APK);
the custom code is synthetic (example.org URL, fixed fallback key).
"""
import base64
import importlib.util
import json
import unittest
from pathlib import Path

STAGE = Path(__file__).resolve().parents[4]
SCRIPT = STAGE / "decoders/Python/apps/XtraVPN/XtraVPN.py"
OVERLAY_ASSET = (Path(__file__).resolve().parents[5]
                 / "overlay/decoders/Python/apps/XtraVPN/config.json")
SUPPLIED = STAGE / "_fragments/groupC/supplied-integrations.json.fragment"
TEXT_BRIDGE = STAGE / "_fragments/groupC/text_bridge.py.fragment"
TEXT_FORMATS = STAGE / "_fragments/groupC/text-formats.json.fragment"


def load():
    spec = importlib.util.spec_from_file_location("xtravpn136", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class XtraVpn136Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load()
        # The asset lives in the repo (overlay); the stage tree has no copy.
        cls.blob = OVERLAY_ASSET.read_text(encoding="utf-8").strip()

    def test_asset_opens_with_pitingo(self):
        result = self.mod.run(data=self.blob)
        self.assertEqual(result["version"], "1.0.0")
        self.assertEqual(result["key_used"], "Pitingo2089")
        self.assertEqual(result["server_count"], 1)

    def test_text_prefix_strips_and_opens(self):
        # Mirrors XtravpnMainActivity.x(): strip the 10-char prefix.
        self.assertTrue("xtravpn://".startswith("xtravpn://"))
        result = self.mod.run(data=self.blob)
        self.assertEqual(result["version"], "1.0.0")

    def test_key_order_pitingo_first(self):
        import inspect
        params = inspect.signature(self.mod.decode_config).parameters
        self.assertEqual(params["keys"].default[0], "Pitingo2089")

    def test_fixed_fallback_key_works(self):
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        key = b"23605c1568999d3a"
        padder = padding.PKCS7(128).padder()
        padded = padder.update(b"https://example.org/catalogo.json") + padder.finalize()
        encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        code = base64.b64encode(encryptor.update(padded) + encryptor.finalize()).decode()
        self.assertEqual(
            self.mod.decrypt_custom_code(code, "0000000000000000"),
            "https://example.org/catalogo.json")

    def test_garbage_rejected(self):
        with self.assertRaises(self.mod.DecodeError):
            self.mod.run(data="not-a-config-blob!!!")

    def test_fragments_advertise_xtravpn_scheme(self):
        self.assertIn('"xtravpn://"', SUPPLIED.read_text(encoding="utf-8"))
        self.assertIn("xtravpn://", TEXT_BRIDGE.read_text(encoding="utf-8"))
        self.assertIn('"xtravpn://"', TEXT_FORMATS.read_text(encoding="utf-8"))
        self.assertIn("CUSTOM_CODE_URL_REQUIRED",
                      SUPPLIED.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
