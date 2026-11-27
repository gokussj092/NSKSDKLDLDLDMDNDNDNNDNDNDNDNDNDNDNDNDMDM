"""Synthetic-only tests for the TunelGuard 17.7 re-analysis.

No network, no real catalog, no real credentials. The STGCM3/TGCR1
vectors live in the fixture (ciphertext only, TEST-ONLY plaintext).
"""
import importlib.util
import json
import sys
import unittest
from pathlib import Path

STAGE = Path(__file__).resolve().parents[4]
APPS = STAGE / "decoders/Python/apps"
CODEC = APPS / "TunelGuard_VPN/codec.py"
SERVER = APPS / "TunelGuard_VPN/server_catalog_decoder.py"
FIXTURE = Path(__file__).resolve().parent / "fixtures/envelope_synthetic.json"


def load_codec():
    """Load the staged codec from a temp repo-layout tree.

    The staged codec needs its unchanged repo siblings
    (HTTP_FenixVPN/codec.py and TunelGuard_VPN/field_names.json), which
    are NOT staged (identical files). The temp tree copies the staged
    codec files verbatim (SHA-256 checked against the stage files) and
    takes the siblings from the repo tree when present, else from the
    read-only overlay (stage-tree runs).
    """
    import hashlib
    import tempfile
    overlay = Path(__file__).resolve().parents[5] / "overlay"
    overlay_apps = overlay / "decoders/Python/apps"
    repo_apps = STAGE / "decoders/Python/apps"

    def sibling(app, name):
        for base in (repo_apps, overlay_apps):
            path = base / app / name
            if path.is_file():
                return path
        raise FileNotFoundError(str(base / app / name))

    tmp = Path(tempfile.mkdtemp(prefix="tg177-test-"))
    tg = tmp / "apps" / "TunelGuard_VPN"
    hx = tmp / "apps" / "HTTP_FenixVPN"
    tg.mkdir(parents=True)
    hx.mkdir(parents=True)
    for src, dst in (
            (CODEC, tg / "codec.py"),
            (SERVER, tg / "server_catalog_decoder.py"),
            (sibling("TunelGuard_VPN", "field_names.json"),
             tg / "field_names.json"),
            (sibling("HTTP_FenixVPN", "codec.py"), hx / "codec.py"),
            (sibling("HTTP_FenixVPN", "field_names.json"),
             hx / "field_names.json")):
        data = src.read_bytes()
        dst.write_bytes(data)
        if src in (CODEC, SERVER):
            assert hashlib.sha256(data).hexdigest() == \
                hashlib.sha256(src.read_bytes()).hexdigest()
    for pkg in (tmp / "apps", tg, hx):
        (pkg / "__init__.py").write_text("", encoding="utf-8")
    sys.path.insert(0, str(tmp / "apps"))
    spec = importlib.util.spec_from_file_location("tg177_codec", tg / "codec.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TunelGuard177Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.codec = load_codec()
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_synthetic_envelope(self):
        doc = self.codec.decode_catalog(
            self.fixture["envelope"].encode("utf-8"))
        self.assertEqual(doc["version"], "9.9")
        self.assertEqual(doc["config_revision"], 999)
        self.assertEqual(len(doc["Servers"]), 1)
        self.assertEqual(len(doc["Tweaks"]), 1)
        self.assertEqual(doc["Servers"][0]["Secret"], "TEST-ONLY-SECRET")
        self.assertEqual(doc["Servers"][0]["Note"], "hello-test")
        self.assertNotIn("url_updater", doc)

    def test_tgcr1_field_direct(self):
        raw = self.codec.decrypt_envelope(self._field_envelope())
        self.assertEqual(raw, b"TEST-ONLY-SECRET")

    def _field_envelope(self):
        import base64
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = self.codec.KEYS[1]
        nonce = bytes(range(12))
        ct = AESGCM(key).encrypt(nonce, b"TEST-ONLY-SECRET", b"TGCR1.")
        b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
        return "TGCR1." + b64u(nonce) + "." + b64u(ct)

    def test_u8_field(self):
        self.assertEqual(self.codec._field("u8:aGVsbG8tdGVzdA=="), "hello-test")

    def test_bad_tag_rejected(self):
        env = self.fixture["envelope"]
        head, tg, nonce, ct = env.split(".")
        bad = head + "." + tg + "." + nonce + "." + ct[:-2] + ("AA" if ct[-2:] != "AA" else "BB")
        with self.assertRaises(self.codec.DecodeError):
            self.codec.decode_catalog(bad.encode("utf-8"))

    def test_unknown_version_rejected(self):
        with self.assertRaises(self.codec.DecodeError):
            self.codec.decode_catalog(b"STGCM9.TG.AAAAAAAAAAAAAAAA.AAAA")

    def test_new_url_constant(self):
        text = SERVER.read_text(encoding="utf-8")
        self.assertIn(
            'CATALOG_URL = "https://raw.githubusercontent.com/guruzgh-ed/edd/refs/heads/main/tg.js"',
            text)
        # The old URL may only appear in the docstring (as history), never
        # as the CATALOG_URL constant.
        self.assertNotIn(
            'CATALOG_URL = "https://raw.githubusercontent.com/eddyme23/octo/refs/heads/main/xxTG.js"',
            text)


if __name__ == "__main__":
    unittest.main()
