"""Tests del metodo JK VPN (build 15).

Vectores SINTETICOS con claves de prueba generadas aqui mismo; no hay
credenciales reales, ni servidores reales, ni red. La criptografia usada
es la extraida a tools/crypto_pure.py (codigo generico, sin claves de
formato). El descifrado con parametros reales esta cubierto por el
--self-test del script operativo (ver RESULTS.md).
"""
import base64
import hashlib
import hmac as hmac_mod
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
sys.path.insert(0, os.path.dirname(__file__))

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
TEST_PASSWORD = b"TEST-ONLY-SYNTHETIC-PASSWORD-2026-11-15"
TEST_KEY_16 = b"TEST-ONLY-KEY-16"
TEST_KEY_32 = b"TEST-ONLY-SYNTHETIC-KEY-32-BYTES"

from aesgcm_pure import gcm_decrypt_pure, gcm_encrypt_pure

# Parametros SINTETICOS del sobre .hs (Tink Streaming AEAD): los valores
# reales de formato viven solo en el script operativo.
TEST_PBKDF2_SALT = b"TEST-ONLY-FIXED-SALT-V1"
TEST_HKDF_INFO = b"TEST-ONLY-STREAM-INFO-V1"
# Segmentacion real del formato: cabecera de 40 B; primer segmento de
# cifrado 4056 B (4096 - 40) y siguientes de 4096 B; cada segmento lleva
# 16 B de tag GCM, asi que el claro por segmento es 4040 / 4080 B.
SEG1_PLAIN = 4040
SEGN_PLAIN = 4080


def derive_stream_key(password: bytes, salt: bytes, info: bytes) -> bytes:
    ikm = hashlib.pbkdf2_hmac("sha256", password, salt, 100000, dklen=32)
    prk = hmac_mod.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    ctr = 1
    while len(out) < 32:
        t = hmac_mod.new(prk, t + info + bytes([ctr]), hashlib.sha256).digest()
        out += t
        ctr += 1
    return out[:32]


def seal_hs(plain: bytes, password: bytes) -> bytes:
    salt = os.urandom(32)
    nonce_prefix = os.urandom(7)
    key = derive_stream_key(password, salt, TEST_HKDF_INFO)
    header = bytes([40]) + salt + nonce_prefix
    out = bytearray(header)
    seg_no = 0
    off = 0
    while True:
        chunk_size = SEG1_PLAIN if seg_no == 0 else SEGN_PLAIN
        chunk = plain[off:off + chunk_size]
        last = 1 if off + len(chunk) >= len(plain) else 0
        nonce = nonce_prefix + seg_no.to_bytes(4, "big") + bytes([last])
        ct_tag = gcm_encrypt_pure(key, nonce, chunk)
        out += ct_tag
        off += len(chunk)
        seg_no += 1
        if last:
            break
    return bytes(out)


def open_hs(blob: bytes, password: bytes) -> bytes:
    if len(blob) < 40 or blob[0] != 40:
        raise ValueError("cabecera .hs invalida")
    salt, nonce_prefix = blob[1:33], blob[33:40]
    key = derive_stream_key(password, salt, TEST_HKDF_INFO)
    body = blob[40:]
    out = bytearray()
    seg_no, off = 0, 0
    while off < len(body):
        remaining = len(body) - off
        seg_ct = 4056 if seg_no == 0 else 4096
        if remaining > seg_ct:
            seg_len = seg_ct
            last = 0
        else:
            seg_len = remaining
            last = 1
        nonce = nonce_prefix + seg_no.to_bytes(4, "big") + bytes([last])
        out += gcm_decrypt_pure(key, nonce, body[off:off + seg_len])
        off += seg_len
        seg_no += 1
    return bytes(out)


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


class TestHsStreamingAead(unittest.TestCase):
    def test_positive_roundtrip(self):
        doc = load_fixture("synthetic_catalog.json")
        plain = json.dumps(doc).encode()
        self.assertEqual(open_hs(seal_hs(plain, TEST_PASSWORD), TEST_PASSWORD), plain)

    def test_positive_multisegment_roundtrip(self):
        plain = (b'{"Version": "9.9-sintetico", "pad": "' + b"A" * 9000 + b'"}')
        blob = seal_hs(plain, TEST_PASSWORD)
        self.assertGreater(len(blob), 4096 + 40)
        self.assertEqual(open_hs(blob, TEST_PASSWORD), plain)

    def test_positive_ed_base32_roundtrip(self):
        text = "203.0.113.10"
        enc = "ED:" + base64.b32encode(text.encode()).decode()
        self.assertEqual(base64.b32decode(enc[3:]).decode(), text)

    def test_negative_tampered_tag(self):
        blob = bytearray(seal_hs(b'{"Version": "9.9"}', TEST_PASSWORD))
        blob[-1] ^= 0x01
        with self.assertRaises(Exception):
            open_hs(bytes(blob), TEST_PASSWORD)

    def test_negative_wrong_password(self):
        blob = seal_hs(b'{"Version": "9.9"}', TEST_PASSWORD)
        with self.assertRaises(Exception):
            open_hs(blob, b"WRONG-TEST-PASSWORD")

    def test_negative_truncated(self):
        blob = seal_hs(b'{"Version": "9.9-sintetico"}', TEST_PASSWORD)
        with self.assertRaises(Exception):
            open_hs(blob[:60], TEST_PASSWORD)

    def test_negative_html_instead_of_hs(self):
        with self.assertRaises(Exception):
            open_hs(b"<html><head><title>Error</title></head></html>", TEST_PASSWORD)

    def test_negative_bad_header(self):
        blob = bytearray(seal_hs(b'{"Version": "9.9"}', TEST_PASSWORD))
        blob[0] = 41
        with self.assertRaises(ValueError):
            open_hs(bytes(blob), TEST_PASSWORD)

    def test_fixture_schema(self):
        doc = load_fixture("synthetic_catalog.json")
        self.assertIn("Version", doc)
        self.assertEqual(doc["Servers"][0]["ServerIPHost"], "203.0.113.10")


if __name__ == "__main__":
    unittest.main()
