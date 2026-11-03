"""Synthetic JCA oracle, malformed input, authentication and full JSON fidelity.

These tests do not establish compatibility with a real Halcon remote catalog.
"""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from Crypto.Cipher import AES

BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('halcon_candidate', BASE / 'tools/envelope_candidate.py')
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)
PASSWORD = 'synthetic-only'

def symbols(raw):
    return ''.join(candidate.ALPHABET[b >> 4] + candidate.ALPHABET[b & 15]
                   for b in base64.b64encode(raw)).encode()

def encrypted(plain):
    nonce = bytes(range(12))
    cipher = AES.new(hashlib.sha256(PASSWORD.encode()).digest(), AES.MODE_GCM, nonce=nonce)
    body, tag = cipher.encrypt_and_digest(plain)
    return symbols(nonce + body + tag)

class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.vector = (BASE / 'tests/fixtures/synthetic.envelope').read_bytes()

    def test_jca_reference_full_json(self):
        expected = json.loads((BASE / 'tests/fixtures/expected.json').read_text())
        self.assertEqual(candidate.decode(self.vector, PASSWORD), expected)

    def test_wrong_password_authentication(self):
        with self.assertRaises(ValueError): candidate.decode(self.vector, 'wrong')

    def test_modified_tag(self):
        text = self.vector.decode()
        lut = {c: i for i, c in enumerate(candidate.ALPHABET)}
        b64 = bytes(lut[text[i]] * 16 + lut[text[i+1]] for i in range(0, len(text), 2))
        raw = bytearray(base64.b64decode(b64))
        raw[-1] ^= 1
        with self.assertRaises(ValueError): candidate.decode(symbols(raw), PASSWORD)

    def test_html_rejected(self):
        with self.assertRaises(ValueError): candidate.decode(b'<html>not a catalog</html>', PASSWORD)

    def test_plain_json_not_fallback(self):
        with self.assertRaises(ValueError): candidate.decode(b'{"version":"1"}', PASSWORD)

    def test_odd_symbol_count(self):
        with self.assertRaises(ValueError): candidate.decode(self.vector + '▙'.encode(), PASSWORD)

    def test_truncated_envelope(self):
        with self.assertRaises(ValueError): candidate.decode(symbols(bytes(27)), PASSWORD)

    def test_duplicate_json_keys(self):
        with self.assertRaises(ValueError): candidate.decode(encrypted(b'{"version":1,"version":2}'), PASSWORD)

    def test_nonfinite_json(self):
        with self.assertRaises(ValueError): candidate.decode(encrypted(b'{"x":NaN}'), PASSWORD)

    def test_invalid_object_schema(self):
        for plain in [b'[]', b'null', b'{}', b'"text"']:
            with self.subTest(plain=plain), self.assertRaises(ValueError):
                candidate.decode(encrypted(plain), PASSWORD)

    def test_missing_credential(self):
        with self.assertRaises(ValueError): candidate.decode(self.vector, '')

    def test_empty_and_excessive_input(self):
        for data in [b'', b'a' * (candidate.MAX_BYTES + 1)]:
            with self.assertRaises(ValueError): candidate.decode(data, PASSWORD)

if __name__ == '__main__': unittest.main()
