"""Diagnostic protector metadata only; no catalog, APK runtime or DEX claim."""
import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('am_liapp_metadata', ROOT / 'scripts/apk_analysis/am_liapp_metadata.py')
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)


class AMLiappMetadata(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads((ROOT / 'tests/golden/am_liapp_vectors.json').read_text())

    def test_original_native_lcg_and_crc_vectors(self):
        for vector in self.vectors['lcg']:
            self.assertEqual(reader.stream_xor(vector['seed'], bytes.fromhex(vector['encodedHex'])),
                             bytes.fromhex(vector['plainHex']))
        for vector in self.vectors['crc']:
            self.assertEqual(zlib.crc32(bytes.fromhex(vector['plainHex'])), vector['crc32'])

    def test_independent_synthetic_metadata(self):
        vector = self.vectors['metadata']
        raw = base64.b64decode(vector['assetBase64'])
        seeds = tuple(vector['seeds'])
        self.assertEqual(reader.open_metadata(raw, seeds), bytes.fromhex(vector['plainHex']))
        with self.assertRaisesRegex(ValueError, 'relation check'):
            reader.open_metadata(raw, (seeds[0], seeds[1], seeds[2] ^ 1))
        damaged = bytearray(raw)
        damaged[0x224] ^= 1
        with self.assertRaisesRegex(ValueError, 'relation check'):
            reader.open_metadata(bytes(damaged), seeds)

    def test_bounds_and_wrong_build_rejected(self):
        seeds = tuple(self.vectors['metadata']['seeds'])
        raw = base64.b64decode(self.vectors['metadata']['assetBase64'])
        for bad in [b'', raw[:0x224], raw[:-1], bytes(reader.MAX_BLOCK_BYTES + 1)]:
            with self.assertRaises(ValueError):
                reader.open_metadata(bad, seeds)
        for seed in [-1, 1 << 32]:
            with self.assertRaises(ValueError):
                reader.stream_xor(seed, b'x')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'unrelated.apk'
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'Unsupported APK'):
                reader.recover(path)


if __name__ == '__main__':
    unittest.main()
