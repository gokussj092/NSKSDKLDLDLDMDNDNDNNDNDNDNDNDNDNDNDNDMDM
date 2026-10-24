"""Synthetic APNA modified XXTEA tests: never commit real catalogs or credentials."""
import base64
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

DECODER = Path(__file__).resolve().parents[1] / "decoders/Python/apps/APNA_VPN/server_catalog_decoder.py"
spec = importlib.util.spec_from_file_location("apna_catalog", DECODER)
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


def seal(plaintext: bytes) -> bytes:
    """Independent encryption oracle based on Dalvik LBm.d, not the reader MX."""
    delta = 0x9e5729b1
    mask = (1 << 32) - 1
    n = (len(plaintext) + 3) // 4
    pad = plaintext.ljust(n * 4, b"\x00")
    words = list(struct.unpack("<" + "I" * n, pad)) + [len(plaintext)]
    count = len(words)
    key = struct.unpack("<4I", b"...|...".ljust(16, b"\0"))
    z = words[-1]
    total = 0
    for _ in range(6 + 52 // count):
        total = (total + delta) & mask
        e = (total >> 2) & 3
        for i in range(count - 1):
            y = words[i + 1]
            mx = (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^
                  ((total ^ y) + (key[(i & 3) ^ e] ^ z))) & mask
            words[i] = (words[i] + mx) & mask
            z = words[i]
        y = words[0]
        mx = (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^
              ((total ^ y) + (key[((count - 1) & 3) ^ e] ^ z))) & mask
        words[-1] = (words[-1] + mx) & mask
        z = words[-1]
    return base64.b64encode(struct.pack("<" + "I" * count, *words))


class APNATests(unittest.TestCase):
    def setUp(self):
        self.catalog = {
            "Free_servers": [{"server_name": "Fixture 🛠", "server_host": "example.invalid",
                              "server_port": "443", "password": "synthetic-only"}],
            "Premium_servers": [], "Vip_servers": [], "Private_servers": [],
            "Payloads": [{"friendly_name": "test", "payload": "GET / HTTP/1.1\r\n"}],
            "Version": "3.9", "OtherField": {"nested": [True, None, "é"]},
        }
        self.plain = json.dumps(self.catalog, ensure_ascii=False, separators=(",", ":")).encode()
        self.encrypted = seal(self.plain)

    def test_exact_plaintext_and_nested_fields(self):
        self.assertEqual(reader.decode_json_bytes(self.encrypted), self.plain)
        self.assertEqual(json.loads(reader.run(self.encrypted)), self.catalog)
        info = reader.summary(self.plain)
        self.assertEqual(info["serverCounts"]["Free_servers"], 1)
        self.assertEqual(info["payloadCount"], 1)
        self.assertNotIn("synthetic-only", json.dumps(info))

    def test_malformed_or_tampered_data_rejected(self):
        with self.assertRaises(reader.CatalogError):
            reader.run(b"not base64%%")
        with self.assertRaises(reader.CatalogError):
            reader.run(base64.b64encode(b"1234"))
        changed = bytearray(base64.b64decode(self.encrypted))
        changed[4] ^= 128
        with self.assertRaises(reader.CatalogError):
            reader.run(base64.b64encode(changed))
        with self.assertRaises(reader.CatalogError):
            reader.run(seal(b'{"not_a_catalog":true}'))

    def test_cli_summary_excludes_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "synthetic.json"
            path.write_bytes(self.encrypted)
            call = [sys.executable, str(DECODER), "--input", str(path), "--summary"]
            done = subprocess.run(call, capture_output=True, check=True, timeout=15)
            self.assertEqual(json.loads(done.stdout)["payloadCount"], 1)
            self.assertNotIn(b"synthetic-only", done.stdout)


if __name__ == "__main__":
    unittest.main()
