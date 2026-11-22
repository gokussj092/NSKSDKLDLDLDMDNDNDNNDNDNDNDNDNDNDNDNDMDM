"""RMP TUNNEL LITE RMP-4: shared-engine catalog plus .rmplite file/text routes.

The catalog reuses the already-integrated ``python-shared-mx-xxtea``
motor through ``decoders.Python.apps.RMP_TUNNEL_PRO.codec`` (same key,
delta and schema; the live RMPLITE bytes are identical to the live
RMPPRO bytes), so the catalog checks reuse the independently generated
shared JDK vectors in ``tests/golden/mx_tunnel_pro_vectors.json`` --
the same fixture ``tests/test_rmp_tunnel_pro.py`` uses. No live catalog
bytes or decrypted credentials are stored here.

The .rmplite / rmplite:// route is new for Lite (PRO has none): one
hex line -> XOR with the 12-byte format key -> JNI modified UTF-8 JSON
tweak. Fixtures are built with the small local encrypt helper below
(inverse of the decoder, same recipe the native Unicorn oracle
verified in both directions). All values are fictitious
(test.invalid); no real exported .rmplite file or link has been
supplied yet (VERIFIED_SYNTHETIC).
"""
import base64
import json
from pathlib import Path
import subprocess
import sys
import unittest

from decoders.Python.apps.RMP_Tunnel_Lite import codec, file_decoder
from decoders.Python.apps.RMP_Tunnel_Lite import server_catalog_decoder as catalog
from cloud.workers.python.engine import DecodeFailure, decode_file, decode_provider_catalog
from cloud.workers.python.text_bridge import dispatch as text_dispatch

ROOT = Path(__file__).resolve().parents[1]
V = json.loads((ROOT / 'tests/golden/mx_tunnel_pro_vectors.json').read_text())

PROFILE_KEY = file_decoder.PROFILE_KEY


def _to_modified_utf8(text: str) -> bytes:
    """Encode as JNI modified UTF-8 (CESU-8): test-fixture helper only."""
    units = text.encode("utf-16-be", errors="surrogatepass")
    out = bytearray()
    for i in range(0, len(units), 2):
        cp = (units[i] << 8) | units[i + 1]
        if cp == 0:
            out += b"\xc0\x80"
        elif cp < 0x80:
            out.append(cp)
        elif cp < 0x800:
            out.append(0xC0 | (cp >> 6))
            out.append(0x80 | (cp & 0x3F))
        else:
            out.append(0xE0 | (cp >> 12))
            out.append(0x80 | ((cp >> 6) & 0x3F))
            out.append(0x80 | (cp & 0x3F))
    return bytes(out)


def encrypt_tweak(text: str) -> str:
    """Hex-encode one tweak JSON string (inverse of file_decoder.decode)."""
    raw = _to_modified_utf8(text)
    return bytes(value ^ PROFILE_KEY[i % len(PROFILE_KEY)]
                 for i, value in enumerate(raw)).hex()


TWEAK = {"friendly_name": "synthetic-tweak", "payload": "GET / HTTP/1.1",
         "tweak_password": "", "tweak_expiry": "",
         "hwid_lock": "", "block_rooted": "false"}
TWEAK_HEX = encrypt_tweak(json.dumps(TWEAK, ensure_ascii=False))


class RmpTunnelLiteCatalogTests(unittest.TestCase):
    def test_complete_shared_jdk_vector_and_isolated_worker(self):
        data = V['catalog'].encode(); expected = V['expected']
        self.assertEqual(json.loads(catalog.run(data)), expected)
        result = decode_provider_catalog('rmp-tunnel-lite', data)
        self.assertEqual(result['structuredJson'], expected)
        self.assertEqual(json.loads(result['rawText']), expected)
        self.assertFalse(result['isPartial'])

    def test_cli_stdin_outside_repository(self):
        p = subprocess.run([sys.executable, str(ROOT / 'decoders/Python/apps/RMP_Tunnel_Lite/server_catalog_decoder.py'), '--stdin'],
                           input=V['catalog'].encode(), cwd='/tmp', capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        self.assertEqual(json.loads(p.stdout), V['expected'])

    def test_invalid_sections_lengths_limits_and_redirects(self):
        raw = base64.b64decode(V['catalog'])
        for data in [b'', b'<html/>', b'private-invalid-data', base64.b64encode(raw[:-1]), V['catalog'][:-12].encode(), b'x' * (catalog.MAX_BYTES + 1), *(s.encode() for s in V['invalid'])]:
            with self.assertRaises(catalog.DecodeError) as e:
                catalog.run(data)
            self.assertNotIn('private-invalid-data', str(e.exception))
        with self.assertRaises(catalog.DecodeError):
            catalog._NoRedirect().redirect_request(None)


class RmpTunnelLiteFileTextTests(unittest.TestCase):
    def test_rmplite_round_trip_file_route(self):
        self.assertEqual(json.loads(file_decoder.run(TWEAK_HEX.encode())), TWEAK)
        # The app reads the first line only; trailing lines are ignored.
        self.assertEqual(json.loads(file_decoder.run((TWEAK_HEX + "\nsecond line ignored\n").encode())), TWEAK)
        self.assertEqual(json.loads(file_decoder.run(("rmplite://" + TWEAK_HEX).encode())), TWEAK)
        self.assertEqual(json.loads(file_decoder.run(("RMPLITE://" + TWEAK_HEX).encode())), TWEAK)
        self.assertEqual(decode_file("rmplite", TWEAK_HEX.encode())["structuredJson"], TWEAK)

    def test_rmplite_link_round_trip_and_text_bridge(self):
        link = "rmplite://" + TWEAK_HEX
        parsed = json.loads(file_decoder.decode_text(link))
        self.assertEqual(parsed, TWEAK)
        self.assertEqual(json.loads(text_dispatch(link)), TWEAK)
        self.assertEqual(json.loads(file_decoder.decode_text("rmplite://RMPLITE" + TWEAK_HEX)), TWEAK)
        self.assertEqual(json.loads(text_dispatch("rmplite://RMPLITE" + TWEAK_HEX)), TWEAK)
        self.assertEqual(json.loads(file_decoder.decode_text("RMPLITE://" + TWEAK_HEX)), TWEAK)
        self.assertEqual(json.loads(text_dispatch("RMPLITE://" + TWEAK_HEX)), TWEAK)
        self.assertEqual(json.loads(file_decoder.run(link.encode("utf-8"))), TWEAK)
        for bad in ("rmplite://zz11",
                    "rmplite://",
                    "rmplite://" + bytes([0x00, 0x11, 0x22, 0x33]).hex(),
                    "https://example.invalid/x",
                    "rmppro://" + TWEAK_HEX):
            with self.subTest(bad=bad[:22]):
                self.assertIsNone(file_decoder.decode_text(bad))
                self.assertIsNone(text_dispatch(bad))
        self.assertIsNone(file_decoder.decode_text(""))
        self.assertIsNone(file_decoder.decode_text("rmplite://"))

    def test_rmplite_rejects_plain_text_bad_hex_and_garbage(self):
        for bad in (b"this is not hex at all!!", b"zz11", b"",
                    bytes([0x00, 0x11, 0x22, 0x33]).hex().encode()):
            with self.subTest(bad=bad[:20]):
                with self.assertRaises(codec.DecodeError):
                    file_decoder.run(bad)
        with self.assertRaises(codec.DecodeError):
            file_decoder.run(b"not-hex")
        with self.assertRaises(DecodeFailure):
            decode_file("rmplite", b"")


if __name__ == '__main__':
    unittest.main()
