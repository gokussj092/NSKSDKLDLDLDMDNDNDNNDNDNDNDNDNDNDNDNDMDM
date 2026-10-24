"""NPVS v5 encryption-policy diagnostics: do not invent keys or mislabel corrupt files."""
from __future__ import annotations
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"cloud/workers/python"))
from engine import _unsupported_npvs_protection,decode_file,DecodeFailure

def make_header(kind: int, method: int)->bytes:
    header=bytearray(135)
    header[0]=kind
    header[50]=method
    return b"NPVS"+bytes([5])+len(header).to_bytes(4,"big")+bytes(header)+bytes(80)

class NpvsErrorsTests(unittest.TestCase):
    def test_alternative_protection_rejected_with_precise_error(self):
        for kind,method in ((2,2),(1,3)):
            with self.subTest(kind=kind,method=method):
                data=make_header(kind,method)
                self.assertTrue(_unsupported_npvs_protection(data))
                with self.assertRaises(DecodeFailure) as e:
                    decode_file("npvs",data)
                self.assertEqual(e.exception.code,"NPVS_PROTECTION_UNSUPPORTED")

    def test_unknown_version_is_not_reported_as_private_key_or_engine_failure(self):
        data = bytearray(make_header(1, 2))
        data[4] = 7
        with self.assertRaises(DecodeFailure) as caught:
            decode_file("npvs", bytes(data))
        self.assertEqual(caught.exception.code, "UNSUPPORTED_VERSION")

        # A truncated header is malformed input, not an unsupported key.
        with self.assertRaises(DecodeFailure) as caught:
            decode_file("npvs", b"NPVS" + bytes([7]))
        self.assertEqual(caught.exception.code, "INVALID_INPUT")

    def test_unsigned_appkey_and_recipient_samples_are_not_key_notices(self):
        # Valid framing but deliberately invalid ECDSA signatures. Before
        # issuing ANY private-key or app-key notice, verify authenticity.
        for method in (0, 2):
            with self.subTest(method=method):
                recipients = 1 if method == 0 else 0
                extra = 125 if recipients else 78
                header = bytearray(53 + extra + 4 + 16)
                header[0] = 1
                header[50] = method
                header[51:53] = recipients.to_bytes(2, "big")
                if recipients:
                    header[53 + 32] = 2  # compressed ECDH ephemeral key
                else:
                    header[53:55] = (2).to_bytes(2, "big")  # app-key keyId
                header[53 + extra:57 + extra] = (16).to_bytes(4, "big")
                raw = (b"NPVS" + bytes([5]) + len(header).to_bytes(4, "big")
                       + bytes(header) + bytes(12) + (70).to_bytes(4, "big")
                       + bytes(70) + bytes(64))
                with self.assertRaises(DecodeFailure) as caught:
                    decode_file("npvs", raw)
                self.assertEqual(caught.exception.code, "INVALID_INPUT")

    def test_corrupt_data_or_standard_app_key_never_mislabeled(self):
        for data in (b"",b"garbage",b"NPVS"+bytes([4])+bytes(200),
                     make_header(1,0),make_header(1,1),make_header(1,2),make_header(2,2)[:65]):
            with self.subTest(data=data[:12]):
                self.assertFalse(_unsupported_npvs_protection(data))

if __name__=="__main__":
    unittest.main()
