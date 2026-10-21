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

    def test_corrupt_data_or_standard_app_key_never_mislabeled(self):
        for data in (b"",b"garbage",b"NPVS"+bytes([4])+bytes(200),
                     make_header(1,2),make_header(2,2)[:65]):
            with self.subTest(data=data[:12]):
                self.assertFalse(_unsupported_npvs_protection(data))

if __name__=="__main__":
    unittest.main()
