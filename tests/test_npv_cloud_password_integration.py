"""NPV text Cloud dispatch and signed/legacy header separation."""
import base64
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"cloud/workers/python"))
from text_bridge import dispatch, is_npv_text
from npvs_bridge import legacy_json
from engine import decode_text, DecodeFailure

PREFIXES=("npvt://","npvt-ssh://","npvt-vless://","npvt-vmess://","npv://")

class NpvCloudPasswordTests(unittest.TestCase):
    def test_every_npv_scheme_dispatches_complete_json(self):
        data={"connection":{"host":"example.invalid","port":443},
              "nested":"npvs1:"+base64.b64encode(b"hello").decode()}
        payload=base64.b64encode(json.dumps(data).encode()).decode()
        for prefix in PREFIXES:
            with self.subTest(prefix=prefix):
                link=prefix+payload
                self.assertTrue(is_npv_text(link))
                decoded=json.loads(dispatch(link))
                self.assertEqual(decoded["nested"],"hello")
                self.assertEqual(decoded["connection"],data["connection"])
                self.assertEqual(json.loads(decode_text(link)["rawText"]),decoded)
                with self.assertRaises(DecodeFailure) as error:
                    decode_text(link,credentials={"password":"not-required"})
                self.assertEqual(error.exception.code,"INVALID_CREDENTIALS")
    def test_signed_npvs_never_tries_legacy_route(self):
        for raw in (b"NPVS"+bytes(120),b"unrelated"):
            with self.assertRaises(ValueError):legacy_json(raw)
    def test_legacy_header_keeps_all_array_members(self):
        from decoders.Python import NPVTUNNEL
        original={"profiles":[{"id":1},{"id":2}]}
        with patch.object(NPVTUNNEL,"load_whitebox_state",return_value=(1,2,3,4)),patch.object(
            NPVTUNNEL,"decrypt_logic",return_value=json.dumps(original)):
            for header in (b"NPVT1",b"NPVTSUB1"):
                out=json.loads(legacy_json(header+b"x,synthetic"))
                self.assertEqual(out,original)
    def test_dns_still_uses_preexisting_handler(self):
        value="dns://"+base64.b64encode(b'{"type":"dns"}').decode()
        self.assertFalse(is_npv_text(value))
        self.assertIn('"dns"',dispatch(value))
