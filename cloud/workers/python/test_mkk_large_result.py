"""Phase 4 regression tests for MKK's complete multi-source JSON output."""
import base64
import json
import unittest
from unittest.mock import patch
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from cloud.workers.python import mkk_bundle, catalog_vpn_bridge
import engine
import server


def bundle() -> bytes:
    entry=base64.b64encode(b'{"sample":true}').decode("ascii")
    return json.dumps({
        "kind":mkk_bundle.KIND,
        "sources":[{"name":name,"status":"ok","dataBase64":entry}
                   for name in mkk_bundle.SOURCES],
    },separators=(",",":")).encode()


class MkkHyperLargeResultTests(unittest.TestCase):
    def test_large_json_preserves_all_four_full_sources(self):
        big={"servers":[{"payload":"x"*(1024*1024+100)}]}
        with patch.object(mkk_bundle.codec,"decode",return_value=big) as decode:
            rendered=mkk_bundle.decode(bundle())
            bridged=catalog_vpn_bridge.decode("mkk-hyper",bundle())
        self.assertGreater(len(rendered.encode("utf-8")),4*1024*1024)
        self.assertEqual(json.loads(rendered),json.loads(bridged))
        value=json.loads(rendered)
        self.assertEqual(value["successfulSources"],4)
        self.assertTrue(value["complete"])
        self.assertEqual(len(value["sources"]),4)
        self.assertEqual(decode.call_count,8)
        for source in value["sources"]:
            self.assertEqual(source["status"],"ok")
            self.assertEqual(source["data"],big)

    def test_non_json_source_is_rejected_not_forwarded_as_text(self):
        with patch.object(mkk_bundle.codec,"decode",return_value="<html>bad</html>"):
            with self.assertRaisesRegex(ValueError,"INVALID_SOURCE_RESULT"):
                mkk_bundle.decode(bundle())

    def test_mkk_budget_is_route_specific(self):
        self.assertEqual(engine.MAX_OUTPUT_BYTES,4*1024*1024)
        self.assertEqual(engine.MAX_MKK_OUTPUT_BYTES,32*1024*1024)
        self.assertEqual(engine.MAX_MKK_BUNDLE_BYTES,45*1024*1024)
        self.assertEqual(server.MAX_MKK_BUNDLE_BYTES,engine.MAX_MKK_BUNDLE_BYTES)


if __name__=="__main__":
    unittest.main()
