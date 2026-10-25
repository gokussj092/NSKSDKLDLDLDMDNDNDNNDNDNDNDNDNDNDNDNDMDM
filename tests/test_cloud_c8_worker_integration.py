"""Cloud C8 integration tests using independently generated golden inputs.

Checks the actual private worker subprocess boundary, not just pure decoders.
Existing engines and their cryptographic implementations are not modified.
"""
from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"cloud/workers/python"))
from engine import (
    DecodeFailure, decode_file, decode_text, decode_provider_catalog,
    load_file_engines, load_runtime_file_engines,
)

def golden(name):
    return json.loads((ROOT/"tests/golden"/name).read_text(encoding="utf-8"))

class C8WorkerIntegrationTests(unittest.TestCase):
    def test_unchanged_prior_inventory_and_explicit_new_file_routes(self):
        base=load_file_engines()
        extended=load_runtime_file_engines()
        self.assertEqual(len(base),240)
        self.assertEqual(len(extended),254)
        from engine import _C8_FILE_ENGINES
        overlays=set(_C8_FILE_ENGINES)
        self.assertEqual(len(overlays),26)
        self.assertEqual({k:v for k,v in extended.items() if k not in overlays},
                         {k:v for k,v in base.items() if k not in overlays})
        for ext in overlays:
            self.assertEqual(extended[ext]["phase"],"C8")
            self.assertIn("/apps/",extended[ext]["source"])
        for ext in ("tgv","rt","gol","ua","nvpnc","green","hxt","mtp","roy","4ulite","actun","aro","sks","tut"):
            self.assertEqual(extended[ext]["phase"],"C8")
            self.assertIn("/apps/",extended[ext]["source"])
        self.assertNotEqual(extended["hxt"]["source"],base["hxt"]["source"])

    def test_24clan_profile_and_catalog_are_complete(self):
        fixture=golden("clan24_green_vectors.json")
        output=decode_file("green",fixture["profile"].encode("utf-8"))
        self.assertEqual(output["structuredJson"],fixture["expectedProfile"])
        self.assertEqual(json.loads(output["rawText"]),fixture["expectedProfile"])
        self.assertFalse(output["isPartial"])
        remote=decode_provider_catalog("24clan-green",fixture["catalog"].encode("utf-8"))
        self.assertEqual(remote["structuredJson"],fixture["expectedCatalog"])
        self.assertFalse(remote["isPartial"])

    def test_hx_hxt_uses_its_own_codec_and_remote_catalog(self):
        fixture=golden("hx_tunnel_vectors.json")
        output=decode_file("hxt",fixture["profile"].encode("utf-8"))
        self.assertEqual(output["structuredJson"],fixture["expectedProfile"])
        self.assertIn("/apps/HX_Tunnel_VPN/HX_Tunnel_VPN_archivos.py",
                      load_runtime_file_engines()["hxt"]["source"])
        remote=decode_provider_catalog("hx-tunnel",fixture["catalog"].encode("utf-8"))
        self.assertEqual(remote["structuredJson"],fixture["expectedCatalog"])

    def test_mkk_remote_catalog_and_text_link(self):
        fixture=golden("mkk_hyper_vectors.json")
        remote=decode_provider_catalog("mkk-hyper",fixture["catalog"].encode("utf-8"))
        self.assertEqual(remote["structuredJson"],fixture["expectedCatalog"])
        self.assertEqual(json.loads(remote["rawText"]),fixture["expectedCatalog"])
        result=decode_text(fixture["profiles"][0]["data"])
        self.assertEqual(result["status"],"success")
        self.assertFalse(result["isPartial"])
        self.assertEqual(result["structuredJson"]["uri"],fixture["profiles"][0]["uri"])

    def test_reese_unprotected_binary_profile(self):
        data=golden("reese_vectors.json")
        sample=next(v for v in data["cases"] if v["name"]=="rse5-c4-flags0")
        output=decode_file("rt",base64.b64decode(sample["data"]))
        expected=json.loads(json.dumps(data["expected"]))
        expected["config"].pop("bannerImage",None)
        self.assertEqual(output["structuredJson"],expected)
        self.assertNotIn("bannerImage",output["rawText"])
        self.assertFalse(output["isPartial"])

    def test_mkk_oversized_render_uses_explicit_error_not_generic_failure(self):
        import io
        import tempfile
        from unittest.mock import patch
        from cloud.workers.python import catalog_vpn_bridge as bridge
        with tempfile.TemporaryDirectory() as folder:
            sample=Path(folder)/"input.bin"
            sample.write_bytes(b"synthetic")
            output=io.StringIO()
            with patch.object(bridge,"decode",return_value="X"*(32*1024*1024+1)), \
                 patch.object(sys,"argv",["catalog_vpn_bridge.py","mkk-hyper",str(sample)]), \
                 patch("sys.stdout",output):
                self.assertEqual(bridge.main(),3)
            self.assertEqual(json.loads(output.getvalue()),{"workerError":"OUTPUT_TOO_LARGE"})

    def test_vpn_plus_peru_akn3_full_json(self):
        data=golden("vpn_plus_peru_vectors.json")
        sample=next(v for v in data["vectors"] if v["version"]==3)
        output=decode_file("gol",sample["data"].encode("utf-8"))
        self.assertEqual(output["structuredJson"],data["expected"])

    def test_ultra_custom_unprotected_v5(self):
        data=golden("ultra_custom_52_vectors.json")
        sample=next(v for v in data["vectors"] if v["name"]=="single-plain")
        output=decode_file("ua",sample["data"].encode("utf-8"))
        document=output["structuredJson"]
        profiles=document.get("profiles",[document])
        self.assertEqual([p["properties"] for p in profiles],
                         [data["expectedProfiles"][0]])

    def test_neutro_unprotected_profile_json(self):
        data=golden("neutro_vpn_vectors.json")
        output=decode_file("nvpnc",data["local"].encode("utf-8"))
        self.assertEqual(output["structuredJson"],data["expectedProfile"])

    def test_reject_unknown_provider_and_ciphertext_instead_of_falling_back(self):
        with self.assertRaises(DecodeFailure) as bad:
            decode_provider_catalog("unregistered",b"not a catalog")
        self.assertEqual(bad.exception.code,"UNSUPPORTED_FORMAT")
        with self.assertRaises(DecodeFailure) as invalid:
            decode_provider_catalog("hx-tunnel",b"invalid ciphertext")
        self.assertEqual(invalid.exception.code,"DECODE_FAILED")
        with self.assertRaises(DecodeFailure) as unsupported:
            decode_file("c8-unknown",b"abc")
        self.assertEqual(unsupported.exception.code,"UNSUPPORTED_FORMAT")

if __name__=="__main__":
    unittest.main()
