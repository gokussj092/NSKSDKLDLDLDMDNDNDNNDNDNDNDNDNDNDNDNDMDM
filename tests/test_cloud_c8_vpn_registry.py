"""C8 independent Cloud engines never mutate C0's fixed 240 routes."""
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"cloud/workers/python"))
from engine import load_file_engines,load_runtime_file_engines

class CloudC8VpnRegistry(unittest.TestCase):
    def test_c0_is_frozen_and_hxt_has_its_own_real_codec(self):
        canonical=load_file_engines()
        self.assertEqual(len(canonical),240)
        self.assertEqual(canonical["hxt"]["source"],str((ROOT/"decoders/Python/xor_family.py").resolve()))
        extended=load_runtime_file_engines()
        self.assertEqual(len(extended),246) # six new suffixes, .hxt overrides its old engine.
        self.assertIn("/apps/HX_Tunnel_VPN/HX_Tunnel_VPN_archivos.py",extended["hxt"]["source"])
        self.assertNotEqual(canonical["hxt"]["source"],extended["hxt"]["source"])
        for suffix in ("rt","gol","ua","nvpnc","green"):
            self.assertEqual(extended[suffix]["phase"],"C8")
            self.assertTrue(Path(extended[suffix]["source"]).is_file())
        self.assertEqual(extended["hc"],canonical["hc"])
        self.assertEqual(extended["solid"],canonical["solid"])

if __name__=="__main__":
    unittest.main()
