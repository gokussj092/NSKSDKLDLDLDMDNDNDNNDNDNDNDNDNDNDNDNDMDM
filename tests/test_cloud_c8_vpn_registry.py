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
        self.assertEqual(len(extended),303) # sixty-three new suffixes; existing suffix overrides stay separate from C0.
        self.assertIn("/apps/HX_Tunnel_VPN/HX_Tunnel_VPN_archivos.py",extended["hxt"]["source"])
        self.assertNotEqual(canonical["hxt"]["source"],extended["hxt"]["source"])
        self.assertIn("/apps/Royal_Tunnel_VPN/file_decoder.py",extended["roy"]["source"])
        self.assertEqual(extended["roy"]["phase"],"C8")
        self.assertEqual(canonical["roy"]["source"],canonical["xtp"]["source"])
        self.assertNotEqual(extended["roy"]["source"],extended["xtp"]["source"])
        self.assertEqual(extended["xtp"],canonical["xtp"])
        self.assertIn("/apps/4U_TUNNEL_LITE/file_decoder.py",extended["4ulite"]["source"])
        self.assertEqual(extended["4ulite"]["phase"],"C8")
        self.assertIn("xor_family.py",canonical["4ulite"]["source"])
        self.assertIn("/apps/AC_TUNNEL_VPN/file_decoder.py",extended["actun"]["source"])
        self.assertEqual(extended["actunnelvpn"],canonical["actunnelvpn"])
        self.assertIn("/apps/AustroPlus_VPN/file_decoder.py",extended["aro"]["source"])
        self.assertIn("/apps/HTTP_FenixVPN/file_decoder.py",extended["sks"]["source"])
        self.assertEqual(canonical["sks"]["runtime"],"node")
        self.assertIn("/apps/Tunneltweak/file_decoder.py",extended["tut"]["source"])
        self.assertIn("generic_des.py",canonical["tut"]["source"])
        for suffix in ("hexcm","creeb","awg","1ftnl","tgv","rt","gol","ua","nvpnc","green"):
            self.assertEqual(extended[suffix]["phase"],"C8")
            self.assertTrue(Path(extended[suffix]["source"]).is_file())
        for suffix in ("v2rc","ucs","v2k","eyj","dgm"):
            self.assertEqual(extended[suffix]["phase"],"C8")
            self.assertTrue(Path(extended[suffix]["source"]).is_file())
        self.assertIn("/apps/SNI_Tunnel/file_decoder.py",extended["v2rc"]["source"])
        self.assertIn("/apps/Ultra_Custom/file_decoder.py",extended["ucs"]["source"])
        self.assertIn("/apps/V2Ray_Injector/file_decoder.py",extended["v2k"]["source"])
        self.assertIn("/apps/DGM_Tunnel/file_decoder.py",extended["eyj"]["source"])
        self.assertIn("/apps/DGM_Tunnel/file_decoder.py",extended["dgm"]["source"])
        self.assertIn("/apps/Ultra_Custom/ultra_custom.py",extended["ua"]["source"])
        self.assertEqual(extended["ua"]["name"],"Ultra Custom 15.7")
        # .st stays Sentinel-routed in the inventory; Surya is a
        # content dispatch inside decode_file(), not a new suffix.
        self.assertIn("/apps/Sentinel_Tunnel/file_decoder.py",extended["st"]["source"])
        self.assertEqual(extended["st"]["phase"],"C8")
        self.assertIn("/apps/CREEB_VPN/file_decoder.py",extended["crev"]["source"])
        self.assertEqual(extended["cer"],canonical["cer"])
        self.assertEqual(extended["cerv"],canonical["cerv"])
        self.assertEqual(extended["hc"],canonical["hc"])
        self.assertEqual(extended["solid"],canonical["solid"])

if __name__=="__main__":
    unittest.main()
