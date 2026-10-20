"""HA Tunnel Cloud retains complete JSON instead of old partial summary."""
import base64
import json
import shutil
import unittest

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from cloud.workers.python.engine import DecodeFailure, decode_file


@unittest.skipUnless(shutil.which("node"), "Node runtime required")
class HatCloudFullOutputTests(unittest.TestCase):
    KEY=base64.b64decode("zbNkuNCGSLivpEuep3BcNA==")
    XOR="**rVg7EkL~c2"+chr(96)+"D[aNn"

    @classmethod
    def seal(cls, data):
        raw=json.dumps(data,ensure_ascii=False,separators=(",",":")).encode("utf-8")
        return base64.b64encode(AES.new(cls.KEY,AES.MODE_ECB).encrypt(pad(raw,16)))

    @classmethod
    def wrap_xor(cls,value):
        wrapped="".join(chr(ord(char)^ord(cls.XOR[index%len(cls.XOR)]))
                        for index,char in enumerate(value))
        return base64.b64encode(wrapped.encode("utf-8")).decode("ascii")

    def test_full_nested_configuration_not_just_profile_tail(self):
        original={
            "configuration":{"connection_mode":1,"server_host":"example.test",
                             "server_username":"user","server_password":"secret",
                             "options":{"keepalive":7,"flags":[1,False,{"extra":None}]}},
            "meta":{"meta_vendor_msg":"Sample","extra":"untouched"},
            "profilev5":{"connection_mode":self.wrap_xor("SSL + SSH"),
                         "custom_payload":self.wrap_xor("GET / HTTP/1.1"),
                         "custom_sni":self.wrap_xor("example.test"),
                         "custom_host":self.wrap_xor("edge.example.test"),
                         "custom_resolver":"1.1.1.1",
                         "future_field":{"enabled":True,"levels":[1,2,3]}},
            "protextras":{"anti_sniff":True,"mobile_data":False},
            "extra_top_level":{"vendor_unknown":23},
        }
        result=decode_file("hat",self.seal(original),full_hat=True)
        self.assertEqual(result["status"],"success")
        self.assertFalse(result["isPartial"])
        data=json.loads(result["rawText"])
        self.assertEqual(result["structuredJson"],data)
        self.assertIsNone(data["configuration"]["options"]["flags"][2]["extra"])
        self.assertEqual(data["configuration"]["server_password"],"secret")
        self.assertEqual(data["profilev5"]["connection_mode"],"SSL + SSH")
        self.assertEqual(data["profilev5"]["custom_payload"],"GET / HTTP/1.1")
        self.assertEqual(data["profilev5"]["future_field"],original["profilev5"]["future_field"])
        self.assertEqual(data["extra_top_level"],original["extra_top_level"])
        self.assertIs(data["protextras"]["mobile_data"],False)

    def test_invalid_ciphertext_fails_closed(self):
        for bad in (b"not base64!",b"AA==",base64.b64encode(b"x"*32)):
            with self.subTest(bad=bad),self.assertRaises(DecodeFailure):
                decode_file("hat",bad,full_hat=True)


if __name__=="__main__":
    unittest.main()
