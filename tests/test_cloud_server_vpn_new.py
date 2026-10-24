"""Offline server-side regressions for owner-supplied KSH/MKK/DTunnel methods.

Every fixture is generated locally, encrypted with each vendor's exact format
constants and executed through the production sandboxed subprocess bridge.
No vendor endpoints, VPN connections or private account identifiers are used.
"""
from __future__ import annotations
import base64
import json
import unittest

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from cloud.workers.python.engine import DecodeFailure, decode_provider_catalog
from decoders.Python.apps.KSH_VPN import ksh_vpn as ksh_catalog
from decoders.Python.apps.DTunnel_Mod import dtunnelmod as dtunnelmod_catalog
from decoders.Python.apps.MKK_Hyper_VPN import MKK_Hyper_VPN as mkk

def seal_ksh(value):
    nonce=bytes(range(12))
    cipher=AES.new(ksh_catalog.CATALOG_KEY,AES.MODE_GCM,nonce=nonce)
    data,tag=cipher.encrypt_and_digest(json.dumps(value).encode())
    return json.dumps({"enc":base64.b64encode(nonce+data+tag).decode()}).encode()

def seal_mkk(value):
    nonce=bytes(range(12))
    cipher=AES.new(mkk._payload_key(),AES.MODE_GCM,nonce=nonce)
    data,tag=cipher.encrypt_and_digest(json.dumps(value).encode())
    return json.dumps({"nonce":base64.b64encode(nonce).decode(),
        "cipher_text":base64.b64encode(data).decode(),
        "mac":base64.b64encode(tag).decode()}).encode()

def seal_dtunnel(value):
    plain=json.dumps(value).encode()
    encrypted=AES.new(dtunnelmod_catalog.CATALOG_KEY,AES.MODE_CBC,iv=bytes(16)).encrypt(pad(plain,16))
    return base64.b64encode(encrypted)

def bundle(sources):
    return json.dumps({"kind":"spdecode-mkk-sources-v1",
        "sources":[{"name":name,"status":"ok","dataBase64":base64.b64encode(data).decode()}
         for name,data in sources]},separators=(",",":")).encode()

class NewServerVpnTests(unittest.TestCase):
    def test_ksh_multiple_entries_full_json_and_ciphertext_tampering(self):
        source={"servers":[{"name":"alpha","config":{"hosts":[1,2,3]}},
            {"name":"beta","enabled":False},{"name":"gamma","extra":{"nested":[1,None]}}]}
        encoded=seal_ksh(source)
        result=decode_provider_catalog("ksh-vpn",encoded)
        self.assertEqual(result["structuredJson"],source)
        self.assertEqual(json.loads(result["rawText"]),source)
        self.assertFalse(result["isPartial"])
        changed=json.loads(encoded)
        raw=bytearray(base64.b64decode(changed["enc"]))
        raw[-1]^=1
        changed["enc"]=base64.b64encode(raw).decode()
        with self.assertRaises(DecodeFailure):
            decode_provider_catalog("ksh-vpn",json.dumps(changed).encode())

    def test_mkk_decodes_all_four_sources_not_just_first_one(self):
        documents=[
          ("servers",{"servers":[{"host":f"node{i}","metadata":{"i":i}} for i in range(5)]}),
          ("static",{"static_users":[{"name":"one"},{"name":"two"}]}),
          ("subscriptions",{"subscriptions":[{"url":"https://example.invalid/a"}]}),
          ("legacy-subscriptions",{"Global":"https://example.invalid/list","US":"https://example.invalid/us"}),
        ]
        encoded=bundle([(name,seal_mkk(doc) if name=="servers" else json.dumps(doc).encode())
          for name,doc in documents])
        result=decode_provider_catalog("mkk-hyper",encoded)
        doc=result["structuredJson"]
        self.assertTrue(doc["complete"])
        self.assertEqual(doc["successfulSources"],4)
        self.assertEqual([x["name"] for x in doc["sources"]],[x[0] for x in documents])
        self.assertEqual([x["records"] for x in doc["sources"]],[5,2,1,2])
        self.assertEqual(doc["sources"][0]["data"],documents[0][1])
        self.assertEqual(doc["sources"][2]["data"],documents[2][1])
        self.assertFalse(result["isPartial"])
        self.assertEqual(json.loads(result["rawText"]),doc)

    def test_mkk_partial_is_explicit_not_silently_one_result(self):
        values={"kind":"spdecode-mkk-sources-v1","sources":[
            {"name":"servers","status":"ok","dataBase64":base64.b64encode(seal_mkk({"servers":[{"id":1},{"id":2}]})).decode()},
            {"name":"static","status":"error","error":"REMOTE_PROVIDER_UNAVAILABLE"},
            {"name":"subscriptions","status":"ok","dataBase64":base64.b64encode(b"{not valid").decode()},
            {"name":"legacy-subscriptions","status":"error","error":"REMOTE_NETWORK_DENIED"},
        ]}
        result=decode_provider_catalog("mkk-hyper",json.dumps(values,separators=(",",":")).encode())
        doc=result["structuredJson"]
        self.assertFalse(doc["complete"])
        self.assertEqual(doc["successfulSources"],1)
        self.assertTrue(result["isPartial"])
        self.assertIn("PARTIAL_SOURCE_FAILURE",result["warnings"])
        self.assertEqual([x["status"] for x in doc["sources"]],["ok","error","error","error"])
        self.assertEqual(doc["sources"][0]["records"],2)

    def test_dtunnel_offline_full_catalog_and_vpn_link(self):
        doc=[{"name":"one","params":{"entries":[1,2]}},{"name":"two","note":"all retained"},{"name":"three","enabled":True}]
        result=decode_provider_catalog("dtunnel-mod",seal_dtunnel(doc))
        self.assertEqual(result["structuredJson"],doc)
        link={"name":"offline","profile":{"host":"example.invalid"}}
        wrapped=b"vpn://"+base64.b64encode(json.dumps(link).encode())
        self.assertEqual(decode_provider_catalog("dtunnel-mod",wrapped)["structuredJson"],link)
        with self.assertRaises(DecodeFailure):
            decode_provider_catalog("dtunnel-mod",b"invalid ciphertext")

if __name__=="__main__":
    unittest.main()
