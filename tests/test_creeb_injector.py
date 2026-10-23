"""CREEB 38.0: independent JDK DES/Properties fixtures and raw JSON bundles."""
from __future__ import annotations
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from decoders.Python.apps.CREEB_INJECTOR import codec,file_decoder

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"cloud/workers/python"))
FIXTURE=json.loads((ROOT/"tests/golden/creeb_vectors.json").read_text())


class CreebTests(unittest.TestCase):
    def test_all_jdk_des_properties_match_and_keep_original_xml(self):
        for v in FIXTURE["desFiles"]:
            with self.subTest(name=v["name"]):
                actual=codec.decode(base64.b64decode(v["cipherBase64"]))
                self.assertEqual(actual["properties"],v["properties"])
                self.assertEqual(actual["raw_xml"].encode(),base64.b64decode(v["xmlBase64"]))
                self.assertEqual({x["key"]:x["value"] for x in actual["entries"]},v["properties"])

    def test_password_and_hwid_are_preserved_without_external_secrets(self):
        v=next(v for v in FIXTURE["desFiles"] if v["name"]=="locked")
        props=json.loads(file_decoder.run(base64.b64decode(v["cipherBase64"])))["properties"]
        self.assertEqual(props["file.passwordHash"],v["properties"]["file.passwordHash"])
        self.assertEqual(props["file.pedirLogin"],"1")
        self.assertEqual(props["hwidstring"],"synthetic-device")

    def test_multiple_profile_bundles_preserve_the_entire_json(self):
        for bundle in FIXTURE["jsonBundles"]:
            data=json.dumps(bundle,ensure_ascii=False).encode()
            self.assertEqual(json.loads(file_decoder.run(data)),bundle)
            self.assertEqual(len(codec.decode(data)["profiles"]),2)

    def test_duplicate_entries_empty_values_and_surrogate_numeric_pairs(self):
        v=next(v for v in FIXTURE["desFiles"] if v["name"]=="duplicate-entries")
        actual=codec.decode(base64.b64decode(v["cipherBase64"]))
        self.assertEqual([x["value"] for x in actual["entries"] if x["key"]=="duplicate"],["first","last"])
        self.assertEqual(actual["properties"]["duplicate"],"last")
        self.assertEqual(actual["properties"]["emoji"]," 😀 😀")
        self.assertEqual(actual["properties"]["empty"],"")
        self.assertEqual(actual["properties"]["crlf"],"one\r\ntwo")

    def test_custom_dtd_entities_and_non_properties_xml_are_rejected(self):
        for xml in (
            b'<!DOCTYPE properties [<!ENTITY x "data">]><properties><entry key="a">&x;</entry></properties>',
            b'<!DOCTYPE properties SYSTEM "https://attacker.invalid/x"><properties><entry key="a">b</entry></properties>',
            b'<properties><entry key="a"><nested/></entry></properties>',
            b'<not-properties><entry key="a">b</entry></not-properties>',
            b'<properties><entry key="a">&#xd83d;</entry></properties>',
        ):
            with self.assertRaises(ValueError):codec.decode_properties(xml)

    def test_malformed_wrong_formats_limits_and_json_types(self):
        for data in (b"",b"a"*7,b"https://attacker.invalid/",b"x"*(codec.MAX_BYTES+1),b'{"type":"other"}'):
            with self.assertRaises(ValueError):codec.decode(data)
        v=FIXTURE["desFiles"][0];raw=base64.b64decode(v["cipherBase64"])
        for data in (raw[:-1],bytes(16),b'<?xml version="1.0"?><properties/>'):
            with self.assertRaises(ValueError):codec.decode(data)
        for patch in ({"version":True},{"version":2},{"profiles":[]},{"profiles":[{"prefs":[]}]},{"security":None}):
            bundle={**FIXTURE["jsonBundles"][0],**patch}
            with self.assertRaises(ValueError):codec.decode(json.dumps(bundle).encode())
        for data in (b'{"type":"creeb_profile_bundle","type":"other"}',b'{"x":NaN}',b'{"x":"\\ud800"}'):
            with self.assertRaises(ValueError):codec.decode(data)

    def test_complete_cli_outside_checkout_and_stdin(self):
        script=ROOT/"decoders/Python/apps/CREEB_INJECTOR/file_decoder.py"
        with tempfile.TemporaryDirectory() as folder:
            for data in (base64.b64decode(FIXTURE["desFiles"][1]["cipherBase64"]),json.dumps(FIXTURE["jsonBundles"][1]).encode()):
                p=Path(folder)/"synthetic.creeb";p.write_bytes(data)
                for argv,incoming in (([str(p)],None),(["-"],data)):
                    result=subprocess.run([sys.executable,str(script),*argv],input=incoming,cwd=folder,capture_output=True,timeout=20)
                    self.assertEqual(result.returncode,0);self.assertEqual(result.stderr,b"")
                    self.assertEqual(json.loads(result.stdout),codec.decode(data))

    def test_worker_and_http_handler_preserve_complete_json(self):
        from cloud.workers.python import engine,server
        from types import SimpleNamespace
        import io
        for data in (base64.b64decode(FIXTURE["desFiles"][1]["cipherBase64"]),json.dumps(FIXTURE["jsonBundles"][1]).encode()):
            result=engine.decode_file("creeb",data)
            self.assertEqual(result["structuredJson"],codec.decode(data));self.assertFalse(result["isPartial"])
            body=json.dumps({"format":"creeb","dataBase64":base64.b64encode(data).decode()}).encode()
            replies=[]
            fake=SimpleNamespace(path="/internal/v1/decode/file",headers={"Content-Length":str(len(body))},
                rfile=io.BytesIO(body),_authorized=lambda:True,_json=lambda status,value:replies.append((status,value)))
            server.WorkerHandler.do_POST(fake)
            self.assertEqual(replies[0][0],200)
            self.assertEqual(replies[0][1]["structuredJson"],codec.decode(data))

    def test_dedicated_bot_route_leaves_historical_crev_untouched(self):
        from spdecode.registry import get_decoder,get_supported_extension
        self.assertEqual(get_supported_extension("Synthetic.CREEB"),"creeb")
        self.assertTrue(get_decoder("creeb").script.endswith("apps/CREEB_INJECTOR/file_decoder.py"))
        self.assertEqual(get_decoder("crev").script,"decoders/Python/crev.py")


if __name__=="__main__":unittest.main()
