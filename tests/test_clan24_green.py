"""Separate 24clan catalog/profile engines, independent JCE/Java vectors."""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import Request

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/"decoders/Python/apps/24clan_VPN_Green"
FIXTURE=json.loads((ROOT/"tests/golden/clan24_green_vectors.json").read_text("utf-8"))


def load(name):
    spec=importlib.util.spec_from_file_location(name,APP/(name+".py"))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


catalog=load("24clan_VPN_Green")
profiles=load("24clan_VPN_Green_archivos")


class Clan24GreenTests(unittest.TestCase):
    def test_independent_jce_catalog_full_document(self):
        result=catalog.decode(FIXTURE["catalog"])
        self.assertEqual(result,FIXTURE["expectedCatalog"])
        self.assertEqual(json.loads(catalog.run(FIXTURE["catalog"])),result)
        self.assertEqual(result["future"],{"keep":True})
        self.assertEqual(result["PremiumServers"],FIXTURE["expectedCatalog"]["PremiumServers"])

    def test_independent_java_profile_full_document(self):
        result=profiles.decode(FIXTURE["profile"])
        self.assertEqual(result,FIXTURE["expectedProfile"])
        self.assertEqual(json.loads(profiles.run(FIXTURE["profile"])),result)
        self.assertEqual(result["Payload"],"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
        self.assertEqual(result["Note"],"First\nSecond\r\nThird")
        self.assertEqual(result["HWID"],"SYNTHETIC-DEVICE")
        self.assertEqual(result["ExpireDate"],1)
        self.assertTrue(result["BlockRoot"])
        self.assertEqual(json.loads(result["Server"])["Password"],"fixture-only")
        self.assertIsInstance(result["Server"],str)

    def test_java_length_word_rounds_and_all_padding_remainders(self):
        for vector in FIXTURE["lengthVectors"]+FIXTURE["shortVectors"]:
            self.assertEqual(profiles.decode(vector["data"]),vector["expected"])
        self.assertEqual({v["utf8Bytes"]%4 for v in FIXTURE["lengthVectors"]},{0,1,2,3})

    def test_modified_delta_and_shared_key_are_required(self):
        with patch.object(profiles,"DELTA",0x9e3779b9):
            self.assertIsNone(profiles.run(FIXTURE["profile"]))
        with patch.object(profiles,"PROFILE_KEY",b"foreign-format"):
            self.assertIsNone(profiles.run(FIXTURE["profile"]))

    def test_original_icon_name_dimensions_and_checksum(self):
        data=(APP/"24clan_VPN_Green.png").read_bytes()
        self.assertEqual(data[:8],b"\x89PNG\r\n\x1a\n")
        self.assertEqual(struct.unpack(">II",data[16:24]),(512,512))
        self.assertEqual(hashlib.sha256(data).hexdigest(),"ab923a12fe537a3b3bfe131f2c3b3c77a13d0439c2ab1ce94701f787423ffedb")

    def test_engines_are_exclusive(self):
        self.assertIsNone(catalog.run(FIXTURE["profile"]))
        self.assertIsNone(profiles.run(FIXTURE["catalog"]))
        with self.assertRaises(profiles.DecodeError) as ctx:
            profiles.decode(FIXTURE["catalog"])
        self.assertEqual(ctx.exception.code,"WRONG_DOCUMENT")
        self.assertFalse(hasattr(profiles,"fetch_catalog"))

    def test_transport_bom_wrapping_and_missing_padding(self):
        for module,name in [(catalog,"catalog"),(profiles,"profile")]:
            data=FIXTURE[name];expected=module.decode(data)
            for value in ["\ufeff \r\n"+data+"\n",data.rstrip("="),
                          "\r\n".join(data[i:i+76] for i in range(0,len(data),76))]:
                self.assertEqual(module.decode(value),expected)

    def test_invalid_types_base64_unicode_and_resource_sizes(self):
        for module in [catalog,profiles]:
            for value in [None,1,[],b"",b"\xff",b"A",b"!bad!",b"AAAA===",b"wrong://AAAA","\ud800"]:
                self.assertIsNone(module.run(value))
            with patch.object(module,"MAX_BYTES",8):
                self.assertIsNone(module.run(b"x"*9))
                self.assertIsNone(module.run("日"*3))

    def test_catalog_header_truncation_and_invalid_cbc_padding(self):
        raw=base64.b64decode(FIXTURE["catalog"])
        for data in [b"not Salted header",b"Salted__",raw[:-1]]:
            self.assertIsNone(catalog.run(base64.b64encode(data)))
        modified=bytearray(raw);modified[-17]^=128
        with self.assertRaises(catalog.DecodeError) as ctx:
            catalog.decode(base64.b64encode(modified))
        self.assertEqual(ctx.exception.code,"DECRYPT_FAILED")

    def test_profile_truncated_words_and_invalid_internal_length(self):
        for data in [b"a",b"abcd",b"abcde",bytes(8),bytes(12)]:
            self.assertIsNone(profiles.run(base64.b64encode(data)))
        raw=base64.b64decode(FIXTURE["profile"])
        self.assertIsNone(profiles.run(base64.b64encode(raw[:-1])))

    def test_strict_json_negative_java_vectors(self):
        for data in FIXTURE["invalidProfiles"]:
            self.assertIsNone(profiles.run(data))
        for data in ['{"Servers":[],"a":1,"a":2}','{"Servers":[],"a":NaN}',
                     '{"Servers":[],"a":1e999}','{"Servers":[],"a":"\\ud800"}','{broken}']:
            self.assertIsNone(catalog.run(data))

    def test_catalog_plaintext_fallback_and_complete_list_schema(self):
        expected=FIXTURE["expectedCatalog"]
        self.assertEqual(catalog.decode(json.dumps(expected)),expected)
        self.assertEqual(catalog.decode('{"Servers":[],"future":true}'),{"Servers":[],"future":True})
        for text in ['{}','[]','{"Servers":null}','{"Tweaks":[{},1]}','{"PremiumServers":{}}']:
            self.assertIsNone(catalog.run(text))

    def test_thousand_tweaks_and_premium_members_not_truncated(self):
        doc={"Version":"test","Servers":[{"id":i} for i in range(1000)],
             "PremiumServers":[{"id":"premium"}],"Tweaks":[{"id":i} for i in range(2000)],
             "PremiumTweaks":[{"future":True}]}
        self.assertEqual(catalog.decode(json.dumps(doc)),doc)

    def test_json_depth_and_node_limits(self):
        for module in [catalog,profiles]:
            with patch.object(module,"MAX_DEPTH",2):
                with self.assertRaises(module.DecodeError):module._json('{"a":{"b":{"c":1}}}')
            with patch.object(module,"MAX_NODES",4):
                with self.assertRaises(module.DecodeError):module._json('{"a":1,"b":2}')
            with self.assertRaises(module.DecodeError):module._json("["*1500+"0"+"]"*1500)

    def test_offline_api_never_downloads(self):
        with patch.object(catalog,"build_opener",side_effect=AssertionError("unexpected network")):
            self.assertIsNotNone(catalog.run(FIXTURE["catalog"]))
            self.assertIsNone(catalog.run("invalid"))
            self.assertIsNotNone(profiles.run(FIXTURE["profile"]))

    def test_http_get_original_url_headers_timeout_and_read_limit(self):
        with patch.object(catalog,"build_opener") as build:
            response=build.return_value.open.return_value.__enter__.return_value
            response.status=200;response.read.return_value=FIXTURE["catalog"].encode()
            self.assertEqual(catalog.decode(catalog.fetch_catalog()),FIXTURE["expectedCatalog"])
            req=build.return_value.open.call_args.args[0]
            self.assertEqual(req.full_url,catalog.CATALOG_URL)
            self.assertEqual(req.get_method(),"GET")
            self.assertIsNone(req.data)
            self.assertEqual(req.get_header("User-agent"),catalog.USER_AGENT)
            self.assertEqual(build.return_value.open.call_args.kwargs,{"timeout":20})
            response.read.assert_called_once_with(catalog.MAX_BYTES+1)

    def test_https_prechecks_and_redirect_policy(self):
        with patch.object(catalog,"build_opener",side_effect=AssertionError("unexpected request")):
            for url in ["http://example.invalid","https://u:p@example.invalid","https:///missing","https://example.invalid/#fragment"]:
                with self.assertRaises(catalog.DecodeError):catalog.fetch_catalog(url)
        req=Request(catalog.CATALOG_URL);handler=catalog._HTTPSRedirect()
        self.assertIsNone(handler.redirect_request(req,None,302,"",{},"http://example.invalid"))
        self.assertIsNone(handler.redirect_request(req,None,302,"",{},"https://u:p@example.invalid"))
        self.assertEqual(handler.redirect_request(req,None,302,"",{},"https://example.invalid").full_url,"https://example.invalid")

    def test_http_failures_are_sanitized_and_bounded(self):
        for error,code in [(HTTPError(catalog.CATALOG_URL,403,"private-value",{},None),"ACCESS_DENIED"),
                           (URLError("private-value"),"DOWNLOAD_FAILED")]:
            with patch.object(catalog,"build_opener") as build:
                build.return_value.open.side_effect=error
                with self.assertRaises(catalog.DecodeError) as ctx:catalog.fetch_catalog()
            self.assertEqual(ctx.exception.code,code)
            self.assertNotIn("private-value",str(ctx.exception))
        with patch.object(catalog,"MAX_BYTES",8),patch.object(catalog,"build_opener") as build:
            response=build.return_value.open.return_value.__enter__.return_value
            response.status=200;response.read.return_value=b"x"*9
            with self.assertRaises(catalog.DecodeError) as ctx:catalog.fetch_catalog()
            self.assertEqual(ctx.exception.code,"SIZE_LIMIT")

    def test_standalone_scripts_can_be_copied_separately(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for filename,name in [("24clan_VPN_Green.py","catalog"),("24clan_VPN_Green_archivos.py","profile")]:
                script=root/filename;shutil.copyfile(APP/filename,script)
                source,out=root/(name+".txt"),root/(name+".json")
                source.write_text(FIXTURE[name])
                proc=subprocess.run([sys.executable,str(script),str(source),"-o",str(out)],cwd=root,capture_output=True,text=True)
                self.assertEqual(proc.returncode,0,proc.stderr)
                self.assertEqual(json.loads(out.read_text()),FIXTURE["expectedCatalog" if name=="catalog" else "expectedProfile"])
                script.unlink()

    def test_cli_encrypted_text_and_explicit_catalog_download(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(profiles.main(["--text",FIXTURE["profile"]]),0)
        self.assertEqual(json.loads(out.getvalue()),FIXTURE["expectedProfile"])
        with patch.object(catalog,"fetch_catalog",return_value=FIXTURE["catalog"]) as fetch,contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(catalog.main(["--url"]),0)
        fetch.assert_called_once_with(catalog.CATALOG_URL)
        self.assertEqual(json.loads(out.getvalue()),FIXTURE["expectedCatalog"])

    def test_cli_failures_preserve_output_and_missing_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source,out=root/"bad.txt",root/"out.json"
            source.write_text("!broken!");out.write_text("keep previous")
            for module in [catalog,profiles]:
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(module.main([str(source),"-o",str(out)]),1)
                self.assertIn("error",json.loads(err.getvalue()))
                self.assertEqual(out.read_text(),"keep previous")
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(module.main([str(root/"missing")]),2)


if __name__ == "__main__":
    unittest.main()
