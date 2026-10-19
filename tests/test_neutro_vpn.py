"""Neutro Vpn: independent JCE vectors, mutation tests and mocked HTTP."""
import base64
import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from decoders.Python import neutro_vpn as nv

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT/"tests/golden/neutro_vpn_vectors.json").read_text("utf-8"))
PUBLIC = base64.b64decode(FIXTURE["catalogPublicKey"])


def b64(data):
    return base64.b64encode(data).decode()


def gcm(plain, key=nv.SHARED_KEY):
    nonce = bytes(range(12))
    cipher = AES.new(key,AES.MODE_GCM,nonce=nonce)
    encrypted,tag = cipher.encrypt_and_digest(plain.encode() if isinstance(plain,str) else plain)
    return nonce,encrypted+tag


def profile(plain):
    nonce,cipher = gcm(plain)
    return "NVPNC1.L.."+b64(nonce)+"."+b64(cipher)


def catalog(plain, key=nv.SHARED_KEY):
    nonce,cipher = gcm(plain,key)
    # Public synthetic test scalar, unrelated to the production verification key.
    signature = DSS.new(ECC.construct(curve="P-256",d=1),"fips-186-3",encoding="der").sign(SHA256.new(nonce+cipher))
    return ".".join(map(b64,[nonce,cipher,signature]))


class NeutroVpnTests(unittest.TestCase):
    def test_jce_profiles_complete_json_and_password_unicode(self):
        for name in ["local","protected"]:
            with self.subTest(name=name):
                doc = nv.decode(FIXTURE[name],password=FIXTURE["password"])
                self.assertEqual(doc,FIXTURE["expectedProfile"])
                self.assertEqual(json.loads(nv.run(FIXTURE[name],password=FIXTURE["password"])),doc)
                self.assertEqual(doc["payload"],"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
                self.assertEqual(doc["expiresAt"],1)
                self.assertTrue(doc["rootBlock"])
                self.assertEqual(doc["lockId"],"ABCD-EF12-3456")
                self.assertEqual(doc["future"],{"unknown":[None,False,""]})

    def test_jce_signed_catalog_and_all_metadata(self):
        doc = nv.decode_catalog(FIXTURE["catalog"],public_key=PUBLIC)
        self.assertEqual(doc,FIXTURE["expectedCatalog"])
        self.assertEqual(doc["profiles"],[FIXTURE["expectedProfile"]])
        self.assertEqual(json.loads(doc["capXray"])["outbounds"][0]["protocol"],"vless")
        with patch.object(nv,"CATALOG_PUBLIC_KEY",PUBLIC):
            self.assertEqual(json.loads(nv.run(FIXTURE["catalog"])),doc)

    def test_signature_checked_before_aes_and_production_key_rejects_test_key(self):
        with patch.object(nv.AES,"new",side_effect=AssertionError("AES before signature")):
            with self.assertRaises(nv.DecodeError) as ctx:
                nv.decode_catalog(FIXTURE["catalog"])
        self.assertEqual(ctx.exception.code,"SIGNATURE_INVALID")
        self.assertIsNone(nv.run(FIXTURE["catalog"]))
        with self.assertRaises(nv.DecodeError):
            nv.decode_catalog(FIXTURE["catalog"],public_key=b"invalid")

    def test_catalog_tampering_nonce_ciphertext_tag_signature(self):
        original = FIXTURE["catalog"].split(".")
        for component,index in [(0,0),(1,0),(1,-1),(2,-1)]:
            parts = original.copy()
            raw = bytearray(base64.b64decode(parts[component]));raw[index] ^= 1
            parts[component] = b64(raw)
            with self.assertRaises(nv.DecodeError) as ctx:
                nv.decode_catalog(".".join(parts),public_key=PUBLIC)
            self.assertEqual(ctx.exception.code,"SIGNATURE_INVALID")

    def test_signed_catalog_still_requires_valid_gcm(self):
        with self.assertRaises(nv.DecodeError) as ctx:
            nv.decode_catalog(catalog('{"profiles":[]}',key=b"x"*32),public_key=PUBLIC)
        self.assertEqual(ctx.exception.code,"AUTH_FAILED")

    def test_password_required_wrong_password_and_significant_spaces(self):
        for password in [None,""]:
            with self.assertRaises(nv.DecodeError) as ctx:
                nv.decode_profile(FIXTURE["protected"],password=password)
            self.assertEqual(ctx.exception.code,"PASSWORD_REQUIRED")
        for password in ["wrong",FIXTURE["password"].strip()]:
            with self.assertRaises(nv.DecodeError) as ctx:
                nv.decode_profile(FIXTURE["protected"],password=password)
            self.assertEqual(ctx.exception.code,"AUTH_FAILED")
        with patch.object(nv,"MAX_PASSWORD_BYTES",2):
            with self.assertRaises(nv.DecodeError) as ctx:
                nv.decode_profile(FIXTURE["protected"],password="日本")
            self.assertEqual(ctx.exception.code,"SIZE_LIMIT")

    def test_profile_gcm_tampering_salt_nonce_cipher_and_tag(self):
        for name in ["local","protected"]:
            original = FIXTURE[name].split(".")
            targets = [(3,0),(4,0),(4,-1)]+([(2,0)] if name=="protected" else [])
            for component,index in targets:
                parts = original.copy()
                raw=bytearray(base64.b64decode(parts[component]));raw[index]^=1
                parts[component]=b64(raw)
                with self.assertRaises(nv.DecodeError) as ctx:
                    nv.decode_profile(".".join(parts),password=FIXTURE["password"])
                self.assertEqual(ctx.exception.code,"AUTH_FAILED")

    def test_profile_headers_lengths_and_empty_fields(self):
        original = FIXTURE["local"].split(".")
        for text in ["NVPNC2.L..AAAA.AAAA","NVPNC1.X..AAAA.AAAA","NVPNC1.L..AAAA", "NVPNC1.L..AAAA.AAAA.extra"]:
            self.assertIsNone(nv.run(text))
        for component,value in [(2,b64(b"x")),(3,b64(b"x"*11)),(4,b64(b"x"*16)),(4,"")]:
            parts=original.copy();parts[component]=value
            self.assertIsNone(nv.run(".".join(parts)))
        parts=FIXTURE["protected"].split(".");parts[2]=b64(b"x"*15)
        self.assertIsNone(nv.run(".".join(parts),password=FIXTURE["password"]))

    def test_bom_whitespace_wrapping_and_optional_base64_padding(self):
        for name in ["local","protected"]:
            data=FIXTURE[name]
            expected=nv.decode(data,password=FIXTURE["password"])
            variants=["\ufeff \r\n"+data+"\n", ".".join(p.rstrip("=") for p in data.split(".")),
                      ".".join("\r\n".join(p[i:i+64] for i in range(0,len(p),64)) for p in data.split("."))]
            for variant in variants:
                self.assertEqual(nv.decode(variant,password=FIXTURE["password"]),expected)

    def test_strict_json_duplicates_nonfinite_unicode_and_utf8(self):
        for text in ['{"a":1,"a":2}','{"a":NaN}','{"a":1e999}','{"a":"\\ud800"}','{broken}',b'\xff']:
            self.assertIsNone(nv.run(profile(text)))
            with self.assertRaises(nv.DecodeError):
                nv.decode_catalog(catalog(text),public_key=PUBLIC)
        self.assertIsNone(nv.run(profile('[]')))

    def test_catalog_schema_empty_list_and_settings_only(self):
        for text in ['{"v":1,"profiles":[]}','{"v":1,"future":{"keep":true}}']:
            self.assertEqual(nv.decode_catalog(catalog(text),public_key=PUBLIC),json.loads(text))
        for text in ['[]','{"profiles":null}','{"profiles":[{},"bad"]}']:
            with self.assertRaises(nv.DecodeError):
                nv.decode_catalog(catalog(text),public_key=PUBLIC)

    def test_catalog_thousand_members_and_json_complexity_limits(self):
        expected={"v":8,"profiles":[{"id":i,"future":{"keep":True}} for i in range(1000)]}
        self.assertEqual(nv.decode_catalog(catalog(json.dumps(expected)),public_key=PUBLIC),expected)
        for attr,value in [("MAX_DEPTH",2),("MAX_NODES",5)]:
            with patch.object(nv,attr,value):
                self.assertIsNone(nv.run(profile('{"a":{"b":{"c":[1,2,3]}}}')))

    def test_vmess_base64_and_direct_links_preserve_original_and_parameters(self):
        config={"add":"example.invalid","id":"synthetic-id","port":"443","future":{"keep":True}}
        link="vmess://"+b64(json.dumps(config).encode()).rstrip("=")+"#Nombre%20de%20prueba"
        result=nv.decode(link)
        self.assertEqual(result["raw"],link)
        self.assertEqual(result["config"],config)
        self.assertEqual(result["fragment"],"Nombre de prueba")
        link="vmess://synthetic-id@example.invalid:443?type=ws&future=a+b&future=&empty#Prueba"
        result=nv.decode_link(link)
        self.assertEqual(result["query"],[["type","ws"],["future","a+b"],["future",""],["empty",""]])
        self.assertEqual(result["userinfo"],"synthetic-id")

    def test_shadowsocks_legacy_and_sip002_ipv6_password_and_query(self):
        secret="aes-256-gcm:synthetic:p+ss"
        for link in ["ss://"+b64((secret+"@[2001:db8::1]:8388").encode()),
                     "ss://"+b64(secret.encode()).rstrip("=")+"@[2001:db8::1]:8388/?plugin=keep%3Braw#Test",
                     "ss://aes-256-gcm:synthetic%3Ap%2Bss@[2001:db8::1]:8388"]:
            result=nv.decode_link(link)
            self.assertEqual(result["raw"],link)
            self.assertEqual(result["server"],"2001:db8::1")
            self.assertEqual(result["port"],8388)
            self.assertEqual(result["method"],"aes-256-gcm")
            self.assertEqual(result["password"],"synthetic:p+ss")

    def test_other_standard_links_and_plain_xray_preserve_raw_fields(self):
        for scheme in ["vless","trojan","hysteria","hysteria2","hy2"]:
            link=scheme+"://synthetic%3Auser@example.invalid:443/?sni=example.invalid&future=%E6%97%A5#Test"
            result=nv.decode(link)
            self.assertEqual(result["scheme"],scheme)
            self.assertEqual(result["userinfo"],"synthetic:user")
            self.assertEqual(result["query"][-1],["future","日"])
            self.assertEqual(json.loads(nv.run(link)),result)
        xray=json.loads(FIXTURE["expectedProfile"]["xray"])
        self.assertEqual(nv.decode(json.dumps(xray)),xray)
        self.assertIsNone(nv.run('{"outbounds":[]}'))
        self.assertIsNone(nv.run('{"name":"not an Xray config"}'))

    def test_invalid_inputs_and_links_do_not_escape_contract(self):
        for text in [None,1,[],b"\xff",b"",b"A",b"!bad!","http://example.invalid","vpn://AAAA", "vless://host:notaport", "vless://[bad", "ss://AAAA", "vmess://AAAA", "vless://example.invalid\nvless://other.invalid"]:
            self.assertIsNone(nv.run(text))
        with patch.object(nv,"MAX_BYTES",5):
            self.assertIsNone(nv.run(b"x"*6))
            self.assertIsNone(nv.run("日"*3))

    def test_offline_contract_does_not_download(self):
        with patch.object(nv,"build_opener",side_effect=AssertionError("unexpected network")):
            self.assertIsNotNone(nv.run(FIXTURE["local"]))
            self.assertIsNotNone(nv.run("vless://synthetic@example.invalid:443"))
            self.assertIsNone(nv.run("invalid"))

    def test_download_get_headers_generated_id_build_and_bounds(self):
        with patch.object(nv,"CATALOG_PUBLIC_KEY",PUBLIC),patch.object(nv,"build_opener") as build:
            response=build.return_value.open.return_value.__enter__.return_value
            response.status=200;response.read.return_value=FIXTURE["catalog"].encode()
            self.assertEqual(nv.download_catalog(),FIXTURE["expectedCatalog"])
            req=build.return_value.open.call_args.args[0]
            query=parse_qs(urlsplit(req.full_url).query)
            self.assertRegex(query["i"][0],r"^[0-9a-f]{32}$")
            self.assertEqual(query["b"],["6"])
            self.assertEqual(req.get_method(),"GET")
            self.assertIsNone(req.data)
            self.assertEqual(req.get_header("User-agent"),"NeutroVpn/1")
            self.assertEqual(build.return_value.open.call_args.kwargs,{"timeout":20})
            response.read.assert_called_once_with(nv.MAX_BYTES+1)

    def test_fallback_only_after_failure_same_id_and_no_builtin_substitution(self):
        with patch.object(nv,"CATALOG_PUBLIC_KEY",PUBLIC),patch.object(nv,"_download",side_effect=[b"invalid",FIXTURE["catalog"]]) as download:
            self.assertEqual(nv.download_catalog(),FIXTURE["expectedCatalog"])
            self.assertEqual([c.args[0] for c in download.call_args_list],list(nv.CATALOG_URLS))
            self.assertEqual(len({c.args[1] for c in download.call_args_list}),1)
        with patch.object(nv,"_download",side_effect=nv.DecodeError("DOWNLOAD_FAILED","unavailable")) as download:
            with self.assertRaises(nv.DecodeError):nv.download_catalog()
            self.assertEqual(download.call_count,2)
        with patch.object(nv,"_download",return_value=b"invalid") as download:
            with self.assertRaises(nv.DecodeError):nv.download_catalog("https://example.invalid/config")
            self.assertEqual(download.call_count,1)

    def test_https_prechecks_redirects_errors_and_size_limits(self):
        with patch.object(nv,"build_opener",side_effect=AssertionError("unexpected network")):
            for url in ["http://example.invalid","https://u:p@example.invalid","https:///missing","https://example.invalid/#fragment"]:
                with self.assertRaises(nv.DecodeError):nv._download(url,"synthetic")
        handler=nv._HTTPSRedirect();req=Request("https://example.invalid")
        self.assertIsNone(handler.redirect_request(req,None,302,"",{},"http://other.invalid"))
        self.assertIsNone(handler.redirect_request(req,None,302,"",{},"https://u:p@other.invalid"))
        self.assertEqual(handler.redirect_request(req,None,302,"",{},"https://other.invalid").full_url,"https://other.invalid")
        for error,code in [(HTTPError("https://example.invalid",403,"private-text",{},None),"ACCESS_DENIED"),(URLError("private-text"),"DOWNLOAD_FAILED")]:
            with patch.object(nv,"build_opener") as build:
                build.return_value.open.side_effect=error
                with self.assertRaises(nv.DecodeError) as ctx:nv._download("https://example.invalid","synthetic")
                self.assertEqual(ctx.exception.code,code)
                self.assertNotIn("private-text",str(ctx.exception))
        with patch.object(nv,"MAX_BYTES",10),patch.object(nv,"build_opener") as build:
            response=build.return_value.open.return_value.__enter__.return_value
            response.status=200;response.read.return_value=b"x"*11
            with self.assertRaises(nv.DecodeError) as ctx:nv._download("https://example.invalid","synthetic")
            self.assertEqual(ctx.exception.code,"SIZE_LIMIT")

    def test_cli_standalone_profile_password_file_and_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);script=root/"neutro_vpn.py";source=root/"profile.nvpnc";pw=root/"password.txt";out=root/"out.json"
            shutil.copyfile(ROOT/"decoders/Python/neutro_vpn.py",script)
            source.write_text(FIXTURE["protected"]);pw.write_bytes(FIXTURE["password"].encode()+b"\r\n")
            proc=subprocess.run([sys.executable,str(script),str(source),"--password-file",str(pw),"-o",str(out)],cwd=root,capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr)
            self.assertEqual(json.loads(out.read_text()),FIXTURE["expectedProfile"])
            proc=subprocess.run([sys.executable,str(script),"--text",FIXTURE["local"]],cwd=root,capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr)
            self.assertEqual(json.loads(proc.stdout),FIXTURE["expectedProfile"])

    def test_password_file_removes_one_line_ending_and_preserves_bare_cr(self):
        with tempfile.TemporaryDirectory() as tmp:
            pw=Path(tmp)/"password.txt"
            for raw,expected in [(b" significant \r", " significant \r"),
                                 (b" significant \n\n", " significant \n"),
                                 (b" significant \r\n", " significant ")]:
                pw.write_bytes(raw)
                with patch.object(nv,"decode",return_value={}) as decode,contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(nv.main(["--text",FIXTURE["protected"],"--password-file",str(pw)]),0)
                decode.assert_called_once_with(FIXTURE["protected"],password=expected)

    def test_cli_download_and_interactive_password_are_explicit(self):
        with patch.object(nv,"download_catalog",return_value=FIXTURE["expectedCatalog"]) as download,contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(nv.main(["--url"]),0)
        download.assert_called_once_with(None)
        self.assertEqual(json.loads(output.getvalue()),FIXTURE["expectedCatalog"])
        with patch.object(nv.getpass,"getpass",return_value=FIXTURE["password"]),contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(nv.main(["--text",FIXTURE["protected"],"--ask-password"]),0)
        self.assertEqual(json.loads(output.getvalue()),FIXTURE["expectedProfile"])

    def test_cli_failure_preserves_existing_output_and_redacts_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);out=root/"out.json";out.write_text("keep previous result")
            error=io.StringIO()
            with contextlib.redirect_stderr(error):
                self.assertEqual(nv.main(["--text",FIXTURE["protected"],"-o",str(out)]),1)
            self.assertEqual(json.loads(error.getvalue())["error"],"PASSWORD_REQUIRED")
            self.assertNotIn(FIXTURE["password"],error.getvalue())
            self.assertEqual(out.read_text(),"keep previous result")
            pw=root/"password.txt";pw.write_bytes(b"\xff")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(nv.main(["--text",FIXTURE["protected"],"--password-file",str(pw)]),1)
                self.assertEqual(nv.main([str(root/"missing.nvpnc")]),2)


if __name__ == "__main__":
    unittest.main()
