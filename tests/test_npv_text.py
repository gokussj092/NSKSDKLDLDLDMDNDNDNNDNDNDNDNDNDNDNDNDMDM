"""Standalone requested NPV schemes; no live Cloud/bot/Android registration."""
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from decoders.Python.apps.NPV_Tunnel import text_decoder as text
from tests.golden.npvs_protected_generate import make
from scripts.android_npvs_fixture_export import export

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/"decoders/Python/apps/NPV_Tunnel/text_decoder.py"


def link(prefix,data,urlsafe=True,padding=False):
    token=(base64.urlsafe_b64encode if urlsafe else base64.b64encode)(data).decode()
    return prefix+(token if padding else token.rstrip("="))


def encoded(value):
    return "npvs1:"+base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")


class NpvTextTests(unittest.TestCase):
    def test_requested_prefixes_complete_json_unicode_null_lists_and_embedded_values(self):
        obj={"sshHost":encoded("example.invalid"),"sshPort":443,"sshUsername":encoded(encoded("日本語")),
            "sshPassword":"dGVzdA==","payload":encoded("GET / HTTP/1.1\r\n\r\n"),
            "extra":encoded(json.dumps({"active":True,"comment":encoded("é😀")})),
            "unknown":[None,False,0,"",{"x":"z"}]}
        expected=copy.deepcopy(obj);expected.update(sshHost="example.invalid",sshUsername="日本語",payload="GET / HTTP/1.1\r\n\r\n",extra={"active":True,"comment":"é😀"})
        raw=json.dumps(obj,ensure_ascii=False).encode()
        for prefix in text.PREFIXES:
            with self.subTest(prefix=prefix):
                for urlsafe in (True,False):
                    for padding in (True,False):
                        value=link(prefix.upper(),raw,urlsafe,padding)
                        self.assertEqual(text.identify(value),prefix)
                        self.assertEqual(text.decode(value),expected)
                        self.assertEqual(json.loads(text.run(value.encode())),expected)
        bundle=[obj,obj,{"extension":"preserved"}]
        self.assertEqual(text.decode(link("npvt://",json.dumps(bundle).encode())),[expected,expected,{"extension":"preserved"}])

    def test_bad_payloads_never_become_partial_success_or_guess_a_cipher(self):
        for value in ("other://abc","npvt://","npvt:// \n", "npvt-ssh://x"):
            if text.identify(value) is None:self.assertIsNone(text.decode_text(value))
        for raw in (b"NPVT1,unknown,opaque",b"vless://not-a-verified-npv-payload",b"random utf8",b"{",b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":"\xff"}'):
            with self.subTest(raw=raw),self.assertRaises(text.DecodeError):text.decode(link("npv://",raw))
        for value in ("npvt://!","npvt://AAAA==", "npvt://AB", "npvt://AA#ignored", "npvt://"+"A"*(text.MAX_TEXT_CHARS+1)):
            with self.assertRaises(text.DecodeError):text.decode(value)
        for obj in ({"x":"npvs1:!"},{"x":"npvs1:/w=="},{"x":"\ud800"}):
            with self.assertRaises(text.DecodeError):text.decode_text(link("npvt://",json.dumps(obj).encode()))
        with self.assertRaises(text.DecodeError) as ctx:text.decode(link("npvt://",b"{}"),password="unused")
        self.assertEqual(ctx.exception.code,"CREDENTIALS_NOT_ALLOWED")

    def test_npvs_transport_reuses_complete_appkey_and_password_authentication(self):
        with tempfile.TemporaryDirectory() as folder:
            export(Path(folder))
            raw=(Path(folder)/"npvs-v5-appkey-embedded.npvs").read_bytes()
            expected=json.loads((Path(folder)/"npvs-v5-appkey-embedded.json").read_text())
            for prefix in text.PREFIXES:self.assertEqual(text.decode(link(prefix,raw)),expected)
        v=make()
        for prefix in text.PREFIXES:
            value=link(prefix,v["data"])
            expected=copy.deepcopy(v["expectedRaw"]);expected["document"]["configs"][0]["sshConfig"]["username"]="usuario 日本語"
            self.assertEqual(text.decode(value,password=v["password"]),expected)
            for password,code in ((None,"PASSWORD_REQUIRED"),("incorrect","AUTH_FAILED")):
                with self.assertRaises(text.DecodeError) as ctx:text.decode(value,password=password)
                self.assertEqual(ctx.exception.code,code)
            bad=bytearray(v["data"]);bad[-1]^=1
            with self.assertRaises(text.DecodeError) as ctx:text.decode(link(prefix,bytes(bad)))
            self.assertEqual(ctx.exception.code,"DECODE_FAILED")

    def test_recipient_transport_keeps_the_existing_honest_diagnostic(self):
        for version in (5,6):
            v=make(version=version,recipient=True)
            for prefix in text.PREFIXES:
                with self.assertRaises(text.DecodeError) as ctx:text.decode(link(prefix,v["data"]),public_key=v["publicKey"])
                self.assertEqual(ctx.exception.code,"PRIVATE_KEY_REQUIRED")

    def test_single_script_cli_stdlib_only_and_optional_sibling_codec(self):
        env={k:v for k,v in os.environ.items() if k!="PYTHONPATH"}
        with tempfile.TemporaryDirectory() as folder:
            script=Path(folder)/"text_decoder.py";shutil.copyfile(SOURCE,script)
            wire=link("npvt-ssh://",json.dumps({"sshHost":encoded("example.invalid"),"sshPort":22}).encode())
            # -S excludes site-packages: JSON/npvs1 genuinely needs only stdlib.
            p=subprocess.run([sys.executable,"-S",str(script)],input=wire.encode(),cwd=folder,env=env,capture_output=True,timeout=10)
            self.assertEqual(p.returncode,0,p.stderr.decode());self.assertEqual(json.loads(p.stdout),{"sshHost":"example.invalid","sshPort":22})
            v=make();source=Path(folder)/"link.txt";source.write_text(link("npvt://",v["data"]))
            args=[sys.executable,str(script),str(source),"--credentials-stdin"]
            p=subprocess.run(args,input=json.dumps({"password":v["password"]}).encode(),cwd=folder,env=env,capture_output=True,timeout=10)
            self.assertEqual(p.returncode,1);self.assertEqual(p.stderr,b"ENGINE_UNAVAILABLE\n");self.assertFalse(p.stdout)
            shutil.copyfile(ROOT/"decoders/Python/npvs.py",Path(folder)/"npvs.py")
            p=subprocess.run(args,input=json.dumps({"password":v["password"]}).encode(),cwd=folder,env=env,capture_output=True,timeout=10)
            self.assertEqual(p.returncode,0,p.stderr.decode());self.assertEqual(json.loads(p.stdout)["document"]["configs"][0]["sshConfig"]["username"],"usuario 日本語")
            p=subprocess.run(args,input=b'{"password":"private-wrong-password"}',cwd=folder,env=env,capture_output=True,timeout=10)
            self.assertEqual(p.returncode,1);self.assertFalse(p.stdout);self.assertEqual(p.stderr,b"AUTH_FAILED\n")


if __name__=="__main__":unittest.main()
