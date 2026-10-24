"""Password mode, complete independent JDK fields, recipient limits and worker."""
from __future__ import annotations
import base64
import copy
import http.client
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from decoders.Python import npvs
from tests.golden.npvs_protected_generate import make,url
from scripts.apk_analysis.npvs_verify import jdk,document,embedded

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"cloud/workers/python"))
from engine import decode_file,DecodeFailure,_unsupported_npvs_protection


def resign(data,key):
    return data[:-64]+DSS.new(key,"deterministic-rfc6979",encoding="binary").sign(SHA256.new(data[:-64]))


class ProtectedNpvsTests(unittest.TestCase):
    def test_password_and_complete_embedded_document_keep_all_values(self):
        for password in ("synthetic-password","contraseña-日本語-😀"):
            v=make(password=password)
            self.assertEqual(npvs.decode_npvs(v["data"],password=password),v["expectedRaw"])
            expected=copy.deepcopy(v["expectedRaw"])
            expected["document"]["configs"][0]["sshConfig"]["username"]="usuario 日本語"
            self.assertEqual(json.loads(npvs.run(v["data"],password=password)),expected)
            self.assertFalse(_unsupported_npvs_protection(v["data"]))
            for supplied,code in ((None,"PASSWORD_REQUIRED"),("incorrect","AUTH_FAILED")):
                with self.assertRaises(npvs.DecodeError) as ctx:npvs.decode_npvs(v["data"],password=supplied)
                self.assertEqual(ctx.exception.code,code)

    def test_recipient_public_key_match_is_not_a_private_key_or_password(self):
        wrong=url(ECC.construct(curve="P-256",d=42).public_key().export_key(format="SEC1",compress=True))
        for version in (5,6):
            v=make(recipient=True,version=version)
            info=npvs.inspect_npvs(v["data"])
            self.assertEqual((info["version"],info["mode"],len(info["recipients"])),(version,0,1))
            self.assertFalse(_unsupported_npvs_protection(v["data"]))
            for key,code in ((None,"PRIVATE_KEY_REQUIRED"),(v["publicKey"],"PRIVATE_KEY_REQUIRED"),
                             (wrong,"RECIPIENT_MISMATCH"),("not-a-key","INVALID_CREDENTIALS")):
                with self.assertRaises(npvs.DecodeError) as ctx:npvs.decode_npvs(v["data"],public_key=key)
                self.assertEqual(ctx.exception.code,code)

    def test_signature_authentication_and_framing_fail_before_any_success(self):
        v=make();raw=v["data"];hlen=int.from_bytes(raw[5:9],"big")
        for n in range(len(raw)):
            with self.assertRaises(npvs.DecodeError):npvs.decode_npvs(raw[:n],password=v["password"])
        for pos in (9+53+4,9+53+20,9+hlen-2,9+hlen,9+hlen+16+80,-1):
            bad=bytearray(raw);bad[pos]^=1
            with self.assertRaises(npvs.DecodeError) as ctx:npvs.decode_npvs(bytes(bad))
            self.assertNotEqual(ctx.exception.code,"PASSWORD_REQUIRED")
            if pos>=0:
                with self.assertRaises(npvs.DecodeError):npvs.decode_npvs(resign(bytes(bad),v["creator"]),password=v["password"])
        for iterations in (1,599999,10000001):
            bad=bytearray(raw);bad[62:66]=iterations.to_bytes(4,"big")
            with self.assertRaises(npvs.DecodeError):npvs.decode_npvs(resign(bytes(bad),v["creator"]),password=v["password"])
        with self.assertRaises(npvs.DecodeError):npvs.decode_npvs(raw+b"extra",password=v["password"])

    def test_cli_outside_repo_and_isolated_worker_credentials(self):
        # Max-size escaped JSON must fit stdin without truncating a valid password.
        for password in ("synthetic-password","\0"*4096):
            v=make(password=password)
            expected=npvs.decode_npvs_complete(v["data"],password=password)
            with tempfile.TemporaryDirectory() as folder:
                path=Path(folder)/"synthetic.npvs";path.write_bytes(v["data"])
                env={k:v for k,v in os.environ.items() if k!="PYTHONPATH"}
                p=subprocess.run([sys.executable,str(ROOT/"decoders/Python/npvs.py"),str(path),"--credentials-stdin"],
                    input=json.dumps({"password":password}).encode(),capture_output=True,cwd=folder,env=env,timeout=10)
                self.assertEqual(p.returncode,0,p.stderr.decode());self.assertEqual(json.loads(p.stdout),expected)
            output=decode_file("npvs",v["data"],credentials={"password":password})
            self.assertEqual(output["structuredJson"],expected);self.assertEqual(json.loads(output["rawText"]),expected);self.assertFalse(output["isPartial"])
        for creds,code in ((None,"PASSWORD_REQUIRED"),({"password":"incorrect"},"AUTH_FAILED"),({"hwid":"unsupported"},"CREDENTIALS_NOT_ALLOWED")):
            with self.assertRaises(DecodeFailure) as ctx:decode_file("npvs",v["data"],credentials=creds)
            self.assertEqual(ctx.exception.code,code)
        v=make(recipient=True,version=6)
        with self.assertRaises(DecodeFailure) as ctx:decode_file("npvs",v["data"],credentials={"publicKey":v["publicKey"]})
        self.assertEqual(ctx.exception.code,"PRIVATE_KEY_REQUIRED")

    def test_authenticated_local_http_worker_password_and_recipient_errors(self):
        from server import WorkerHandler,ThreadingHTTPServer
        token="synthetic-npv-worker-token-"*3
        with patch.dict(os.environ,{"CLOUD_WORKER_TOKEN":token}):
            server=ThreadingHTTPServer(("127.0.0.1",0),WorkerHandler)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                v=make();recipient=make(recipient=True,version=6)
                for fixture,creds,status,code in ((v,{"password":v["password"]},200,None),(v,{},422,"PASSWORD_REQUIRED"),
                    (v,{"password":"incorrect"},422,"AUTH_FAILED"),(recipient,{"publicKey":recipient["publicKey"]},422,"PRIVATE_KEY_REQUIRED")):
                    body={"format":"npvs","dataBase64":base64.b64encode(fixture["data"]).decode(),"credentials":creds}
                    c=http.client.HTTPConnection(*server.server_address,timeout=10)
                    c.request("POST","/internal/v1/decode/file",json.dumps(body),{"X-SP-Worker-Token":token})
                    r=c.getresponse();out=json.loads(r.read());c.close();self.assertEqual(r.status,status)
                    if code:self.assertEqual(out,{"error":{"code":code}})
                    else:self.assertEqual(out["structuredJson"],npvs.decode_npvs_complete(v["data"],password=v["password"]));self.assertFalse(out["isPartial"])
            finally:server.shutdown();server.server_close();thread.join(timeout=2)

    @unittest.skipUnless(shutil.which("java"),"JDK unavailable")
    def test_jdk_complete_metadata_inventory_and_every_scalar(self):
        vectors=[make(),make(password="contraseña-日本語-😀"),make(recipient=True,version=6)]
        references=jdk([(v["data"],v["password"]) for v in vectors])
        for v,reference in zip(vectors,references):
            if v["publicKey"]:self.assertEqual(reference,{"status":"PRIVATE_KEY_REQUIRED","signatureValid":True})
            else:
                self.assertEqual(document(reference,v["data"]),v["expectedRaw"])
                self.assertEqual(embedded(document(reference,v["data"])),npvs.decode_npvs_complete(v["data"],password=v["password"]))


if __name__=="__main__":unittest.main()
