"""Complete JDK documents, authenticated negative cases and actual worker routes."""
import base64
import http.client
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from Crypto.Cipher import AES
from decoders.Python.apps.OneFTunnel import codec
from decoders.Python.apps.OneFTunnel.file_decoder import run

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "decoders/Python/apps/OneFTunnel"
VECTORS = json.loads((ROOT / "tests/golden/oneftunnel_vectors.json").read_text())
sys.path.insert(0, str(ROOT / "cloud/workers/python"))
from engine import decode_file, decode_text, DecodeFailure, load_file_engines, load_runtime_file_engines


def reseal(raw, *, plaintext=None, aad=None):
    raw = codec.unwrap(raw)
    n = struct.unpack_from(">I", raw, 36)[0]
    old_aad = raw[44:44+n]
    key = codec.derive_key(raw[4], raw[8:24], old_aad)
    gcm = AES.new(key, AES.MODE_GCM, nonce=raw[24:36]);gcm.update(old_aad)
    old_plain = gcm.decrypt_and_verify(raw[44+n:-16], raw[-16:])
    aad = old_aad if aad is None else aad
    plaintext = old_plain if plaintext is None else plaintext
    gcm = AES.new(codec.derive_key(raw[4],raw[8:24],aad), AES.MODE_GCM, nonce=raw[24:36]);gcm.update(aad)
    ciphertext, tag = gcm.encrypt_and_digest(plaintext)
    return raw[:36] + struct.pack(">II",len(aad),len(ciphertext)+16) + aad + ciphertext + tag


class OneFTunnelTests(unittest.TestCase):
    def test_complete_jdk_vectors_all_container_payload_versions_and_import_prefixes(self):
        self.assertEqual(len(VECTORS),15)
        for v in VECTORS:
            with self.subTest(v["label"]):
                expected=v["expected"];pw=v["password"] or None;raw=codec.unwrap(v["wire"])
                self.assertEqual(codec.decode(raw,password=pw),expected)
                self.assertEqual(json.loads(run(v["wire"].encode(),password=pw)),expected)
                body=base64.urlsafe_b64encode(raw[4:]).decode()
                for prefix in codec.PREFIXES:
                    self.assertEqual(codec.decode(" \n"+prefix+body.rstrip("=")+"\n",password=pw),expected)
                    self.assertEqual(codec.decode(prefix+body,password=pw),expected)

    def test_tampered_nonce_salt_aad_cipher_tag_and_outer_lengths_fail_closed(self):
        raw=codec.unwrap(VECTORS[0]["wire"])
        n=struct.unpack_from(">I",raw,36)[0]
        for offset in (8,24,44+n-4,44+n,len(raw)-1):
            bad=bytearray(raw);bad[offset]^=1
            with self.subTest(offset=offset),self.assertRaises(codec.DecodeError):codec.decode(bytes(bad))
        cases=[b"",raw[:-1],raw+b"x",b"1FTnl.!",b"1ftnl.AAAA",b"1ftunnel://1FTnl/",b"1FTnl.AAAA=="]
        for offset,value in [(4,9),(5,2),(6,2),(7,1)]:
            bad=bytearray(raw);bad[offset]=value;cases.append(bytes(bad))
        for offset,value in [(36,1025),(36,0xffffffff),(40,15),(40,0xffffffff)]:
            bad=bytearray(raw);struct.pack_into(">I",bad,offset,value);cases.append(bytes(bad))
        cases.extend([b"1FTnl."+b"A"*393217,b"1FT1"+b"\0"*(5*1024*1024)])
        for bad in cases:
            with self.assertRaises(codec.DecodeError):codec.decode(bad)

    def test_authenticated_invalid_cfg_and_policy_consistency_are_rejected(self):
        raw=codec.unwrap(VECTORS[10]["wire"])
        n=struct.unpack_from(">I",raw,36)[0];aad=raw[44:44+n]
        gcm=AES.new(codec.derive_key(raw[4],raw[8:24],aad),AES.MODE_GCM,nonce=raw[24:36]);gcm.update(aad)
        plain=gcm.decrypt_and_verify(raw[44+n:-16],raw[-16:])
        bads=[plain+b"x",plain[:-1],b"BAD!"+plain[4:],plain[:4]+b"\x06"+plain[5:],
              plain[:5]+struct.pack(">i",2097153)+plain[9:],
              plain[:5]+struct.pack(">i",-2)+plain[9:]]
        for bad in bads:
            with self.assertRaises(codec.DecodeError):codec.decode(reseal(raw,plaintext=bad))
        for field,value in [("createdAt",1),("configType",1),("lockMode",3),("blockRoot",2)]:
            bad=bytearray(aad)
            # Version 3 tail: createdAt, expiry, type, lock, blockRoot.
            if field=="createdAt":struct.pack_into(">q",bad,len(bad)-19,value)
            else:bad[{"configType":-3,"lockMode":-2,"blockRoot":-1}[field]]=value
            with self.assertRaises(codec.DecodeError):codec.decode(reseal(raw,aad=bytes(bad)))
        # Identity remains exact even when the envelope has a valid tag.
        with self.assertRaises(codec.DecodeError) as ctx:
            codec.decode(reseal(raw,aad=aad.replace(b"com.oneftunnel.app",b"com.otherfake.appx")))
        self.assertEqual(ctx.exception.code,"UNSUPPORTED_IDENTITY")
        # Strict bools and UTF-8; all input must be consumed.
        r=codec.Reader(plain);r.take(5);r.string();r.string();r.take(8);r.string(nullable=True)
        bad_bool=plain[:r.pos]+b"\x02"+plain[r.pos+1:]
        for bad in [bad_bool,plain[:9]+b"\xff"+plain[10:]]:
            with self.assertRaises(codec.DecodeError):codec.parse_config(bad)

    def test_password_required_wrong_password_and_worker_credentials_are_sanitized(self):
        v=next(v for v in VECTORS if v["password"])
        for pw,code in [(None,"PASSWORD_REQUIRED"),("incorrect","AUTH_FAILED")]:
            with self.assertRaises(codec.DecodeError) as ctx:codec.decode(v["wire"],password=pw)
            self.assertEqual(ctx.exception.code,code)
            for action in (lambda:decode_file("1ftnl",v["wire"].encode(),credentials={"password":pw} if pw else None),
                           lambda:decode_text(v["wire"],credentials={"password":pw} if pw else None)):
                with self.assertRaises(DecodeFailure) as ctx:action()
                self.assertEqual(ctx.exception.code,code)
        with self.assertRaises(DecodeFailure):decode_file("1ftnl",v["wire"].encode(),credentials={"hwid":"not-supported"})
        with self.assertRaises(DecodeFailure):decode_text("tls://unrelated",credentials={"password":v["password"]})

    def test_complete_isolated_file_text_routes_and_bot_registration(self):
        self.assertEqual(len(load_file_engines()),240)
        # Two new audited Cloud-only routes (.awg and .creeb) extend the
        # runtime registry without modifying the frozen 240 C0 file routes.
        routes=load_runtime_file_engines()
        self.assertEqual(len(routes),254)
        self.assertIn("awg",routes)
        self.assertIn("creeb",routes)
        from spdecode.registry import get_decoder,get_supported_extension
        self.assertEqual(get_supported_extension("profile.1FTNL"),"1ftnl")
        self.assertEqual(get_decoder("1ftnl").script,"decoders/Python/apps/OneFTunnel/file_decoder.py")
        for v in (VECTORS[0],VECTORS[2],VECTORS[-1]):
            creds={"password":v["password"]} if v["password"] else None
            for out in (decode_file("1ftnl",v["wire"].encode(),credentials=creds),decode_text(v["wire"],credentials=creds)):
                self.assertEqual(out["structuredJson"],v["expected"])
                self.assertEqual(json.loads(out["rawText"]),v["expected"])
                self.assertFalse(out["isPartial"])

    def test_cli_outside_repo_stdin_password_bridge_and_safe_errors(self):
        env={k:v for k,v in os.environ.items() if k!="PYTHONPATH"}
        with tempfile.TemporaryDirectory() as directory:
            for v in (VECTORS[0],VECTORS[2]):
                path=Path(directory)/"private.1ftnl";path.write_text(v["wire"])
                flags=[str(path),"--password-stdin"] if v["password"] else ["-"]
                incoming=json.dumps({"password":v["password"]}).encode() if v["password"] else v["wire"].encode()
                out=subprocess.run([sys.executable,str(APP/"file_decoder.py"),*flags],input=incoming,cwd=directory,env=env,capture_output=True,timeout=10)
                self.assertEqual(out.returncode,0,out.stderr.decode());self.assertEqual(json.loads(out.stdout),v["expected"])
            out=subprocess.run([sys.executable,str(APP/"worker_bridge.py"),str(path)],input=b'{"password":"incorrect"}',cwd=directory,env=env,capture_output=True,timeout=10)
            self.assertEqual(out.returncode,3);self.assertEqual(json.loads(out.stdout),{"workerError":"AUTH_FAILED"});self.assertFalse(out.stderr)
            path.write_bytes(b"private-invalid-input")
            out=subprocess.run([sys.executable,str(APP/"file_decoder.py"),str(path)],cwd=directory,env=env,capture_output=True,timeout=10)
            self.assertEqual(out.returncode,1);self.assertFalse(out.stdout);self.assertEqual(out.stderr,b"INVALID_FORMAT\n")

    def test_authenticated_http_worker_complete_result(self):
        from server import WorkerHandler,ThreadingHTTPServer
        token="synthetic-worker-token-"*3
        with patch.dict(os.environ,{"CLOUD_WORKER_TOKEN":token}):
            server=ThreadingHTTPServer(("127.0.0.1",0),WorkerHandler)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                for v in (VECTORS[0],VECTORS[2]):
                    for kind in ("file","text"):
                        body={"format":"1ftnl","dataBase64":base64.b64encode(v["wire"].encode()).decode()} if kind=="file" else {"text":v["wire"]}
                        if v["password"]:body["credentials"]={"password":v["password"]}
                        c=http.client.HTTPConnection(*server.server_address,timeout=10)
                        c.request("POST","/internal/v1/decode/"+kind,json.dumps(body),{"X-SP-Worker-Token":token})
                        r=c.getresponse();data=json.loads(r.read());c.close()
                        self.assertEqual(r.status,200);self.assertEqual(data["structuredJson"],v["expected"]);self.assertFalse(data["isPartial"])
            finally:
                server.shutdown();server.server_close();thread.join(timeout=2)

    @unittest.skipUnless(shutil.which("java"),"JDK unavailable")
    def test_jdk_regenerates_all_complete_reference_documents(self):
        out=subprocess.run(["java","-XX:-UsePerfData",str(ROOT/"tests/golden/oneftunnel_oracle.java")],capture_output=True,text=True,timeout=30)
        self.assertEqual(out.returncode,0,out.stderr)
        self.assertEqual(json.loads(out.stdout),VECTORS)


if __name__ == "__main__":unittest.main()
