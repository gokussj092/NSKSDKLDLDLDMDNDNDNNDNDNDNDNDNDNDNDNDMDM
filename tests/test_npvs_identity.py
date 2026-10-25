"""Recipient generation, full JCA comparison, file-bound capture and isolation."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from Crypto.PublicKey import ECC
from decoders.Python import npvs, npvs_identity as identities
from tests.golden.npvs_protected_generate import make, url
from tests.test_npvs_protected import resign
from scripts.apk_analysis.npvs_verify import jdk, document

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"cloud/workers/python"))
from engine import decode_file, DecodeFailure


class IdentityTests(unittest.TestCase):
    def test_termux_collector_and_standalone_bundle(self):
        import tempfile,subprocess,zipfile,stat
        from scripts.apk_analysis.npv_termux import collect
        from scripts.apk_analysis.npv_termux_bundle import build
        identity=identities.generate();fixture=make(recipient=True,identity=identity);raw=fixture["data"]
        private={"kind":"private-pkcs8","fileSha256":hashlib.sha256(raw).hexdigest(),
            "fingerprint":identity["fingerprint"],"privateKey":identity["privateKey"]}
        captured=collect(raw,private)
        self.assertEqual(captured,identity|{"source":"captured"})
        with self.assertRaises(ValueError):collect(raw,private|{"fingerprint":"0"*64})
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder);build(path/"one.zip");build(path/"two.zip")
            self.assertEqual((path/"one.zip").read_bytes(),(path/"two.zip").read_bytes())
            with zipfile.ZipFile(path/"one.zip") as archive:archive.extractall(path/"standalone")
            profile=path/"input.npvs";profile.write_bytes(raw)
            material=path/"key.json";material.write_text(json.dumps(identity))
            output=path/"result.json"
            command=[sys.executable,str(path/"standalone/npv_termux.py"),"decode",str(profile),
                "--identity",str(material),"-o",str(output)]
            result=subprocess.run(command,cwd=folder,capture_output=True,timeout=10,
                env={k:v for k,v in os.environ.items() if k!="PYTHONPATH"})
            self.assertEqual(result.returncode,0,result.stderr.decode())
            self.assertEqual(json.loads(output.read_text()),npvs.decode_npvs_complete(raw,recipient_key=identity))
            self.assertEqual(stat.S_IMODE(output.stat().st_mode),0o600)
            self.assertNotEqual(subprocess.run(command,cwd=folder,capture_output=True,timeout=10).returncode,0)

    def test_fresh_keys_and_strict_identity_import(self):
        first,second=identities.generate(),identities.generate()
        self.assertNotEqual(first["publicKey"],second["publicKey"])
        self.assertEqual(identities.normalize(json.dumps(first)),first)
        for updates in ({"publicKey":second["publicKey"]},{"privateKey":second["privateKey"]},
                        {"curve":"P-384"},{"extra":"rejected"},{"fingerprint":"0"*64}):
            with self.assertRaises(ValueError):identities.normalize(first|updates)
        with self.assertRaises(ValueError):identities.normalize(json.dumps(first)[:-1]+',"kind":"keypair"}')

    def test_v5_v6_complete_document_jca_and_worker(self):
        identity=identities.generate()
        for version in (5,6):
            fixture=make(recipient=True,version=version,identity=identity);raw=fixture["data"]
            result=npvs.decode_npvs(raw,recipient_key=identity)
            self.assertEqual(result,fixture["expectedRaw"])
            self.assertEqual(document(jdk([(raw,None)],identity)[0],raw),result)
            output=decode_file("npvs",raw,credentials={"recipientKey":json.dumps(identity)})
            self.assertEqual(output["structuredJson"],npvs.decode_npvs_complete(raw,recipient_key=identity))
            self.assertFalse(output["isPartial"])
            with self.assertRaises(npvs.DecodeError) as error:
                npvs.decode_npvs(raw,recipient_key=identities.generate())
            self.assertEqual(error.exception.code,"RECIPIENT_MISMATCH")

    def test_capture_is_bound_to_exact_file_and_ephemeral_point(self):
        identity=identities.generate();fixture=make(recipient=True,version=6,identity=identity)
        raw=fixture["data"];record=npvs.inspect_npvs(raw)["recipients"][0]
        _,shared=identities.agreement(identity,raw,[record])
        capture={"schema":identities.SCHEMA,"source":"captured","kind":"agreement","curve":"P-256",
            "fingerprint":identity["fingerprint"],"fileSha256":hashlib.sha256(raw).hexdigest(),
            "peer":url(record[32:65]),"sharedSecret":url(shared)}
        self.assertEqual(npvs.decode_npvs(raw,recipient_key=capture),fixture["expectedRaw"])
        for changes,code in (({"fileSha256":"0"*64},"RECIPIENT_MISMATCH"),
                             ({"sharedSecret":url(bytes(range(32)))},"AUTH_FAILED"),
                             ({"peer":identities.generate()["publicKey"]},"RECIPIENT_MISMATCH")):
            with self.assertRaises(npvs.DecodeError) as error:npvs.decode_npvs(raw,recipient_key=capture|changes)
            self.assertEqual(error.exception.code,code)
        with self.assertRaises(npvs.DecodeError):npvs.decode_npvs(make()["data"],recipient_key=capture)

    def test_signature_and_recipient_tag_cannot_be_bypassed(self):
        identity=identities.generate();fixture=make(recipient=True,identity=identity)
        for signed in (False,True):
            raw=bytearray(fixture["data"]);raw[9+53+109]^=1
            raw=resign(bytes(raw),fixture["creator"]) if signed else bytes(raw)
            with self.assertRaises(npvs.DecodeError) as error:npvs.decode_npvs(raw,recipient_key=identity)
            self.assertEqual(error.exception.code,"AUTH_FAILED" if signed else "INVALID_INPUT")

    def test_apk_fingerprint_salt_and_aad_are_not_interchanged_with_config_id(self):
        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import HKDF
        from Crypto.Hash import SHA256
        identity=identities.generate();fixture=make(recipient=True,identity=identity)
        raw=fixture["data"];env=npvs.inspect_npvs(raw);record=env["recipients"][0];cid=env["header"][1:17]
        _,shared=identities.agreement(identity,raw,[record])
        # The former generic recipe used salt=cid/info=label+fp/AAD=cid.
        # It is a valid AES-GCM envelope but is NOT the APK's ah.m.e method.
        key=HKDF(shared,32,cid,SHA256,context=b"NPVS-v1-wrap"+record[:32])
        cipher=AES.new(key,AES.MODE_GCM,nonce=record[65:77]);cipher.update(cid)
        encrypted,tag=cipher.encrypt_and_digest(fixture["dek"])
        wrong=raw[:9+53+77]+encrypted+tag+raw[9+53+125:]
        wrong=resign(wrong,fixture["creator"])
        with self.assertRaises(npvs.DecodeError) as error:npvs.decode_npvs(wrong,recipient_key=identity)
        self.assertEqual(error.exception.code,"AUTH_FAILED")

    def test_worker_identity_route_requires_auth_and_explicit_consent(self):
        import http.client,threading
        from server import WorkerHandler,ThreadingHTTPServer
        token="synthetic-identity-worker-token-"*3
        with patch.dict(os.environ,{"CLOUD_WORKER_TOKEN":token}):
            server=ThreadingHTTPServer(("127.0.0.1",0),WorkerHandler)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                for auth,payload,status in ((False,{"consent":True},403),(True,{},400),(True,{"consent":True},200)):
                    c=http.client.HTTPConnection(*server.server_address,timeout=5)
                    c.request("POST","/internal/v1/npvs/identity",json.dumps(payload),{"X-SP-Worker-Token":token} if auth else {})
                    response=c.getresponse();result=json.loads(response.read());c.close()
                    self.assertEqual(response.status,status)
                    if status==200:self.assertEqual(identities.normalize(result["identity"]),result["identity"])
            finally:server.shutdown();server.server_close();thread.join(timeout=2)


if __name__=="__main__":unittest.main()
