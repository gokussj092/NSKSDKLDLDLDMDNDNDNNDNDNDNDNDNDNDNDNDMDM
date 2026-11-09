"""Tunneltweak 6.2.1: APK Java parity, protected files and complete catalogs."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad
from decoders.Python.apps.Tunneltweak import codec, file_decoder as files, server_catalog_decoder as catalog, network

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "decoders/Python/apps/Tunneltweak"
V = json.loads((ROOT / "tests/golden/tunneltweak_vectors.json").read_text())


def cbc(text):
    iv = bytes(range(16))
    return base64.b64encode(iv + AES.new(codec.FILE_KEY, AES.MODE_CBC, iv).encrypt(pad(text.encode(), 16)))


def catalog_gcm(text, *, salt=bytes(range(16))):
    nonce = bytes(range(12))
    key = hashlib.pbkdf2_hmac("sha256", codec.CATALOG_PASSWORD.encode(), salt, 10000, 32)
    sealed, tag = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(text.encode())
    return base64.b64encode(salt + nonce + sealed + tag)


class TunneltweakTests(unittest.TestCase):
    def test_three_file_variants_preserve_every_field_and_type(self):
        for key in ("profileCbc", "profileXor", "profilePbe"):
            result = files.run(V[key].encode(), password=V["testPassword"])
            self.assertEqual(json.loads(result), V["profile"])
            self.assertIn('"hwid_list"', result)
            self.assertEqual(json.loads(result)["config_expiry"], 123456789)

    def test_pbe_requires_password_and_authenticates_every_component(self):
        with self.assertRaises(codec.PasswordRequired):
            files.run(V["profilePbe"].encode())
        raw = bytearray(base64.b64decode(V["profilePbe"][7:]))
        for pos in (0, 16, 28, len(raw)-1):
            changed = raw.copy(); changed[pos] ^= 1
            with self.assertRaises(codec.AuthFailed):
                files.run(b"TTPBE1:"+base64.b64encode(changed), password=V["testPassword"])
        with self.assertRaises(codec.AuthFailed) as error:
            files.run(V["profilePbe"].encode(), password="private-wrong-password")
        self.assertNotIn("private-wrong-password", str(error.exception))

    def test_public_keyed_plain_and_legacy_catalogs_keep_all_profiles(self):
        for data in (V["catalogGcm"].encode(), V["catalogLegacy"].encode(), json.dumps(V["catalog"]).encode()):
            self.assertEqual(json.loads(catalog.run(data)), V["catalog"])
        self.assertEqual(json.loads(catalog.run(V["catalogKeyed"].encode(), api_key=V["testPassword"])), V["catalog"])
        with self.assertRaises(codec.DecodeError):
            catalog.run(V["catalogKeyed"].encode())
        # Original app tries the provided subscription key, then the public key.
        self.assertEqual(json.loads(catalog.run(V["catalogGcm"].encode(), api_key="wrong-test-key")), V["catalog"])

    def test_outer_metadata_hidden_servers_and_unknown_fields_survive(self):
        self.assertEqual(json.loads(catalog.run(json.dumps(V["wrapper"]).encode())), V["expectedWrapper"])
        self.assertFalse(V["expectedWrapper"]["data"]["servers"][0]["visible"])
        obj = dict(V["wrapper"], data=json.dumps(V["catalog"]))
        self.assertEqual(json.loads(catalog.run(json.dumps(obj).encode())), V["expectedWrapper"])

    def test_random_gcm_salt_can_begin_with_json_brace(self):
        data = catalog_gcm(json.dumps(V["catalog"]), salt=b"{" + bytes(range(15)))
        self.assertEqual(json.loads(catalog.run(data)), V["catalog"])

    def test_catalog_authentication_and_malformed_known_structures_fail_closed(self):
        raw = bytearray(base64.b64decode(V["catalogGcm"]))
        for pos in (0, 16, 28, len(raw)-1):
            b = raw.copy(); b[pos] ^= 1
            with self.assertRaises(codec.DecodeError): catalog.run(base64.b64encode(b))
        for obj in ({"data": True}, {"data": "fake-private-input"}, {"servers": {}, "configs": {}},
                    {"servers": [], "configs": {}}, {"servers": [None], "configs": {}},
                    {"servers": [], "configs": {"bad": []}}):
            with self.assertRaises(codec.DecodeError) as error:
                catalog.run(json.dumps(obj).encode())
            self.assertNotIn("fake-private-input", str(error.exception))

    def test_invalid_versions_padding_and_base64_are_rejected(self):
        for version in (True, "6", 5, 7, None):
            with self.assertRaises(codec.DecodeError):
                files.run(cbc(json.dumps(dict(V["profile"], config_version=version))))
        for raw in (b"bad", b"", b"TTPBE1:YWJj", b"<html/>", V["profileCbc"].encode()[:-12]):
            with self.assertRaises(codec.DecodeError): files.run(raw)

    def test_duplicate_nonfinite_surrogate_and_deep_json_are_rejected(self):
        texts = ['{"config_version":6,"config_version":6}', '{"config_version":6,"n":NaN}',
                 '{"config_version":6,"n":1e999}', '{"config_version":6,"s":"\\ud800"}']
        deep = {"config_version": 6, "value": 0}
        for _ in range(66): deep["value"] = [deep["value"]]
        texts.append(json.dumps(deep))
        for text in texts:
            with self.assertRaises(codec.DecodeError): files.run(cbc(text))
        for text in ('{"servers":[],"servers":[],"configs":{}}', '{"servers":[],"configs":{"x":{}},"n":NaN}'):
            with self.assertRaises(codec.DecodeError): catalog.run(catalog_gcm(text))

    def test_input_output_limits(self):
        for run, limit in ((files.run, codec.MAX_FILE_BYTES), (catalog.run, codec.MAX_BYTES)):
            for raw in (b"", b"x" * (limit+1)):
                with self.assertRaises(codec.DecodeError): run(raw)
        with self.assertRaises(codec.DecodeError): codec.render({"x": "x" * codec.MAX_BYTES})

    def test_cloud_response_preserves_metadata_and_uses_same_file_cipher(self):
        obj = {"config": V["profileCbc"], "expiresAt": "test", "unknown": [False, 0, None]}
        self.assertEqual(json.loads(files.decode_cloud_response(json.dumps(obj).encode())), dict(obj, config=V["profile"]))
        for obj in ({"config": False}, {"unknown": "test"}):
            with self.assertRaises(codec.DecodeError): files.decode_cloud_response(json.dumps(obj).encode())

    def test_fixed_download_urls_headers_subscription_and_uuid(self):
        class Response:
            status = 200
            headers = {}
            data = json.dumps(V["wrapper"]).encode()
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size): return self.data[:size]
        seen = []
        class Opener:
            def open(self, request, timeout):
                self_timeout = timeout
                assert self_timeout == 25
                seen.append(request)
                return Response()
        uuid = "00000000-0000-4000-8000-000000000001"
        with patch.object(network, "build_opener", return_value=Opener()):
            network.download(); network.download(api_key="test-key"); network.download(cloud_id=uuid)
            self.assertEqual([r.full_url for r in seen], [network.CATALOG_URL, network.CATALOG_URL, network.CLOUD_BASE_URL+uuid])
            self.assertEqual(seen[0].get_header("X-app-version"), "53")
            self.assertEqual(seen[0].get_header("X-cfg-keyed"), "1")
            self.assertIsNone(seen[0].get_header("X-api-key"))
            self.assertEqual(seen[1].get_header("X-api-key"), "test-key")
            self.assertIsNone(seen[2].get_header("X-api-key"))
            for value in ("../private", "https://example.invalid/", uuid+"?a=b", "", "x\nheader"):
                with self.assertRaises(codec.DecodeError): network.download(cloud_id=value)
            for data in (b"", b"<html/>", b"x" * (codec.MAX_BYTES+1)):
                with patch.object(Response, "data", data), self.assertRaises(codec.DecodeError): network.download()
            with patch.object(Response, "headers", {"Content-Encoding": "gzip"}), self.assertRaises(codec.DecodeError): network.download()
            with self.assertRaises(codec.DecodeError): network.download(api_key="x\r\nInjected: yes")
        with self.assertRaises(codec.DecodeError): network._NoRedirect().redirect_request(None)

    def test_actual_worker_password_challenge_errors_and_complete_catalog(self):
        from cloud.workers.python import engine
        for key in ("profileCbc", "profileXor"):
            result = engine.decode_file("tut", V[key].encode())
            self.assertEqual(result["structuredJson"], V["profile"])
            self.assertFalse(result["isPartial"])
        for creds, code in ((None, "PASSWORD_REQUIRED"), ({"password": "wrong"}, "AUTH_FAILED"), ({"hwid": "x"}, "CREDENTIALS_NOT_ALLOWED")):
            with self.assertRaises(engine.DecodeFailure) as error:
                engine.decode_file("tut", V["profilePbe"].encode(), credentials=creds)
            self.assertEqual(error.exception.code, code)
        result = engine.decode_file("tut", V["profilePbe"].encode(), credentials={"password": V["testPassword"]})
        self.assertEqual(result["structuredJson"], V["profile"])
        result = engine.decode_provider_catalog("tunneltweak", json.dumps(V["wrapper"]).encode())
        self.assertEqual(result["structuredJson"], V["expectedWrapper"])
        self.assertFalse(result["isPartial"])

    def test_worker_never_tries_legacy_on_failed_pbe_tag(self):
        from decoders.Python.apps.Tunneltweak import worker_bridge
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"input.tut"; path.write_text(V["profilePbe"])
            import io
            stdin = io.TextIOWrapper(io.BytesIO(json.dumps({"password":"wrong"}).encode()))
            stdout = io.StringIO()
            with patch.object(sys, "argv", ["worker_bridge.py", str(path)]), patch.object(sys,"stdin",stdin), patch.object(sys,"stdout",stdout), patch.object(worker_bridge.generic_des,"run",side_effect=AssertionError("fallback")):
                code = worker_bridge.main()
            self.assertEqual(code,3)
            self.assertEqual(json.loads(stdout.getvalue()), {"workerError":"AUTH_FAILED"})

    def test_historical_generic_tut_output_is_byte_identical(self):
        from cloud.workers.python import engine
        # Independently generate both pre-existing generic formats. These have
        # no dedicated .tut vector in the frozen sixty-case C0 golden corpus.
        xml = b'<properties><entry key="server">test.example</entry></properties>'
        xml += b" " * (-len(xml) % 8)
        des = DES.new(b"fubvx788", DES.MODE_ECB).encrypt(xml)
        salt, nonce = bytes(range(16)), bytes(range(16, 32))
        key = hashlib.pbkdf2_hmac("sha256", b"fubvx788b46v", salt, 1000, 16)
        sealed, tag = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(xml)
        old_gcm = b".".join(base64.b64encode(x) for x in (salt, nonce, sealed+tag))
        samples = [des, base64.b64encode(des), base64.encodebytes(des), old_gcm]
        for data in samples:
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder)/"input.tut"; path.write_bytes(data)
                original = subprocess.run([sys.executable, engine.load_file_engines()["tut"]["source"], str(path)],capture_output=True,timeout=10)
            self.assertEqual(original.returncode, 0)
            self.assertEqual(engine.decode_file("tut",data)["rawText"].encode(),original.stdout)

    def test_cli_from_outside_repo_with_password_file_and_stdin(self):
        env={k:v for k,v in os.environ.items() if k!="PYTHONPATH"}
        with tempfile.TemporaryDirectory() as folder:
            secret=Path(folder)/"password.txt";secret.write_text(V["testPassword"]+"\n")
            for script,data,args,expected in (
                ("file_decoder.py",V["profileCbc"].encode(),[],V["profile"]),
                ("file_decoder.py",V["profilePbe"].encode(),["--password-file",str(secret)],V["profile"]),
                ("server_catalog_decoder.py",json.dumps(V["wrapper"]).encode(),["--stdin"],V["expectedWrapper"])):
                result=subprocess.run([sys.executable,str(APP/script),*args],input=data,cwd="/tmp",env=env,capture_output=True,timeout=15)
                self.assertEqual(result.returncode,0,result.stderr.decode())
                self.assertEqual(json.loads(result.stdout),expected)
            result=subprocess.run([sys.executable,str(APP/"file_decoder.py")],input=b"fake-private-input",cwd="/tmp",env=env,capture_output=True,timeout=10)
            self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b"");self.assertNotIn(b"fake-private-input",result.stderr)

    @unittest.skipUnless(shutil.which("java"), "Java source launcher not installed")
    def test_original_apk_java_crypto_methods_match_whole_documents(self):
        pairs=[("file-cbc",V["profileCbc"]),("file-pbe",V["profilePbe"]),("file-xor",V["profileXor"]),
               ("catalog",V["catalogGcm"]),("catalog-keyed",V["catalogKeyed"]),("catalog-legacy",V["catalogLegacy"])]
        text="".join(k+"\t"+base64.b64encode(v.encode()).decode()+"\t"+base64.b64encode(V["testPassword"].encode()).decode()+"\n" for k,v in pairs)
        result=subprocess.run(["java",str(ROOT/"tests/golden/tunneltweak_oracle.java")],input=text,text=True,capture_output=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual([json.loads(base64.b64decode(v)) for v in result.stdout.splitlines()],[V["profile"]]*3+[V["catalog"]]*3)

    def test_original_icon_is_exact_in_both_locations(self):
        raw=(APP/"Tunneltweak.png").read_bytes()
        self.assertEqual(raw,(ROOT/"cloud/web/public/server-vpn-icons/tunneltweak.png").read_bytes())
        self.assertEqual(hashlib.sha256(raw).hexdigest(),"e7eec681345d4fcbefd699857d2e456d42d7cd6568488d64d578b9d489263a72")


if __name__ == "__main__":
    unittest.main()
