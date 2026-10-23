"""Synthetic JDK fixtures and real isolated worker contract for AboWaged 1.0."""
from __future__ import annotations
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from decoders.Python.apps.AboWaged_VPN import codec, file_decoder, server_catalog_decoder as catalogs

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"cloud/workers/python"))
FIXTURE=json.loads((ROOT/"tests/golden/abowaged_vectors.json").read_text())


class AboWagedTests(unittest.TestCase):
    def test_independent_jdk_cbc_and_cfb_vectors(self):
        for v in FIXTURE["primitives"]:
            with self.subTest(method=v["method"],length=len(v["plain"])):
                method=codec.decrypt_j if v["method"]=="J" else codec.decrypt_f
                self.assertEqual(method(v["cipher"]),v["plain"])

    def test_normal_and_custom_password_profiles_need_no_external_password(self):
        for v in FIXTURE["files"]:
            actual=json.loads(file_decoder.run(v["cipher"].encode()))
            self.assertEqual(actual,v["expected"])
            self.assertEqual(actual["isPassON"],v["name"]=="locked")
            self.assertIsInstance(actual["Server"],str)
            self.assertEqual(json.loads(actual["Server"])["SSHHost"],"synthetic SSHHost é\n")

    def test_complete_catalog_and_unknown_fields(self):
        v=FIXTURE["catalog"]
        actual=codec.decode_catalog(v["cipher"].encode())
        self.assertEqual(actual,v["expected"])
        self.assertEqual(actual["unknown"]["Payload"],"ordinary Base64: YWJjZA==")
        self.assertEqual(actual["Servers"][0]["unknown"]["Password"],"untouched")
        self.assertIsNone(actual["Servers"][0]["WebPass"])

    def test_complete_udp_with_utf16_surrogate_pair(self):
        v=FIXTURE["udp"]
        self.assertEqual(codec.decode_udp(v["cipher"].encode()),v["expected"])
        self.assertEqual(codec._decimal_chars("65,-1,"),"A\uffff")
        for invalid in ("",",", "1,,2", " 65", "2147483648", "65,x"):
            with self.assertRaises(ValueError):codec._decimal_chars(invalid)

    def test_both_sources_are_required_in_bundle(self):
        a=FIXTURE["catalog"]["cipher"].encode();b=FIXTURE["udp"]["cipher"].encode()
        packed=catalogs.pack_catalogs(a,b)
        expected={"provider":"abowaged-vpn","complete":True,"catalogs":{
            "servers":FIXTURE["catalog"]["expected"],"udp":FIXTURE["udp"]["expected"]}}
        self.assertEqual(json.loads(catalogs.run(packed)),expected)
        bundle=json.loads(packed);del bundle["catalogs"]["udp"]
        with self.assertRaises(ValueError):catalogs.run(json.dumps(bundle).encode())
        bundle=json.loads(packed);bundle["catalogs"]["udp"]="not base64"
        with self.assertRaises(ValueError):catalogs.run(json.dumps(bundle).encode())

    def test_ciphers_and_schemas_are_not_interchangeable(self):
        with self.assertRaises(ValueError):codec.decode_file(FIXTURE["catalog"]["cipher"].encode())
        with self.assertRaises(ValueError):codec.decode_catalog(FIXTURE["files"][0]["cipher"].encode())
        with self.assertRaises(ValueError):codec.decode_udp(b'[{"Servers":[]}]')
        for method in (codec.decrypt_j,codec.decrypt_f):
            with self.assertRaises(ValueError):method("YWJjZA==!")
        with self.assertRaises(ValueError):codec._fields({"Password":True},{"Password"},codec.decrypt_j)

    def test_input_json_and_output_limits(self):
        for data in (b"",b"<html>error</html>",b"https://attacker.invalid/",b"A"*(codec.MAX_BYTES+1)):
            with self.assertRaises(ValueError):codec.decode_catalog(data)
        for data in ('{"x":1,"x":2}','{"x":NaN}','{"x":1e999}','{"x":"\\ud800"}','['*70+'0'+']'*70):
            with self.assertRaises(ValueError):codec._json(data)
        with self.assertRaises(ValueError):codec.render("x"*(codec.MAX_BYTES+1))

    def test_cli_from_another_directory_and_stdin(self):
        script=ROOT/"decoders/Python/apps/AboWaged_VPN/file_decoder.py"
        v=FIXTURE["files"][1]
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/"synthetic.awg";p.write_text(v["cipher"])
            for argv,incoming in (([str(p)],None),(["-"],v["cipher"].encode())):
                result=subprocess.run([sys.executable,str(script),*argv],input=incoming,
                                      cwd=folder,capture_output=True,timeout=20)
                self.assertEqual(result.returncode,0)
                self.assertEqual(result.stderr,b"")
                self.assertEqual(json.loads(result.stdout),v["expected"])

    def test_isolated_workers_and_http_handler_preserve_complete_documents(self):
        from cloud.workers.python import engine,server
        from types import SimpleNamespace
        import io
        v=FIXTURE["files"][1]
        actual=engine.decode_file("awg",v["cipher"].encode())
        self.assertEqual(actual["structuredJson"],v["expected"])
        self.assertFalse(actual["isPartial"])
        bundle=catalogs.pack_catalogs(FIXTURE["catalog"]["cipher"].encode(),FIXTURE["udp"]["cipher"].encode())
        body=json.dumps({"providerId":"abowaged-vpn","dataBase64":base64.b64encode(bundle).decode()}).encode()
        replies=[]
        fake=SimpleNamespace(path="/internal/v1/decode/import/server-vpn",headers={"Content-Length":str(len(body))},
                             rfile=io.BytesIO(body),_authorized=lambda:True,
                             _json=lambda status,body:replies.append((status,body)))
        server.WorkerHandler.do_POST(fake)
        self.assertEqual(replies[0][0],200)
        actual=replies[0][1]
        self.assertEqual(actual["structuredJson"],json.loads(catalogs.run(bundle)))
        self.assertEqual(json.loads(actual["rawText"]),actual["structuredJson"])
        self.assertFalse(actual["isPartial"])

    def test_bot_extension_has_a_dedicated_source(self):
        from spdecode.registry import get_decoder,get_supported_extension
        self.assertEqual(get_supported_extension("EXAMPLE.AWG"),"awg")
        self.assertTrue(get_decoder("awg").script.endswith("apps/AboWaged_VPN/file_decoder.py"))


if __name__=="__main__":unittest.main()
