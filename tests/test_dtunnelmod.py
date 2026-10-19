"""DTunnel Mod: frozen independent Java/JCE vectors; all HTTP is mocked."""
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
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError
from urllib.request import Request

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from decoders.Python import dtunnelmod as dt

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / "tests/golden/dtunnelmod_vectors.json").read_text("utf-8"))
VECTORS = {v["name"]: v for v in FIXTURE["vectors"]}


def encrypted(text):
    # Mutation/limit cases only; positive vectors come from Java/JCE.
    return base64.b64encode(AES.new(dt.CATALOG_KEY, AES.MODE_CBC, bytes(16)).encrypt(pad(text.encode(), 16)))


class DTunnelModTests(unittest.TestCase):
    def assert_error(self, data, code, **kwargs):
        with self.assertRaises(dt.DecodeError) as ctx:
            dt.decode(data, **kwargs)
        self.assertEqual(ctx.exception.code, code)
        self.assertIsNone(dt.run(data, **kwargs))

    def test_independent_jce_vectors_preserve_all_fields(self):
        for vector in FIXTURE["vectors"]:
            with self.subTest(name=vector["name"]):
                expected = FIXTURE[vector["expected"]]
                self.assertEqual(dt.decode_catalog(vector["data"], kind=vector["kind"]), expected)
                self.assertEqual(json.loads(dt.run(vector["data"], kind=vector["kind"])), expected)
        self.assertEqual(dt.decode(VECTORS["catalog"]["data"])[0]["payload"],
                         "GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n")

    def test_link_preserves_original_ids_and_unknown_fields(self):
        expected = FIXTURE["expectedProfiles"][0]
        self.assertEqual(dt.decode_link(FIXTURE["link"]), expected)
        self.assertEqual(dt.decode(FIXTURE["link"].encode()), expected)
        self.assertEqual(expected["id"], 7)
        self.assertEqual(expected["category_id"], 42)
        self.assertEqual(expected["user_id"], "synthetic-owner")
        self.assertEqual(expected["sorter"], 9)

    def test_bom_wrapping_and_missing_base64_padding(self):
        for data in [VECTORS["catalog"]["data"], FIXTURE["link"]]:
            expected = dt.decode(data)
            self.assertEqual(dt.decode("\ufeff \n"+data+"\r\n"), expected)
            self.assertEqual(dt.decode(data.rstrip("=")), expected)
            self.assertEqual(dt.decode("\n".join(data[i:i+64] for i in range(0,len(data),64))), expected)

    def test_empty_catalog_is_valid_but_failures_are_not_empty(self):
        self.assertEqual(dt.decode(VECTORS["empty"]["data"]), [])
        self.assert_error(b"broken", "TRUNCATED")
        with self.assertRaises(dt.DecodeError):
            dt.decrypt_catalog_text(b"!broken!")

    def test_thousand_profiles_no_fixed_catalog_cap(self):
        expected = [{"id":i,"name":f"Synthetic {i}","future":{"keep":True}} for i in range(1000)]
        carrier = json.dumps([json.dumps(p) for p in expected])
        self.assertEqual(dt.decode(encrypted(carrier)), expected)

    def test_invalid_input_transport_and_size(self):
        for data in [None,1,[],b"",b"\xff",b"!bad!",b"vpn://",b"A",b"other://AAAA",b"AAAA===="]:
            self.assertIsNone(dt.run(data))
        with patch.object(dt,"MAX_BYTES",10):
            self.assert_error(b"x"*11,"SIZE_LIMIT")
            self.assert_error("日"*5,"SIZE_LIMIT")
        with self.assertRaises(dt.DecodeError):
            dt.decode_link("wrong://AAAA")

    def test_cbc_block_padding_and_utf8_failures(self):
        raw = base64.b64decode(VECTORS["catalog"]["data"])
        self.assert_error(base64.b64encode(raw[:-1]),"TRUNCATED")
        # Two ciphertext blocks guarantee that a last-byte flip in the
        # penultimate block changes only the final padding byte of the last.
        modified = bytearray(raw)
        modified[-17] ^= 128
        self.assert_error(base64.b64encode(modified),"DECRYPT_FAILED")
        cipher = AES.new(dt.CATALOG_KEY,AES.MODE_CBC,bytes(16)).encrypt(pad(b"\xff",16))
        self.assert_error(base64.b64encode(cipher),"DECRYPT_FAILED")

    def test_strict_json_duplicate_nonfinite_unicode(self):
        for text in ['[{"a":1,"a":2}]','[{"a":NaN}]','[{"a":1e999}]','[{"a":"\\ud800"}]',
                     '["{\\"a\\":1,\\"a\\":2}"]','{broken}']:
            with self.subTest(text=text):
                self.assert_error(encrypted(text),"INVALID_JSON")
        link = "vpn://"+base64.b64encode(b'{"a":1,"a":2}').decode()
        self.assert_error(link,"INVALID_JSON")

    def test_root_and_member_schema_no_partial_results(self):
        for text in ['{}','null','[1]','[[]]','[null]','["[]"]','[{},"bad"]']:
            self.assertIsNone(dt.run(encrypted(text)))
        self.assert_error("vpn://"+base64.b64encode(b'[]').decode(),"WRONG_DOCUMENT")
        self.assertIsNone(dt.run("vpn://"+base64.b64encode(b'\xff').decode()))
        self.assert_error(VECTORS["catalog"]["data"],"FORMAT_ERROR",kind="unknown")

    def test_json_complexity_limits(self):
        with patch.object(dt,"MAX_DEPTH",2):
            self.assert_error(encrypted('[{"a":{"b":{"c":1}}}]'),"SIZE_LIMIT")
        with patch.object(dt,"MAX_NODES",5):
            self.assert_error(encrypted('[{"a":1,"b":2,"c":3}]'),"SIZE_LIMIT")
        self.assertIsNone(dt.run(encrypted("["*1500+"0"+"]"*1500)))

    def test_offline_decode_and_run_never_open_network(self):
        with patch.object(dt,"build_opener",side_effect=AssertionError("unexpected network")):
            self.assertIsNotNone(dt.run(VECTORS["catalog"]["data"]))
            self.assertIsNotNone(dt.run(FIXTURE["link"]))
            self.assertIsNone(dt.run("invalid"))

    def test_explicit_get_headers_and_update_kinds(self):
        for kind, update in dt.UPDATE_KINDS.items():
            opener = MagicMock()
            response = opener.open.return_value.__enter__.return_value
            response.read.return_value = b"synthetic-response"
            with patch.object(dt,"build_opener",return_value=opener) as build:
                self.assertEqual(dt.fetch_catalog(dt.CATALOG_URL,"synthetic-id",kind=kind),b"synthetic-response")
            request = opener.open.call_args.args[0]
            headers = {k.lower():v for k,v in request.header_items()}
            self.assertEqual(headers["dtunnel-token"],"synthetic-id")
            self.assertEqual(headers["dtunnel-update"],update)
            self.assertEqual(headers["user-agent"],dt.USER_AGENT)
            self.assertEqual(request.get_method(),"GET")
            self.assertIsNone(request.data)
            self.assertEqual(opener.open.call_args.kwargs,{"timeout":20})
            response.read.assert_called_once_with(dt.MAX_BYTES+1)
            self.assertIsInstance(build.call_args.args[0],dt._NoRedirect)

    def test_download_prechecks_no_request_for_invalid_identifiers_or_urls(self):
        with patch.object(dt,"build_opener",side_effect=AssertionError("unexpected network")):
            for ident in [None,"","a\nb","a\rb","has space","日","x"*513]:
                with self.assertRaises(dt.DecodeError) as ctx:
                    dt.fetch_catalog(dt.CATALOG_URL,ident)
                self.assertEqual(ctx.exception.code,"CREDENTIALS_REQUIRED")
            for url in ["http://example.invalid","https://u:p@example.invalid","https:///missing","https://example.invalid/#fragment"]:
                with self.assertRaises(dt.DecodeError) as ctx:
                    dt.fetch_catalog(url,"synthetic-id")
                self.assertEqual(ctx.exception.code,"DOWNLOAD_FAILED")
            with self.assertRaises(dt.DecodeError):
                dt.fetch_catalog(dt.CATALOG_URL,"synthetic-id",kind="unknown")

    def test_http_errors_are_sanitized_and_redirects_rejected(self):
        sensitive = "never-print-identifier"
        for error, code in [(HTTPError("https://example.invalid",401,sensitive,{},None),"ACCESS_DENIED"),
                            (HTTPError("https://example.invalid",403,sensitive,{},None),"ACCESS_DENIED"),
                            (HTTPError("https://example.invalid",302,sensitive,{},None),"DOWNLOAD_FAILED"),
                            (URLError(sensitive),"DOWNLOAD_FAILED")]:
            with patch.object(dt,"build_opener") as build:
                build.return_value.open.side_effect = error
                with self.assertRaises(dt.DecodeError) as ctx:
                    dt.fetch_catalog(dt.CATALOG_URL,sensitive)
            self.assertEqual(ctx.exception.code,code)
            self.assertNotIn(sensitive,str(ctx.exception))
        self.assertIsNone(dt._NoRedirect().redirect_request(Request(dt.CATALOG_URL),None,302,"",{},"https://example.invalid"))

    def test_download_response_size_limit(self):
        with patch.object(dt,"MAX_BYTES",16),patch.object(dt,"build_opener") as build:
            build.return_value.open.return_value.__enter__.return_value.read.return_value = b"x"*17
            with self.assertRaises(dt.DecodeError) as ctx:
                dt.fetch_catalog(dt.CATALOG_URL,"synthetic-id")
            self.assertEqual(ctx.exception.code,"SIZE_LIMIT")

    def test_cli_download_uses_user_id_not_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"credentials.json"
            path.write_text(json.dumps({"user_id":"synthetic-owner","token":"synthetic-manual-token"}))
            output = io.StringIO()
            with patch.object(dt,"fetch_catalog",return_value=VECTORS["catalog"]["data"]) as fetch,contextlib.redirect_stdout(output):
                self.assertEqual(dt.main(["--url","--credentials-file",str(path)]),0)
            fetch.assert_called_once_with(dt.CATALOG_URL,"synthetic-owner",kind="catalog")
            self.assertEqual(json.loads(output.getvalue()),FIXTURE["expectedProfiles"])

    def test_cli_explicit_identifier_and_failures_preserve_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            ident,output = Path(tmp)/"id.txt",Path(tmp)/"out.json"
            ident.write_bytes(b"synthetic-id\r\n")
            with patch.object(dt,"fetch_catalog",return_value=VECTORS["texts"]["data"]) as fetch:
                self.assertEqual(dt.main(["--url","--request-id-file",str(ident),"--kind","texts","-o",str(output)]),0)
            fetch.assert_called_once_with(dt.CATALOG_URL,"synthetic-id",kind="texts")
            self.assertEqual(json.loads(output.read_text()),FIXTURE["expectedTexts"])
            original = output.read_bytes()
            stderr = io.StringIO()
            with patch.object(dt,"fetch_catalog") as fetch,contextlib.redirect_stderr(stderr):
                self.assertEqual(dt.main(["--url","-o",str(output)]),1)
            fetch.assert_not_called()
            self.assertEqual(json.loads(stderr.getvalue())["error"],"CREDENTIALS_REQUIRED")
            self.assertEqual(output.read_bytes(),original)
            ident.write_bytes(b"\xff")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(dt.main(["--url","--request-id-file",str(ident)]),1)

    def test_cli_standalone_copy_local_and_link(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script,source,output = root/"dtunnelmod.py",root/"response.txt",root/"result.json"
            shutil.copyfile(ROOT/"decoders/Python/dtunnelmod.py",script)
            source.write_text(VECTORS["catalog"]["data"])
            proc = subprocess.run([sys.executable,str(script),str(source),"-o",str(output)],cwd=root,capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr)
            self.assertEqual(json.loads(output.read_text()),FIXTURE["expectedProfiles"])
            proc = subprocess.run([sys.executable,str(script),"--link",FIXTURE["link"]],cwd=root,capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr)
            self.assertEqual(json.loads(proc.stdout),FIXTURE["expectedProfiles"][0])
            source.write_text("!broken!")
            previous = output.read_bytes()
            proc = subprocess.run([sys.executable,str(script),str(source),"-o",str(output)],cwd=root,capture_output=True,text=True)
            self.assertEqual(proc.returncode,1)
            self.assertEqual(output.read_bytes(),previous)
            self.assertEqual(proc.stdout,"")

    def test_cli_local_read_limit_and_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"source.txt"
            path.write_bytes(b"x"*17)
            with patch.object(dt,"MAX_BYTES",16),contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(dt.main([str(path)]),1)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(dt.main([str(path.with_name("missing"))]),2)


if __name__ == "__main__":
    unittest.main()
