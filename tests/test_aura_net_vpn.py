"""Aura build 19: independent vectors, whole documents and actual workers."""
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
from unittest.mock import MagicMock, patch

from decoders.Python import ultra
from decoders.Python.apps.Aura_Net_VPN import codec, file_decoder, server_catalog_decoder

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT/"decoders/Python/apps/Aura_Net_VPN"
VECTORS = json.loads((ROOT/"tests/golden/aura_net_vectors.json").read_text())


class AuraNetTests(unittest.TestCase):
    def test_six_independent_complete_documents_and_bot_route(self):
        for vector in VECTORS["documents"]:
            with self.subTest(kind=vector["kind"], mode=vector["mode"]):
                wire = vector["wire"].encode()
                result = json.loads((file_decoder.run if vector["kind"] == "file" else server_catalog_decoder.run)(wire))
                expected = ({"application": "Aura Net VPN", "extension": ".aura", "config": vector["expected"]}
                            if vector["kind"] == "file" else vector["expected"])
                self.assertEqual(result, expected)
                if vector["kind"] == "file":
                    self.assertEqual(json.loads(ultra.run(wire, ".aura")), expected)

    def test_salt_nonce_ciphertext_and_tag_authentication(self):
        for vector in VECTORS["documents"]:
            if vector["mode"] == "plain":
                continue
            text = vector["wire"]
            if vector["mode"] == "export":
                text = text[:3]+text[4:]
            raw = base64.b64decode(text)
            for offset in (0, 16, 28, len(raw)-1):
                changed = bytearray(raw); changed[offset] ^= 1
                damaged = base64.b64encode(changed).decode()
                if vector["mode"] == "export":
                    damaged = damaged[:3]+"Q"+damaged[3:]
                with self.assertRaises(ValueError):
                    codec.open_document(damaged.encode())

    def test_inner_failure_never_falls_back_to_legacy(self):
        obj = copy.deepcopy(VECTORS["documents"][0]["outer"])
        raw = bytearray(base64.b64decode(obj["Payload"])); raw[-1] ^= 1
        obj["Payload"] = base64.b64encode(raw).decode()
        with patch.object(ultra, "decrypt_ultra_file", side_effect=AssertionError("No fallback after authentication")):
            with self.assertRaises(ValueError):
                file_decoder.run(json.dumps(obj).encode())

    def test_authenticated_invalid_json_utf8_never_falls_back(self):
        with patch.object(ultra, "decrypt_ultra_file", side_effect=AssertionError("No legacy retry")):
            for name in ("duplicate", "invalidUtf8"):
                with self.assertRaises(ValueError):
                    file_decoder.run(VECTORS[name].encode())

    def test_historical_aura_both_aad_modes_and_unchanged_sibling_routes(self):
        from tests.test_ultra_sandok import config_fixture
        for aad in (True, False):
            data = config_fixture("auranetvpn", aad=aad, inner=True)
            expected = {"application": ultra.ULTRA_NAMES[".aura"], "extension": ".aura",
                        "config": ultra.decrypt_ultra_file(data, ".aura")}
            self.assertEqual(json.loads(file_decoder.run(data)), expected)
            self.assertEqual(json.loads(ultra.run(data, ".aura")), expected)
        self.assertEqual(ultra.ULTRA_CONFIGS["auranetvpn"]["password"], b"AuraNETXRPTeam")
        self.assertEqual(ultra.EXT_TO_KEY[".bcl"], "beevpn")

    def test_actual_worker_catalog_file_and_inventory(self):
        from cloud.workers.python.engine import decode_file, decode_provider_catalog, load_file_engines, load_runtime_file_engines
        canonical = load_file_engines(); runtime = load_runtime_file_engines()
        self.assertEqual(len(canonical), 240); self.assertEqual(len(runtime), 256)
        self.assertTrue(canonical["aura"]["source"].endswith("/ultra.py"))
        self.assertTrue(runtime["aura"]["source"].endswith("/Aura_Net_VPN/file_decoder.py"))
        self.assertEqual(runtime["bcl"], canonical["bcl"])
        for vector in VECTORS["documents"]:
            data = vector["wire"].encode()
            output = (decode_file("aura", data) if vector["kind"] == "file"
                      else decode_provider_catalog("aura-net-vpn", data))
            expected = ({"application": "Aura Net VPN", "extension": ".aura", "config": vector["expected"]}
                        if vector["kind"] == "file" else vector["expected"])
            self.assertEqual(output["structuredJson"], expected)
            self.assertEqual(json.loads(output["rawText"]), expected)
            self.assertFalse(output["isPartial"])
        formats = json.loads((ROOT/"cloud/web/content/file-formats.json").read_text())["formats"]
        entry = next(item for item in formats if item["suffix"] == "aura")
        self.assertEqual(entry["name"], "Aura Net VPN AuraNet_v9")
        self.assertEqual(entry["credentialFields"], [])

    def test_bad_inputs_structures_numbers_depth_and_surrogates(self):
        cases = [b"", b"\xff", b"<html>invalid</html>", b"{}", b"[]", b"x"*(codec.MAX_BYTES+1),
                 b'{"Name":"a","TunnelType":false}',
                 b'{"Name":"a","TunnelType":"SSH","x":NaN}',
                 b'{"Name":"a","TunnelType":"SSH","x":1e9999}',
                 b'{"Name":"a","TunnelType":"SSH","x":"\\ud800"}',
                 b'{"Name":"a","TunnelType":"SSH","x":'+b'['*51+b'0'+b']'*51+b'}']
        for data in cases:
            with self.subTest(prefix=data[:30]), self.assertRaises(ValueError):
                codec.decode_file(data)
        for data in (None, "x", bytearray(b"AAAA")):
            with self.assertRaises(ValueError):
                file_decoder.run(data)
        with self.assertRaises(ValueError):
            codec.decode_catalog(VECTORS["documents"][0]["wire"].encode())

    def test_bom_crlf_and_inserted_letter_are_handled_as_exporter(self):
        vector = VECTORS["documents"][0]
        # CR/LF after the insertion point are ignored by Go StdEncoding.
        text = vector["wire"][:9]+"\r\n"+vector["wire"][9:]
        self.assertEqual(codec.decode_file(b"\xef\xbb\xbf"+text.encode()), vector["expected"])
        with self.assertRaises(codec.EnvelopeError):
            codec.open_envelope(vector["wire"][:3]+"!"+vector["wire"][4:], exported=True)

    def test_downloader_fixed_source_headers_and_failures(self):
        response = MagicMock(status=200, headers={})
        response.read.return_value = b"synthetic"
        opener = MagicMock(); opener.open.return_value.__enter__.return_value = response
        with patch.object(codec, "build_opener", return_value=opener):
            self.assertEqual(codec.download(), b"synthetic")
            request = opener.open.call_args.args[0]
            self.assertEqual(request.full_url, "https://strongteam.co/api/kidvpn/v4/aurav1.txt")
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(request.get_header("User-agent"), "Aura Net VPN")
            self.assertEqual(request.get_header("Accept-encoding"), "identity")
            self.assertEqual(opener.open.call_args.kwargs["timeout"], 25)
            response.read.assert_called_with(codec.MAX_BYTES+1)
            for status, headers, body in ((403, {}, b"x"), (200, {"Content-Encoding": "gzip"}, b"x"),
                                          (200, {}, b""), (200, {}, b"x"*(codec.MAX_BYTES+1))):
                response.status, response.headers, response.read.return_value = status, headers, body
                with self.assertRaises(ValueError):
                    codec.download()
            opener.open.side_effect = OSError("private information")
            with self.assertRaisesRegex(ValueError, "REMOTE_UNAVAILABLE"):
                codec.download()
        with self.assertRaises(ValueError):
            codec._NoRedirect().redirect_request(None, None, 302, "", {}, codec.SOURCE)

    def test_standalone_cli_complete_output_summary_and_0600_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); script = root/"aura_net_vpn.py"
            shutil.copyfile(APP/"codec.py", script)
            source = root/"synthetic.enc"; target = root/"result.json"
            vector = next(v for v in VECTORS["documents"] if v["kind"] == "catalog")
            source.write_text(vector["wire"])
            env = dict(os.environ); env.pop("PYTHONPATH", None)
            base = [sys.executable, str(script), "--input", str(source)]
            done = subprocess.run([*base, "--output", str(target)], cwd=root, env=env, capture_output=True, timeout=20)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(json.loads(target.read_text()), vector["expected"])
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            again = subprocess.run([*base, "--output", str(target)], cwd=root, env=env, capture_output=True, timeout=20)
            self.assertEqual(again.returncode, 1)
            info = subprocess.run([*base, "--summary"], cwd=root, env=env, check=True, capture_output=True, timeout=20)
            self.assertEqual(json.loads(info.stdout)["servers"], 1)
            self.assertNotIn(b"synthetic h2", info.stdout)
            profile = VECTORS["documents"][0]; source.write_text(profile["wire"])
            done = subprocess.run([sys.executable, str(script), "--file", str(source)], cwd=root, env=env, check=True, capture_output=True, timeout=20)
            self.assertEqual(json.loads(done.stdout), profile["expected"])

    @unittest.skipUnless(shutil.which("java"), "JDK is required for independent generation")
    def test_independent_libsodium_jdk_regenerates_frozen_vectors(self):
        from tests.golden import aura_net_reference
        self.assertEqual(aura_net_reference.generate(), VECTORS)


if __name__ == "__main__":
    unittest.main()
