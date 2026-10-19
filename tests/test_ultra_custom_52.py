"""Ultra Custom .ua: independent JCE/DEFLATE vectors checked against ARM64."""
import base64
import contextlib
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path
from unittest.mock import patch

from decoders.Python import ultra_custom_52 as uc

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / "tests/golden/ultra_custom_52_vectors.json").read_text())
VECTORS = {v["name"]: v for v in FIXTURE["vectors"]}
PASSWORD = FIXTURE["password"]


def mask(data):
    # Test input producer only. Positive reference outputs are frozen JCE
    # vectors independently compared with the real libx ARM64 instructions.
    s = 0x91AC3F12
    for b in bytes.fromhex("a78840e92f734b36fb"):
        s ^= b
    out = bytearray()
    for i, b in enumerate(data):
        s ^= (s << 13) & 0xffffffff
        s ^= s >> 17
        s ^= (s << 5) & 0xffffffff
        key = bytes.fromhex("a78840e92f734b36fb")[(i+(s & 255)) % 9]
        v = ((b ^ key) + s) & 255
        out.append(((v >> 4) | (v << 4)) & 255)
    return base64.urlsafe_b64encode(out)


def xml(props):
    root = ET.Element("properties")
    for key, value in props.items():
        ET.SubElement(root, "entry", key=key).text = value
    return ET.tostring(root, encoding="utf-8")


class UltraCustom52Tests(unittest.TestCase):
    def assert_error(self, data, code, **kwargs):
        with self.assertRaises(uc.DecodeError) as ctx:
            uc.decode(data, **kwargs)
        self.assertEqual(ctx.exception.code, code)
        self.assertIsNone(uc.run(data, **kwargs))

    def test_all_independent_vectors_and_complete_properties(self):
        for vector in FIXTURE["vectors"]:
            with self.subTest(name=vector["name"]):
                data = vector["data"]
                stage = uc.unmask(base64.urlsafe_b64decode(data))
                self.assertEqual(hashlib.sha256(stage).hexdigest(), vector["stageSha256"])
                result = uc.decode(data, password=PASSWORD)
                profiles = result.get("profiles", [result])
                self.assertEqual([p["properties"] for p in profiles],
                                 [FIXTURE["expectedProfiles"][i] for i in vector["expected"]])
                self.assertEqual(json.loads(uc.run(data, password=PASSWORD)), result)
                for p in profiles:
                    self.assertEqual(p["comments"], ["Archivo de Configuracion"])
                    self.assertEqual(p["properties"]["proxyPayload"], "GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
                    self.assertEqual(p["properties"]["empty"], "")
                    self.assertEqual(p["properties"]["futureField"], "keep me")

    def test_dictionary_matches_extracted_apk_dictionary(self):
        self.assertEqual(uc.LINK_DICTIONARY, (ROOT / "tests/golden/ultra_custom_52_dictionary.txt").read_bytes())
        self.assertEqual(len(uc.DICTIONARY_KEYS), 72)
        self.assertEqual(hashlib.sha256(uc.LINK_DICTIONARY).hexdigest(),
                         "78e8417efba522298311269ddfb9bc1fd29e55cbc758b0c778e3081225b26ca7")

    def test_ua_links_bom_wrapping_and_optional_padding(self):
        data = VECTORS["link-plain"]["data"]
        expected = uc.decode(data)
        for text in ["ua://" + data, "\ufeff \nua:// " + data + "\n", data.rstrip("="),
                     "\r\n".join(data[i:i+64] for i in range(0, len(data), 64))]:
            self.assertEqual(uc.decode(text.encode()), expected)

    def test_original_password_required_for_outer_and_bundle_member(self):
        for name in ["single-password", "link-password", "bundle-outer-password", "bundle-mixed-password"]:
            data = VECTORS[name]["data"]
            with self.subTest(name=name):
                self.assert_error(data, "PASSWORD_REQUIRED")
                self.assert_error(data, "PASSWORD_REQUIRED", password="")
                self.assert_error(data, "AUTH_FAILED", password="wrong password")
                self.assertIsNotNone(uc.run(data, password=PASSWORD))

    def test_uap1_authenticates_header_ciphertext_and_tag(self):
        raw = uc.unmask(base64.urlsafe_b64decode(VECTORS["single-password"]["data"]))
        for index in [4, 19, 20, 31, 32, len(raw)-17, len(raw)-16, len(raw)-1]:
            modified = bytearray(raw)
            modified[index] ^= 1
            with self.subTest(index=index):
                self.assert_error(mask(modified), "AUTH_FAILED", password=PASSWORD)
        self.assert_error(mask(b"UAP1"+b"x"*12), "TRUNCATED", password=PASSWORD)

    def test_mixed_bundle_preserves_wrapper_and_all_members(self):
        result = uc.decode(VECTORS["bundle-mixed-password"]["data"], password=PASSWORD)
        self.assertEqual(result["type"], "bundle")
        self.assertEqual(len(result["profiles"]), 2)
        self.assertFalse(result["encoding"]["passwordProtected"])
        protected = result["profiles"][1]
        self.assertEqual(protected["passwordEnvelope"]["properties"]["file.profilePasswordFormat"], "1")
        self.assertEqual(protected["properties"]["blockHwid"], "1")
        self.assertEqual(protected["properties"]["file.validade"], "1")
        self.assertEqual(protected["embeddedJson"]["v2rayjson"]["outbounds"][0]["protocol"], "vless")

    def test_invalid_transport_and_size_limits(self):
        for data in [None, [], 1, b"", b"\xff", b"ua://", b"other://AAAA", b"A", b"!bad!", b"++++"]:
            self.assertIsNone(uc.run(data))
        with patch.object(uc, "MAX_BYTES", 10):
            self.assert_error(b"x"*11, "SIZE_LIMIT")
            self.assert_error("日"*5, "SIZE_LIMIT")
        with patch.object(uc, "MAX_TOTAL_XML_BYTES", 5):
            self.assert_error(VECTORS["single-plain"]["data"], "SIZE_LIMIT")

    def test_compression_truncation_trailing_data_and_bomb_limits(self):
        raw = uc.unmask(base64.urlsafe_b64decode(VECTORS["link-plain"]["data"]))
        self.assert_error(mask(raw[:-1]), "COMPRESSION_ERROR")
        self.assert_error(mask(raw+b"extra"), "COMPRESSION_ERROR")
        self.assert_error(mask(b"EXA1\xff\xff"), "COMPRESSION_ERROR")
        z = zlib.compressobj(9, zlib.DEFLATED, -15, zdict=uc.LINK_DICTIONARY)
        packed = b"EXA1" + z.compress(b"x"*10000) + z.flush()
        with patch.object(uc, "MAX_BYTES", 1000):
            self.assert_error(mask(packed), "SIZE_LIMIT")

    def test_xml_rejects_duplicate_keys_external_entities_and_nested_values(self):
        for data in [b'<properties><entry key="x">1</entry><entry key="x">2</entry></properties>',
                     b'<!DOCTYPE properties [<!ENTITY x "hidden">]><properties><entry key="x">&x;</entry></properties>',
                     b'<!DOCTYPE properties SYSTEM "https://example.invalid/private"><properties/>',
                     b'<properties><entry key="x"><nested/></entry></properties>',
                     b'<properties><entry>no key</entry></properties>',
                     b'<properties><unknown/></properties>']:
            self.assert_error(mask(b'<?xml version="1.0"?>'+data), "INVALID_XML")

    def test_bundle_requires_exact_count_keys_and_no_nesting(self):
        profile = xml({"file.profileName": "synthetic"}).decode()
        good = {"file.bundleFormat": "UA-BUNDLE-1", "file.profileCount": "1", "profile.0": profile}
        for props in [{**good, "file.profileCount": "0"}, {**good, "file.profileCount": "101"},
                      {**good, "extra": "bad"}, {**good, "profile.0": ""},
                      {k:v for k,v in good.items() if k != "profile.0"}]:
            self.assert_error(mask(xml(props)), "FORMAT_ERROR")
        self.assert_error(mask(xml({**good, "file.bundleFormat": "UA-BUNDLE-2"})), "UNSUPPORTED_BUNDLE")
        self.assert_error(mask(xml({**good, "profile.0": xml(good).decode()})), "UNSUPPORTED_BUNDLE")
        hundred = {"file.bundleFormat": "UA-BUNDLE-1", "file.profileCount": "100"}
        hundred.update({f"profile.{i}": profile for i in range(100)})
        self.assertEqual(len(uc.decode(mask(xml(hundred)))["profiles"]), 100)

    def test_password_wrapper_requires_exact_schema_and_uap1(self):
        wrapper = {"file.profilePasswordFormat": "1", "file.profileName": "x", "file.passwordPayload": "AAAA"}
        bundle = {"file.bundleFormat": "UA-BUNDLE-1", "file.profileCount": "1", "profile.0": xml(wrapper).decode()}
        for w in [wrapper, {**wrapper, "file.profilePasswordFormat": "2"}, {**wrapper, "extra": "bad"}]:
            self.assert_error(mask(xml({**bundle, "profile.0": xml(w).decode()})), "FORMAT_ERROR", password=PASSWORD)
        self.assert_error(mask(xml(wrapper)), "FORMAT_ERROR", password=PASSWORD)

    def test_embedded_json_is_an_additional_view_raw_value_is_preserved(self):
        for value in ['{"a":1,"a":2}', '{"a":NaN}', '{"a":1e999}', '{"a":"\\ud800"}', '{broken}', '[]', '{"unknown":true}']:
            result = uc.decode(mask(xml({"v2rayjson": value})))
            self.assertEqual(result["properties"]["v2rayjson"], value)
            if value in ["[]", '{"unknown":true}']:
                self.assertEqual(result["embeddedJson"]["v2rayjson"], json.loads(value))
            else:
                self.assertNotIn("embeddedJson", result)

    def test_cli_standalone_copy_password_file_and_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "ultra_custom_52.py"
            script.write_bytes((ROOT / "decoders/Python/ultra_custom_52.py").read_bytes())
            source, pw, output = root/"profile.ua", root/"password.txt", root/"result.json"
            source.write_text(VECTORS["single-password"]["data"])
            pw.write_bytes(PASSWORD.encode()+b"\r\n")
            proc = subprocess.run([sys.executable,str(script),str(source),"--password-file",str(pw),"-o",str(output)],
                                  cwd=root,capture_output=True,text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, "")
            self.assertEqual(proc.stderr, "")
            self.assertEqual(json.loads(output.read_text())["properties"], FIXTURE["expectedProfiles"][1])

    def test_cli_wrong_password_never_returns_partial_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, output = root/"profile.ua", root/"result.json"
            source.write_text(VECTORS["bundle-mixed-password"]["data"])
            output.write_text("existing output")
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(uc.getpass,"getpass",return_value="synthetic-secret-do-not-print"), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                rc = uc.main([str(source),"--ask-password","-o",str(output)])
            self.assertEqual(rc, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(json.loads(stderr.getvalue())["error"], "AUTH_FAILED")
            self.assertNotIn("synthetic-secret-do-not-print", stderr.getvalue())
            self.assertEqual(output.read_text(), "existing output")

    def test_cli_missing_files_password_encoding_and_usage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, password = root/"profile.ua", root/"password.txt"
            source.write_text(VECTORS["single-password"]["data"])
            password.write_bytes(b"\xff")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(uc.main([str(root/"missing")]), 2)
                self.assertEqual(uc.main([str(source),"--password-file",str(password)]), 1)
                with self.assertRaises(SystemExit):
                    uc.main([str(source),"--password-file",str(password),"--ask-password"])


if __name__ == "__main__":
    unittest.main()
