"""Wolf16: independent Go fixtures, authenticated envelopes, full JSON and worker."""
import base64,json
from pathlib import Path
import unittest
from unittest.mock import patch
from decoders.Python.apps.Wolf_Custom_VPN import codec,codec_v16,file_decoder
ROOT=Path(__file__).resolve().parents[1]
V=json.loads((ROOT/"analysis/core.vpn3jx.xtreme/16/tests/fixtures/build16-vectors.json").read_text())
class Wolf16Tests(unittest.TestCase):
    def test_complete_native_transport_and_embedded_vectors(self):
        for key in ("catalogTransport","catalogEmbedded"):
            self.assertEqual(codec.decode_catalog(V[key].encode()),V["expected"])
        for name,value in V["fieldCipher"].items():
            self.assertEqual(codec_v16.decrypt(value),V["fieldPlain"][name])
    def test_profile_preserves_unknown_fields_and_types(self):
        r=json.loads(file_decoder.run(V["profileTransport"].encode()))
        self.assertEqual(r["config"],V["expectedProfile"])
        self.assertIs(r["config"]["URI"],False)
        self.assertEqual(r["config"]["unknown"],V["expectedProfile"]["unknown"])
    def test_gcm_authenticates_salt_nonce_ciphertext_and_tag(self):
        for transport,key in [(False,"catalogEmbedded"),(True,"catalogTransport")]:
            text=V[key]
            raw=bytearray(base64.b64decode(text[:3]+text[4:] if transport else text))
            for at in (0,16,28,len(raw)-1):
                changed=raw.copy();changed[at]^=1
                b=base64.b64encode(changed).decode()
                if transport:b=b[:3]+"Z"+b[3:]
                with self.assertRaises(codec.DecodeError):codec.decode_catalog(b.encode())
    def test_native_inserted_letter_and_bad_base64_fail_closed(self):
        for value in ("","abc","A"*61,V["catalogTransport"][:3]+"!"+V["catalogTransport"][4:]):
            with self.assertRaises((codec.DecodeError,ValueError)):codec.decrypt(value)
    def test_authenticated_bad_document_never_falls_back_to_historical_decoder(self):
        with patch("decoders.Python.ultra.decrypt_ultra_file",side_effect=AssertionError("unexpected fallback")):
            with self.assertRaises(codec.DecodeError):
                file_decoder.run(V["catalogTransport"].encode())
    def test_authenticated_invalid_utf8_never_tries_another_format(self):
        with patch("decoders.Python.ultra.decrypt_ultra_file",side_effect=AssertionError("unexpected fallback")):
            with self.assertRaises(codec.DecodeError):file_decoder.run(V["invalidUtf8Transport"].encode())
    def test_real_isolated_worker_returns_whole_synthetic_json(self):
        from cloud.workers.python.engine import decode_provider_catalog,decode_file
        r=decode_provider_catalog("wolf-custom-vpn",V["catalogTransport"].encode())
        self.assertEqual(r["structuredJson"],V["expected"]);self.assertFalse(r["isPartial"])
        r=decode_file("wolf",V["profileTransport"].encode())
        self.assertEqual(r["structuredJson"]["config"],V["expectedProfile"]);self.assertFalse(r["isPartial"])
if __name__=="__main__":unittest.main()

