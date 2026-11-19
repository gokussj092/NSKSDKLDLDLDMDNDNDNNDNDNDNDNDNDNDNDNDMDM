"""Focused independent JDK vectors, RENZ compatibility and isolated Cloud."""
import base64,json,subprocess,sys,unittest
from pathlib import Path
from decoders.Python.apps.SevenNET_VPN import codec,server_catalog_decoder as catalog,file_decoder
from decoders.Python import renz
from cloud.workers.python.engine import decode_provider_catalog
ROOT=Path(__file__).resolve().parents[1]

class SevenNETSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v=json.loads((ROOT/'tests/golden/sevennet_vpn_vectors.json').read_text());cls.raw=cls.v['catalog'].encode()
    def test_full_jdk_document_cli_and_actual_isolated_worker(self):
        self.assertEqual(json.loads(catalog.run(self.raw)),self.v['expected'])
        result=decode_provider_catalog('7net-vpn',self.raw)
        self.assertEqual(result['structuredJson'],self.v['expected']);self.assertEqual(json.loads(result['rawText']),self.v['expected']);self.assertFalse(result['isPartial'])
        path=ROOT/'decoders/Python/apps/SevenNET_VPN/server_catalog_decoder.py'
        p=subprocess.run([sys.executable,str(path),'--stdin'],input=self.raw,cwd='/tmp',capture_output=True,check=True)
        self.assertEqual(json.loads(p.stdout),self.v['expected'])
    def test_sensitive_credentials_and_zero_ciphertext_boundary(self):
        self.assertEqual(codec.decode_sensitive(self.v['sensitiveSample']),self.v['sensitiveExpected'])
        b=self.v['boundary'];self.assertEqual(codec.decode_special(b['cipher']),b['plain'])
        self.assertEqual(renz.renz_decrypt_speciale(b['cipher'],'7net'),b['plain'])
        for method in (codec.decode_main,codec.decode_special,codec.decode_sensitive):
            for invalid in ['not base64','\u200b',base64.b64encode(b'incomplete').decode()]:
                with self.subTest(method=method.__name__),self.assertRaises(ValueError):method(invalid)
    def test_corruption_rejects_entire_catalog_and_limits(self):
        for invalid in [b'',b'<html/>',b'x'*(codec.MAX_BYTES+1),self.raw[:-5],self.v['invalidFieldCatalog'].encode()]:
            with self.subTest(length=len(invalid)),self.assertRaises(codec.DecodeError):catalog.run(invalid)
        with self.assertRaises(codec.DecodeError):catalog._NoRedirect().redirect_request(None,None,None,None,None,None)
    def test_alternate_credential_key_names_decode(self):
        # 7NET 5.6 exports may use User/Pass or user/pwd instead of
        # Username/Password; the decoder must return them in clear.
        # Typed fallback: a short alphanumeric credential must not be
        # rejected for "looking like Base64".
        import hashlib
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        from tests.test_renz_family import profile_fixture, xxtea_encrypt
        from tests.test_renz_legacy_types import legacy_encrypt
        src = renz.RENZ_KEYS["7net"]
        key32 = hashlib.pbkdf2_hmac("sha256", src["KEY_SEED"], src["FIXED_SALT"], 100000, 32)
        nonce = bytes(range(16))
        def enc(plain):
            ct = AES.new(key32, AES.MODE_CBC, nonce).encrypt(pad(plain.encode(), 16))
            return base64.b64encode(xxtea_encrypt(nonce + ct, key32)).decode()
        for cfg, want in (
            ({"User": enc("test-user"), "Pass": enc("test-password")},
             {"User": "test-user", "Pass": "test-password"}),
            ({"user": enc("test-user"), "pwd": enc("test-password")},
             {"user": "test-user", "pwd": "test-password"}),
        ):
            out = json.loads(renz.decode_file(profile_fixture("7net", cfg), ".7net"))["config"]
            for k, v in want.items():
                self.assertEqual(out.get(k), v)
        key2 = renz.renz_get_pbkdf2_key()
        inner = json.dumps({"Username": enc("test1234")}).encode()
        iv = bytes(range(16))
        stage = iv + AES.new(key2, AES.MODE_CBC, iv).encrypt(pad(inner, 16))
        ct2 = base64.b64encode(legacy_encrypt(stage, key2[:16]))
        out = json.loads(renz.decode_file(ct2, ".7net"))["config"]
        self.assertEqual(out.get("Username"), "test1234")

    def test_existing_file_text_routes_and_historical_data(self):
        raw=self.v['file'].encode()
        self.assertEqual(json.loads(file_decoder.run(raw))['config'],self.v['expectedFile'])
        self.assertEqual(json.loads(renz.decode_file(raw,'.7net'))['config'],self.v['expectedFile'])
        self.assertEqual(json.loads(renz.decode_text('7netvpn://'+raw.decode()))['config'],self.v['expectedFile'])
        self.assertEqual(json.loads(file_decoder.run(self.v['networkFile'].encode()))['config'],self.v['expectedNetworkFile'])
        self.assertEqual(json.loads(renz.decode_text('7net://'+raw.decode()))['config'],self.v['expectedFile'])
        self.assertEqual(json.loads(renz.decode_file(self.v['historical'].encode(),'.7net'))['config'],{'Host':'legacy.example.test','Port':443,'Enabled':False})
        p=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/SevenNET_VPN/file_decoder.py')],input=raw,cwd='/tmp',capture_output=True,check=True)
        self.assertEqual(json.loads(p.stdout)['config'],self.v['expectedFile'])

if __name__=='__main__':unittest.main()
