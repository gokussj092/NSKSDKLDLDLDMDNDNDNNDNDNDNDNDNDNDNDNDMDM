"""Synthetic primitives and independent real public-ID binding, not registration."""
import base64,importlib.util,json,sys,tempfile,unittest,subprocess,shutil
from pathlib import Path
TOOLS=Path(__file__).parents[1]/'tools';sys.path.insert(0,str(TOOLS))
import hc2_identity as hc
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1,SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature.pss import MGF1

class IdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.key=RSA.generate(2048);cls.other=RSA.generate(2048)
    def header(self,mgf=SHA1):
        cert={'v':1,'id':hc.access_id(self.key),'p':hc.b64u(self.key.public_key().export_key(format='DER'))}
        payload=hc.b64u(json.dumps(cert,separators=(',',':')).encode())
        cipher=PKCS1_OAEP.new(self.key.public_key(),hashAlgo=SHA256,mgfunc=lambda s,n:MGF1(s,n,mgf))
        return {'r':[{'c':payload+'.'+hc.b64u(b'synthetic-unsigned-certificate'),
                      'w':hc.b64u(cipher.encrypt(bytes(range(32))))}]}
    def test_original_oaep_parameters_and_matching_private_key(self):
        plain,meta=hc.unwrap_header(self.header(),self.key.export_key())
        self.assertEqual(plain,bytes(range(32)));self.assertFalse(meta['issuer_signature_verified']);self.assertFalse(meta['payload_decrypted'])
    def test_wrong_private_public_only_mgf_and_ciphertext_rejected(self):
        with self.assertRaisesRegex(ValueError,'PRIVATE_KEY_IS_NOT_A_RECIPIENT'):hc.unwrap_header(self.header(),self.other.export_key())
        with self.assertRaisesRegex(ValueError,'RECIPIENT_PRIVATE_KEY_REQUIRED'):hc.unwrap_header(self.header(),self.key.public_key().export_key())
        with self.assertRaises(ValueError):hc.unwrap_header(self.header(SHA256),self.key.export_key())
        header=self.header();raw=bytearray(hc.unb64u(header['r'][0]['w']));raw[0]^=1;header['r'][0]['w']=hc.b64u(raw)
        with self.assertRaises(ValueError):hc.unwrap_header(header,self.key.export_key())
    def test_identity_generation_never_claims_registration(self):
        with tempfile.TemporaryDirectory() as temp:
            descriptor=hc.generate(temp)
            private=RSA.import_key((Path(temp)/'private-key.pem').read_bytes())
            self.assertEqual(descriptor['access_id'],hc.access_id(private))
            self.assertEqual(len(descriptor['access_id']),47)
            self.assertEqual(descriptor['registration_status'],'UNREGISTERED')
            self.assertIsNone(descriptor['issuer_certificate'])
            self.assertFalse(descriptor['opens_other_recipients_files'])
    @unittest.skipUnless(shutil.which('java'),'JCE source launcher unavailable')
    def test_independent_java_oaep_oracle(self):
        with tempfile.TemporaryDirectory() as temp:
            public=Path(temp)/'public.der';public.write_bytes(self.key.public_key().export_key(format='DER'))
            result=subprocess.run(['java',str(Path(__file__).with_name('HcOaepOracle.java')),str(public)],
                                  input=bytes(range(32)),capture_output=True,timeout=30,check=True)
            header=self.header();header['r'][0]['w']=hc.b64u(base64.b64decode(result.stdout,validate=True))
            value,meta=hc.unwrap_header(header,self.key.export_key())
            self.assertEqual(value,bytes(range(32)))

if __name__=='__main__':unittest.main()
