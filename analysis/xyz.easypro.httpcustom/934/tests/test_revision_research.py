"""Public synthetic security checks for the research tools, not APK validation."""
import importlib.util,json,sys,unittest
from pathlib import Path
TOOLS=Path(__file__).parents[1]/'tools';sys.path.insert(0,str(TOOLS))
import n15_content as n15
import recipient_lab as lab
from Crypto.PublicKey import RSA

class ResearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.owner=RSA.generate(2048);cls.other=RSA.generate(2048)
    def test_recipient_file_needs_corresponding_private_key(self):
        public=lab.public_record(self.owner);data={'host':'example.org','note':'synthetic'}
        sealed=lab.seal(public,data)
        self.assertEqual(lab.unseal(self.owner.export_key(),sealed),data)
        self.assertFalse(sealed['http_custom_compatible'])
        self.assertFalse(public['http_custom_registered'])
        with self.assertRaises(ValueError):lab.unseal(self.owner.public_key().export_key(),sealed)
        with self.assertRaises(ValueError):lab.unseal(self.other.export_key(),sealed)
    def test_recipient_ciphertext_and_public_id_tampering_rejected(self):
        public=lab.public_record(self.owner);sealed=lab.seal(public,{'fixture':True})
        cipher=bytearray(lab.dec(sealed['ciphertext']));cipher[0]^=1
        with self.assertRaises(ValueError):lab.unseal(self.owner.export_key(),{**sealed,'ciphertext':lab.enc(cipher)})
        with self.assertRaises(ValueError):lab.seal({**public,'id':'HC2-INVALID-SYNTHETIC'}, {})
    def test_n15_rejects_bad_material_lengths(self):
        for seed,aad,pw in [(b'x',b'aad',b''),(bytes(32),b'',b''),(bytes(32),b'aad',b'short')]:
            with self.assertRaises(ValueError):n15.derive(seed,aad,pw)
    def test_n15_password_key_changes_content_key(self):
        seed=bytes(range(32));aad=b'HCCFG|12|synthetic-public-vector|n15|934'
        self.assertNotEqual(n15.derive(seed,aad),n15.derive(seed,aad,bytes(range(32))))
        self.assertNotEqual(n15.derive(seed,aad),n15.derive(seed,aad+b'!'))
    def test_frozen_vectors_from_independent_supplied_sha256_implementation(self):
        vectors=json.loads((Path(__file__).parents[1]/'generated/n15_public_vectors.json').read_text())
        for case in vectors['cases']:
            with self.subTest(password_key_length=len(case['password_key_hex'])//2):
                actual=n15.derive(bytes.fromhex(vectors['seed_hex']),vectors['aad_ascii'].encode(),
                                  bytes.fromhex(case['password_key_hex']))
                self.assertEqual(actual.hex(),case['expected_key_hex'])

if __name__=='__main__':unittest.main()
