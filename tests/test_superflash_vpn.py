"""Focused SV5C authentication, complete documents and paired bridge checks."""
import base64
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from decoders.Python.apps.SuperFlash_VPN import codec, server_catalog_decoder as catalog
from cloud.workers.python.catalog_vpn_bridge import decode

ROOT = Path(__file__).resolve().parents[1]


class SuperFlashSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = json.loads((ROOT / 'tests/golden/superflash_vpn_vectors.json').read_text())
        cls.servers, cls.users = (base64.b64decode(cls.v[k]) for k in ('servers', 'users'))

    def test_native_sodium_jdk_documents_and_paired_bridge(self):
        # The public test seed cannot sign app catalogs. Only this in-process
        # test substitutes its public key; no runtime key override exists.
        with patch.object(codec, 'SIGNATURE_PUBLIC_KEY', bytes.fromhex(self.v['testPublicKey'])):
            for source, expected in [(self.servers, 'expectedServers'), (self.users, 'expectedUsers')]:
                self.assertEqual(json.loads(catalog.run(source)), self.v[expected])
            expected = {'provider': 'superflash-vpn', 'complete': True,
                        'catalogs': {'servers': self.v['expectedServers'], 'users': self.v['expectedUsers']}}
            bundle = catalog.pack_catalogs(self.servers, self.users)
            self.assertEqual(json.loads(decode('superflash-vpn', bundle)), expected)

    def test_app_key_rejects_test_signer_and_signed_corruption_rejects_all_layers(self):
        with self.assertRaises(codec.DecodeError): catalog.run(self.users)
        with patch.object(codec, 'SIGNATURE_PUBLIC_KEY', bytes.fromhex(self.v['testPublicKey'])):
            corrupt_signature = bytearray(self.users);corrupt_signature[-1] ^= 1
            invalid = [bytes(corrupt_signature), self.users[:-1], b'', b'<html/>',
                       b'x' * (codec.MAX_BYTES + 1), *(base64.b64decode(v) for v in self.v['invalid'])]
            for raw in invalid:
                with self.subTest(length=len(raw)), self.assertRaises(codec.DecodeError) as e:
                    catalog.run(raw)
                self.assertNotIn('invalid-cipher', str(e.exception))

    def test_pair_requires_both_correct_sources_and_refuses_duplicates_redirects(self):
        with patch.object(codec, 'SIGNATURE_PUBLIC_KEY', bytes.fromhex(self.v['testPublicKey'])):
            bundle = json.loads(catalog.pack_catalogs(self.servers, self.users))
            swapped = json.loads(json.dumps(bundle));swapped['catalogs']['users'] = swapped['catalogs']['servers']
            del bundle['catalogs']['users']
            for raw in [json.dumps(bundle).encode(), json.dumps(swapped).encode(),
                        b'{"kind":"x","kind":"y","catalogs":{}}']:
                with self.assertRaises(codec.DecodeError): catalog.run(raw)
        with self.assertRaises(codec.DecodeError): catalog.pack_catalogs(b'', self.users)
        with self.assertRaises(codec.DecodeError): catalog._NoRedirect().redirect_request(None, None, None, None, None, None)


if __name__ == '__main__': unittest.main()
