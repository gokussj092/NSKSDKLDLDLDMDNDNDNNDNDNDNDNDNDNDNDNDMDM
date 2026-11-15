"""Netcol 14.2 independent JCA vectors, field keys and complete worker route."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from decoders.Python.apps.Netcol_VPN import codec, server_catalog_decoder as catalog

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'decoders/Python/apps/Netcol_VPN'
V = json.loads((ROOT / 'tests/golden/netcol_vectors.json').read_text())

def seal(text):
    raw = base64.b64encode(AES.new(codec.CATALOG_KEY, AES.MODE_CBC, bytes(16)).encrypt(pad(text.encode(), 16)))
    return ''.join(codec.ALPHABET[v >> 4] + codec.ALPHABET[v & 15] for v in raw).encode()

class NetcolTests(unittest.TestCase):
    def test_independent_jca_catalog_and_each_blowfish_key(self):
        self.assertEqual(codec.decode_catalog(V['catalog'].encode()), V['expected'])
        self.assertEqual(len(codec.SERVER_FIELDS), 7)
        for name, value in V['fieldCipher'].items():
            self.assertEqual(codec.decrypt_field(value, username=name == 'ServerUser'), V['fieldPlain'][name])
        with self.assertRaises(codec.DecodeError):codec.decrypt_field(V['fieldCipher']['Payload'], username=True)
        expected = hashlib.sha256(b'FamiliaGelves24'.hex().upper().encode()).digest()
        self.assertEqual(codec.CATALOG_KEY, expected)
        self.assertNotEqual(codec.CATALOG_KEY, hashlib.sha256(b'FamiliaGelves24').digest())

    def test_preserves_plain_password_unknown_ciphertext_and_mixed_flag_types(self):
        d = codec.decode_catalog(V['catalog'].encode())
        server = d['Servers'][0]
        self.assertEqual(server['ServerPass'], 'U3ludGhldGljLWNsZWFyLXBhc3M=')
        self.assertEqual(server['UnknownCipher'], V['fieldCipher']['Payload'])
        self.assertEqual(server['isSSL'], 'true');self.assertIs(d['Servers'][1]['isSSL'], True)
        self.assertEqual(server['ServerPort'], '443');self.assertEqual(server['SNI'], '')
        self.assertEqual(d['unknown'], V['expected']['unknown'])

    def test_real_worker_keeps_complete_document_without_new_file_inventory(self):
        from cloud.workers.python.engine import decode_provider_catalog, load_runtime_file_engines
        result = decode_provider_catalog('netcol-vpn', V['catalog'].encode())
        self.assertEqual(result['structuredJson'], V['expected'])
        self.assertEqual(json.loads(result['rawText']), V['expected'])
        self.assertFalse(result['isPartial'])
        inventory = load_runtime_file_engines()
        self.assertEqual(len(inventory), 270);self.assertNotIn('netcol', inventory)

    def test_bad_symbols_lengths_padding_and_json_are_rejected_without_input_echo(self):
        for data in (b'private-sentinel', b'<html/>', '▙'.encode(), '▙▙'.encode(), V['catalog'][:-12].encode()):
            with self.assertRaises(codec.DecodeError) as err:catalog.run(data)
            self.assertNotIn('private-sentinel', str(err.exception))
        for doc in ('{"Version":"1","Version":"2","Servers":[]}',
                    '{"Version":"1","Servers":[]}', '{"Version":NaN}',
                    '{"Version":"1","Servers":[{"Name":"x","ServerIP":false}]}',
                    '{"Version":"1","Servers":[{"Name":"x","Payload":"invalid"}]}'):
            with self.assertRaises(codec.DecodeError):catalog.run(seal(doc))

    def test_depth_input_and_output_limits(self):
        for data in (b'', b'x' * (codec.MAX_BYTES + 1)):
            with self.assertRaises(codec.DecodeError):catalog.run(data)
        d = {'Version': '1', 'Servers': [{'Name': 'x'}], 'unknown': []}
        for _ in range(66):d['unknown'] = [d['unknown']]
        with self.assertRaises(codec.DecodeError):catalog.run(seal(json.dumps(d)))
        with self.assertRaises(codec.DecodeError):codec.render({'x': 'x' * codec.MAX_BYTES})

    def test_fixed_active_source_limits_and_no_redirect_or_stale_fallback(self):
        class Response:
            status = 200
            headers = {}
            data = V['catalog'].encode()
            def __enter__(self):return self
            def __exit__(self, *args):pass
            def read(self, n):return self.data[:n]
        class Opener:
            def open(self, req, timeout):
                if req.full_url != 'https://raw.githubusercontent.com/jdavidag/setting/main/tO6oD1drTvL2.json':raise AssertionError()
                if timeout != 25 or req.get_header('User-agent') != 'Netcol VPN/14.2':raise AssertionError()
                if req.get_header('Accept-encoding') != 'identity':raise AssertionError()
                return Response()
        with patch.object(catalog, 'build_opener', return_value=Opener()):
            self.assertEqual(catalog.download(), V['catalog'].encode())
            for data in (b'', b'<html>', b'x' * (codec.MAX_BYTES + 1)):
                with patch.object(Response, 'data', data), self.assertRaises(codec.DecodeError):catalog.download()
            with patch.object(Response, 'headers', {'Content-Encoding': 'gzip'}), self.assertRaises(codec.DecodeError):catalog.download()
        with self.assertRaises(codec.DecodeError):catalog._NoRedirect().redirect_request()
        self.assertNotIn('firebase', catalog.SOURCE)

    def test_cli_outside_checkout_preserves_full_json_and_has_private_errors(self):
        env = {k:v for k,v in os.environ.items() if k != 'PYTHONPATH'}
        cmd = [sys.executable, str(APP / 'server_catalog_decoder.py'), '--stdin']
        result = subprocess.run(cmd, input=V['catalog'].encode(), capture_output=True, cwd='/tmp', env=env, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(json.loads(result.stdout), V['expected'])
        result = subprocess.run(cmd, input=b'private-sentinel', capture_output=True, cwd='/tmp', env=env, timeout=10)
        self.assertNotEqual(result.returncode, 0);self.assertEqual(result.stdout, b'')
        self.assertNotIn(b'private-sentinel', result.stderr)

    def test_jdk_independently_decrypts_committed_catalog_fixture(self):
        line = 'dec\tcatalog\t' + base64.b64encode(V['catalog'].encode()).decode() + '\n'
        r = subprocess.run(['java', str(ROOT / 'tests/golden/netcol_oracle.java')], input=line,
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(base64.b64decode(r.stdout))['Version'], 'synthetic-162')

    def test_launcher_matches_both_locations_and_original_hash(self):
        png = (APP / 'Netcol_VPN.png').read_bytes()
        self.assertEqual(png, (ROOT / 'cloud/web/public/server-vpn-icons/netcol-vpn.png').read_bytes())
        self.assertEqual(hashlib.sha256(png).hexdigest(), '1cf1a5995d31294a39ffcc03630af88bfcee91577ba061852cc82eb7da9d0b39')
        self.assertEqual(hashlib.sha256((APP / 'Netcol_VPN.webp').read_bytes()).hexdigest(), '0c5bfb9bfa5250413d300133b1339b4a2ff80ad7716664b3573d3bd07ba12f28')

if __name__ == '__main__':unittest.main()
