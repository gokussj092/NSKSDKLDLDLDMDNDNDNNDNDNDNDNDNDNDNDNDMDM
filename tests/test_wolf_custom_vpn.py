"""Independent JCA fixture, modern/legacy file routing and complete catalogs."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from Crypto.Cipher import AES
from decoders.Python.apps.Wolf_Custom_VPN import codec, file_decoder, server_catalog_decoder as catalog

ROOT = Path(__file__).resolve().parents[1]
V = json.loads((ROOT / 'tests/golden/wolf_vectors.json').read_text())

def seal(text):
    cipher = AES.new(codec.KEY, AES.MODE_GCM, nonce=bytes(12))
    raw, tag = cipher.encrypt_and_digest(text.encode())
    return base64.b64encode(bytes(12) + raw + tag)

class WolfTests(unittest.TestCase):
    def test_independent_full_catalog_fixture_and_both_native_keys(self):
        self.assertEqual(codec.decode_catalog(V['catalog'].encode()), V['expected'])
        for key, value in V['fieldCipher'].items():
            self.assertEqual(codec.decrypt(value, injector=key in ('Payload', 'SNI', 'CustomProxy')), V['fieldPlain'][key])
        self.assertEqual(json.loads(catalog.run(V['catalog'].encode())), V['expected'])

    def test_unknown_keys_types_empty_fields_and_nested_settings_survive(self):
        d = codec.decode_catalog(V['catalog'].encode())
        self.assertEqual(d['Servers'][0]['unknown'], {'Payload': 'preserve-unknown'})
        self.assertEqual(d['Networks'][0]['SNI'], '')
        self.assertFalse(d['Networks'][0]['URI'])
        self.assertEqual(d['Servers'][0]['SSH_Port'], '443')
        self.assertEqual(d['Servers'][0]['UDPHysteria']['port'], '80')
        self.assertEqual(codec.decode_catalog(json.dumps(V['expected']).encode()), V['expected'])

    def test_invalid_authentication_and_authenticated_bad_documents_fail_closed(self):
        data = bytearray(base64.b64decode(V['catalog']));data[-1] ^= 1
        for raw in (base64.b64encode(data), b'private-sentinel', b'<html/>'):
            with self.assertRaises(codec.DecodeError) as error:catalog.run(raw)
            self.assertNotIn('private-sentinel', str(error.exception))
        for text in ('{"Version":"1","Version":"2","Servers":[]}', '{"Version":NaN}', '{}', '[]'):
            with self.assertRaises(codec.DecodeError):catalog.run(seal(text))
        doc = json.loads(json.dumps(V['expected']))
        doc['Networks'][0]['SNI'] = base64.b64encode(data[:50]).decode()
        with self.assertRaises(codec.DecodeError):codec.decode_catalog(json.dumps(doc).encode())
        with patch('decoders.Python.ultra.decrypt_ultra_file', side_effect=AssertionError('unexpected legacy fallback')):
            with self.assertRaises(codec.DecodeError):file_decoder.run(seal('{"Name":"x"}'))

    def test_depth_input_and_complete_output_limits(self):
        for raw in (b'', b'x' * (codec.MAX_BYTES + 1)):
            with self.assertRaises(codec.DecodeError):catalog.run(raw)
        with self.assertRaises(codec.DecodeError):file_decoder.run(b'x' * (codec.MAX_FILE_BYTES + 1))
        d = {'Version': '1', 'Servers': [{'Name': 's'}], 'Networks': [{'Name': 'n'}], 'unknown': []}
        for _ in range(66):d['unknown'] = [d['unknown']]
        with self.assertRaises(codec.DecodeError):codec.decode_catalog(json.dumps(d).encode())
        with self.assertRaises(codec.DecodeError):codec.render({'x': 'x' * codec.MAX_BYTES})

    def test_modern_profile_cloud_worker_and_ultra_dispatcher(self):
        from cloud.workers.python.engine import decode_file, decode_provider_catalog
        from decoders.Python import ultra
        expected = {'application': 'Wolf Custom VPN', 'extension': '.wolf', 'config': V['expectedProfile']}
        for result in (file_decoder.run(V['profile'].encode()), ultra.run(V['profile'].encode(), '.wolf')):
            self.assertEqual(json.loads(result), expected)
        worker = decode_file('wolf', V['profile'].encode())
        self.assertEqual(worker['structuredJson'], expected)
        self.assertFalse(worker['isPartial'])
        result = decode_provider_catalog('wolf-custom-vpn', V['catalog'].encode())
        self.assertEqual(result['structuredJson'], V['expected'])
        self.assertEqual(json.loads(result['rawText']), V['expected'])
        self.assertFalse(result['isPartial'])

    def test_real_historical_argon2_route_is_preserved_for_both_suffixes(self):
        from decoders.Python import ultra
        salt, nonce = bytes(range(16)), bytes(range(12))
        p = ultra.ULTRA_CONFIGS['wolfcustom'];key = ultra.ultra_derive_key(salt, p['password'], p['mem'])
        self.assertIsNotNone(key)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        body, tag = cipher.encrypt_and_digest(b'{"Name":"synthetic historical","Payload":"plain"}')
        raw = base64.b64encode(salt + nonce + body + tag)
        for result in (file_decoder.run(raw), ultra.run(raw, '.wolftunnel')):
            parsed = json.loads(result);self.assertEqual(parsed['config']['Name'], 'synthetic historical')
        from cloud.workers.python.engine import load_file_engines, load_runtime_file_engines
        before, after = load_file_engines(), load_runtime_file_engines()
        self.assertEqual((len(before), len(after)), (240, 256))
        self.assertEqual(before['wolftunnel'], after['wolftunnel'])
        self.assertNotEqual(before['wolf']['source'], after['wolf']['source'])

    def test_cli_works_offline_outside_checkout_and_errors_do_not_echo_input(self):
        env = {k: v for k, v in os.environ.items() if k != 'PYTHONPATH'}
        for name, raw, expected in [('server_catalog_decoder.py', V['catalog'], V['expected']),
                                    ('file_decoder.py', V['profile'], {'application': 'Wolf Custom VPN', 'extension': '.wolf', 'config': V['expectedProfile']})]:
            cmd = [sys.executable, str(ROOT / 'decoders/Python/apps/Wolf_Custom_VPN' / name)]
            if name.startswith('server'):cmd.append('--stdin')
            r = subprocess.run(cmd, input=raw.encode(), capture_output=True, cwd='/tmp', env=env, timeout=10)
            self.assertEqual(r.returncode, 0, r.stderr.decode());self.assertEqual(json.loads(r.stdout), expected)
        r = subprocess.run(cmd, input=b'private-sentinel', capture_output=True, cwd='/tmp', env=env, timeout=20)
        self.assertNotEqual(r.returncode, 0);self.assertEqual(r.stdout, b'');self.assertNotIn(b'private-sentinel', r.stderr)

    def test_fixed_download_rejects_redirects_html_encoding_and_oversize(self):
        class Response:
            status = 200
            headers = {}
            data = V['catalog'].encode()
            def __enter__(self):return self
            def __exit__(self, *args):pass
            def read(self, n):return self.data[:n]
        class Opener:
            def open(self, req, timeout):
                self.url = req.full_url
                if timeout != 25 or req.get_header('Accept-encoding') != 'identity':raise AssertionError()
                return Response()
        opener = Opener()
        with patch.object(catalog, 'build_opener', return_value=opener):
            self.assertEqual(catalog.download(), V['catalog'].encode())
            self.assertEqual(opener.url, 'https://strongteam.co/api/wolfcustom/newv1.txt')
            for data in (b'', b'<html>', b'x' * (codec.MAX_BYTES + 1)):
                with patch.object(Response, 'data', data), self.assertRaises(codec.DecodeError):catalog.download()
            with patch.object(Response, 'headers', {'Content-Encoding': 'gzip'}), self.assertRaises(codec.DecodeError):catalog.download()
        with self.assertRaises(codec.DecodeError):catalog._NoRedirect().redirect_request()

    def test_jdk_independently_decrypts_the_whole_committed_synthetic_catalog(self):
        line = 'dec\t' + base64.b64encode(codec.KEY).decode() + '\t' + V['catalog'] + '\n'
        r = subprocess.run(['java', str(ROOT / 'tests/golden/wolf_oracle.java')], input=line, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(base64.b64decode(r.stdout))['Version'], 'synthetic-1')

if __name__ == '__main__':unittest.main()
