"""Independent synthetic vectors; no real catalogs, APKs or VPN accounts."""
import base64
import json
import io
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from decoders.Python.apps.VIP_Snipher_Pro import codec, server_catalog_decoder as catalog

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'decoders/Python/apps/VIP_Snipher_Pro'
V = json.loads((ROOT / 'tests/golden/vip_snipher_vectors.json').read_text())

def seal(text):
    # Construct malformed inner documents through the independent encoder.
    line = '10\t' + base64.b64encode(text.encode()).decode() + '\n'
    result = subprocess.run(['java', str(ROOT / 'tests/golden/vip_snipher_oracle.java')],
                            input=line, text=True, capture_output=True, check=True, timeout=30)
    return base64.b64decode(result.stdout.strip(), validate=True)

class VipSnipherTests(unittest.TestCase):
    def test_independent_java_vectors_for_all_modes_and_complete_nested_document(self):
        for mode, fn in enumerate((codec.decode_main, codec.decode_special, codec.decode_sensitive)):
            self.assertEqual(fn(V['cipher'][str(mode)]), V['plain'][str(mode)])
        self.assertEqual(codec.decode_catalog(V['catalog'].encode()), V['expected'])
        self.assertEqual(json.loads(catalog.run(V['catalog'].encode())), V['expected'])

    def test_unknown_ciphertext_types_and_empty_values_are_preserved(self):
        doc = codec.decode_catalog(V['catalog'].encode())
        server = doc['Servers'][0]
        self.assertEqual(server['UnknownCipher'], V['cipher']['1'])
        self.assertEqual(server['Obfs'], '');self.assertIsNone(server['CustomCert'])
        self.assertIs(server['UseCustomCert'], False)
        self.assertIs(doc['Networks'][0]['EnableWS'], True)
        self.assertIs(type(server['Protocol']), int)
        self.assertEqual(doc['unknown'], V['expected']['unknown'])

    def test_isolated_worker_and_historical_format_inventory(self):
        from cloud.workers.python.engine import decode_provider_catalog, load_runtime_file_engines
        result = decode_provider_catalog('vip-snipher-pro', V['catalog'].encode())
        self.assertEqual(result['structuredJson'], V['expected'])
        self.assertEqual(json.loads(result['rawText']), V['expected'])
        self.assertFalse(result['isPartial']);self.assertFalse(result['exporterCertified'])
        inventory = load_runtime_file_engines()
        self.assertEqual(len(inventory), 256)
        self.assertTrue(inventory['vipsnipherpro']['source'].endswith('/renz.py'))
        self.assertNotIn('js', inventory);self.assertNotIn('rj', inventory)

    def test_rejects_bad_encoding_padding_duplicate_keys_and_partial_documents(self):
        for data in (b'private-sentinel', b'<html/>', b'', V['catalog'][:-8].encode()):
            with self.assertRaises(codec.DecodeError) as error:catalog.run(data)
            self.assertNotIn('private-sentinel', str(error.exception))
        for text in ('{"Version":"a","Version":"b","Servers":[],"Networks":[]}',
                     '{"Version":NaN}', '{"Version":"1","Servers":[],"Networks":[]}',
                     '{"Version":"1","Servers":[{"Name":"bad"}],"Networks":[{"Name":"bad"}]}'):
            with self.assertRaises(codec.DecodeError):catalog.run(seal(text))
        for fn in (codec.decode_main, codec.decode_special, codec.decode_sensitive):
            with self.assertRaises(ValueError):fn('invalid')

    def test_whole_document_rejects_one_invalid_known_field(self):
        outer = codec.open_outer(V['catalog'].encode())
        outer['Networks'][0]['Payload'] = 'invalid'
        with self.assertRaises(codec.DecodeError):catalog.run(seal(json.dumps(outer)))
        outer['Networks'][0]['Payload'] = False
        with self.assertRaises(codec.DecodeError):catalog.run(seal(json.dumps(outer)))

    def test_input_depth_and_output_limits(self):
        with self.assertRaises(codec.DecodeError):catalog.run(b'x' * (codec.MAX_BYTES + 1))
        outer = codec.open_outer(V['catalog'].encode())
        node = []
        for _ in range(66):node = [node]
        outer['unknown'] = node
        with self.assertRaises(codec.DecodeError):catalog.run(seal(json.dumps(outer)))
        with self.assertRaises(codec.DecodeError):codec.render({'x': 'x' * codec.MAX_BYTES})

    def test_unavailable_fixed_source_is_sanitized_and_never_falls_back(self):
        self.assertIn('/NEW-VIP-SNIPHER-PRO-3/', catalog.SOURCE)
        self.assertEqual(catalog.USER_AGENT, 'VIP Snipher Pro/2.9')
        class Opener:
            def open(self, request, timeout):
                self_request = request.full_url
                if self_request != catalog.SOURCE or timeout != 25:raise AssertionError('wrong source')
                headers = {key.lower(): value for key, value in request.header_items()}
                if headers != {'user-agent': 'VIP Snipher Pro/2.9', 'accept': 'application/json',
                               'x-github-api-version': '2022-11-28', 'accept-encoding': 'identity'}:
                    raise AssertionError('unexpected public request headers')
                raise HTTPError(catalog.SOURCE, 404, 'private-sentinel', {}, None)
        with patch.object(catalog, 'build_opener', return_value=Opener()):
            with self.assertRaises(codec.DecodeError) as error:catalog.download()
            self.assertNotIn('private-sentinel', str(error.exception))
        with self.assertRaises(codec.DecodeError):catalog._NoRedirect().redirect_request(None, None, None, None, None, None)

    def test_stdin_cli_from_outside_repo_returns_all_data(self):
        result = subprocess.run([sys.executable, str(APP / 'server_catalog_decoder.py'), '--stdin'],
                                input=V['catalog'].encode(), cwd='/tmp', capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), V['expected']);self.assertEqual(result.stderr, b'')

    def test_operator_authorization_is_sent_only_to_the_exact_app_source(self):
        owner = self
        credential = 'Bearer synthetic-vip-test-credential'
        data = V['catalog'].encode()
        class Response:
            status = 200
            headers = {}
            def __enter__(self):return self
            def __exit__(self, *args):return False
            def read(self, limit):
                owner.assertEqual(limit, codec.MAX_BYTES + 1)
                return data
        class Opener:
            def open(self, request, timeout):
                owner.assertEqual(request.full_url, catalog.SOURCE)
                owner.assertEqual(request.get_header('Authorization'), credential)
                owner.assertEqual(request.get_method(), 'GET')
                owner.assertEqual(timeout, 25)
                return Response()
        with patch.object(catalog, 'build_opener', return_value=Opener()):
            self.assertEqual(catalog.download(authorization=credential), data)

    def test_invalid_authorization_is_rejected_before_transport_without_echoing_it(self):
        with patch.object(catalog, 'build_opener') as transport:
            for credential in ('Bearer private-sentinel\r\nX-Injected: yes',
                               'Bearer ', 'Basic private-sentinel', 'Bearer ' + 'x' * 2048):
                with self.assertRaises(codec.DecodeError) as error:
                    catalog.download(authorization=credential)
                self.assertNotIn('private-sentinel', str(error.exception))
            transport.assert_not_called()

    def test_explicit_download_cli_reads_only_its_scoped_authorization_secret(self):
        credential = 'Bearer synthetic-vip-test-credential'
        with patch.dict(os.environ, {catalog.AUTHORIZATION_ENV: credential}), \
             patch.object(sys, 'argv', ['server_catalog_decoder.py', '--download']), \
             patch.object(catalog, 'download', return_value=V['catalog'].encode()) as download, \
             patch.object(sys, 'stdout', new_callable=io.StringIO) as output:
            self.assertEqual(catalog.main(), 0)
            download.assert_called_once_with(authorization=credential)
            self.assertEqual(json.loads(output.getvalue()), V['expected'])
            self.assertNotIn(credential, output.getvalue())

if __name__ == '__main__':unittest.main()
