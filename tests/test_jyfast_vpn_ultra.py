"""Independent JCA vectors, lossless paired catalogs, SKS and real worker routing."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from decoders.Python.apps.JyFast_VPN_Ultra import codec, server_catalog_decoder as catalog, file_decoder

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'decoders/Python/apps/JyFast_VPN_Ultra'
V = json.loads((ROOT / 'tests/golden/jyfast_vectors.json').read_text())
SKS = json.loads((ROOT / 'tests/golden/jireh_vectors.json').read_text())


def bundle(catalogs=None):
    return json.dumps({'kind': codec.BUNDLE_KIND, 'catalogs': {
        k: base64.b64encode(v.encode()).decode() for k, v in (catalogs or V['catalogs']).items()
    }}).encode()


def seal(text, mode='free'):
    raw = AES.new(hashlib.sha256(codec.PASSWORDS[mode].encode()).digest(), AES.MODE_CBC, bytes(16)).encrypt(pad(text.encode(), 16))
    return ''.join(codec.ALPHABET[codec.BASE64_ALPHABET.index(c)] for c in base64.b64encode(raw).decode()).encode()


class JyfastTests(unittest.TestCase):
    def test_jca_vectors_cover_both_modes_and_all_fields_without_renaming(self):
        for mode in ('free', 'premium'):
            result = codec.decode_catalog(V['catalogs'][mode].encode(), mode=mode)
            self.assertEqual(result, V['expected'][mode])
            self.assertEqual(result['Servers'][0]['SNI'], '')
        self.assertEqual(len(codec.SERVER_FIELDS), 22)
        for name, cipher in V['fieldCipher'].items():
            self.assertEqual(codec.decrypt(cipher, codec.FIELD_PASSWORD), V['fieldPlain'][name])

    def test_paired_worker_keeps_both_complete_catalogs_distinct(self):
        expected = {'provider': 'jyfast-vpn-ultra', 'complete': True, 'catalogs': V['expected']}
        self.assertEqual(json.loads(catalog.run(bundle())), expected)
        sys.path.insert(0, str(ROOT / 'cloud/workers/python'))
        from engine import decode_provider_catalog
        result = decode_provider_catalog('jyfast-vpn-ultra', bundle())
        self.assertEqual(result['structuredJson'], expected)
        self.assertFalse(result['isPartial'])
        self.assertEqual(json.loads(result['rawText']), expected)

    def test_incomplete_wrong_mode_or_ambiguous_bundle_fails(self):
        for mode, cipher in [('free', V['catalogs']['premium']), ('premium', V['catalogs']['free'])]:
            with self.assertRaises(codec.DecodeError): codec.decode_catalog(cipher.encode(), mode=mode)
        for data in (bundle({'free': V['catalogs']['free']}),
                     b'{"kind":"wrong","catalogs":{}}',
                     b'{"kind":"a","kind":"b","catalogs":{}}',
                     json.dumps({'kind': codec.BUNDLE_KIND, 'catalogs': {'free': 'broken', 'premium': 'broken'}}).encode()):
            with self.assertRaises(codec.DecodeError): codec.decode_bundle(data)

    def test_padding_symbols_wrong_types_and_json_ambiguity_are_rejected(self):
        for raw in (b'private-sentinel', b'<html/>', b'6' * 24, V['catalogs']['free'][:-8].encode()):
            with self.assertRaises(codec.DecodeError) as error: codec.decode_catalog(raw)
            self.assertNotIn('private-sentinel', str(error.exception))
        for text in ('{"Version":"1","Version":"2","Servers":[]}',
                     '{"Version":"1","Servers":[]}',
                     '{"Version":"1","Servers":[{"Name":"x","SNI":false}]}',
                     '{"Version":"1","Servers":[{"Name":"x","SNI":"bad"}]}',
                     '{"Version":"1","Servers":[{"Name":"x"}],"x":NaN}'):
            with self.assertRaises(codec.DecodeError): codec.decode_catalog(seal(text))

    def test_input_depth_and_output_limits(self):
        for data in (b'', b'x' * (codec.MAX_BYTES + 1)):
            with self.assertRaises(codec.DecodeError): codec.decode_catalog(data)
        deep = {'Version': '1', 'Servers': [{'Name': 'x'}], 'unknown': [0]}
        for _ in range(65): deep['unknown'] = [deep['unknown']]
        with self.assertRaises(codec.DecodeError): codec.decode_catalog(seal(json.dumps(deep)))
        with self.assertRaises(codec.DecodeError): codec.render({'x': 'x' * codec.MAX_BYTES})

    def test_sks_gcm_and_des_reuse_the_existing_lossless_engine(self):
        for raw in (SKS['profileGcm'].encode(), base64.b64decode(SKS['profileDesBase64'])):
            self.assertEqual(json.loads(file_decoder.run(raw)), SKS['expectedProfile'])
        tampered = bytearray(SKS['profileGcm'].encode());tampered[-5] ^= 1
        with self.assertRaises(codec.DecodeError): file_decoder.run(bytes(tampered))

    def test_fixed_downloader_modes_certificate_header_and_redirect_policy(self):
        class Response:
            status = 200
            headers = {}
            data = V['catalogs']['free'].encode()
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, n): return self.data[:n]
        class Opener:
            seen = []
            def open(self, req, timeout):
                self.seen.append(req.full_url)
                if timeout != 25: raise AssertionError('deadline')
                if req.get_header('X-ignix-sig') != '10c7440b8feac5cee6a54959e7599ff26bd27153': raise AssertionError('signer')
                return Response()
        opener = Opener()
        with patch.object(catalog, 'build_opener', return_value=opener):
            catalog.download(mode='free');catalog.download(mode='premium')
            self.assertEqual(opener.seen, [
                'http://dev.jenrri.shop:85/ignix_update.php?cfg=free',
                'http://dev.jenrri.shop:85/ignix_update.php?cfg=premium'])
            for mode in ('custom', 'http://127.0.0.1/', '../free'):
                with self.assertRaises(codec.DecodeError): catalog.download(mode=mode)
            for bad in (b'', b'<html/>', b'x' * (codec.MAX_BYTES + 1)):
                with patch.object(Response, 'data', bad), self.assertRaises(codec.DecodeError): catalog.download()
            with patch.object(Response, 'headers', {'Content-Encoding': 'gzip'}), self.assertRaises(codec.DecodeError): catalog.download()
        with self.assertRaises(codec.DecodeError): catalog._NoRedirect().redirect_request(None, None, 302, '', {}, 'http://dev.jenrri.shop:85/other')

    def test_cli_from_another_directory_is_offline_and_preserves_whole_json(self):
        env = {k: v for k, v in os.environ.items() if k != 'PYTHONPATH'}
        for mode in ('free', 'premium'):
            args = [sys.executable, str(APP / 'server_catalog_decoder.py'), '--stdin', '--mode', mode]
            r = subprocess.run(args, input=V['catalogs'][mode].encode(), capture_output=True, cwd='/tmp', env=env, timeout=10)
            self.assertEqual(r.returncode, 0, r.stderr.decode())
            self.assertEqual(json.loads(r.stdout), V['expected'][mode])
        r = subprocess.run(args, input=b'private-sentinel', capture_output=True, cwd='/tmp', env=env, timeout=10)
        self.assertNotEqual(r.returncode, 0);self.assertEqual(r.stdout, b'');self.assertNotIn(b'private-sentinel', r.stderr)

    def test_exact_original_launcher_icon_is_available_in_both_locations(self):
        icon = (APP / 'JyFast_VPN_Ultra.png').read_bytes()
        self.assertEqual(icon, (ROOT / 'cloud/web/public/server-vpn-icons/jyfast-vpn-ultra.png').read_bytes())
        self.assertEqual(hashlib.sha256(icon).hexdigest(), '05e176023754019f84135e0247d0db91370a450536ddbc7b035c626e0a094ae8')

    @unittest.skipUnless(shutil.which('java'), 'JDK source launcher unavailable')
    def test_jdk_independently_decrypts_committed_synthetic_catalogs(self):
        lines = ''.join('dec\t' + base64.b64encode(codec.PASSWORDS[m].encode()).decode() + '\t' + base64.b64encode(V['catalogs'][m].encode()).decode() + '\n' for m in ('free', 'premium'))
        r = subprocess.run(['java', str(ROOT / 'tests/golden/jyfast_oracle.java')], input=lines, text=True, capture_output=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        for mode, line in zip(('free', 'premium'), r.stdout.splitlines()):
            outer = json.loads(base64.b64decode(line))
            self.assertEqual(outer['Version'], V['expected'][mode]['Version'])
            self.assertEqual(outer['Servers'][0]['ServerIP'], V['fieldCipher']['ServerIP'])

if __name__ == '__main__': unittest.main()
