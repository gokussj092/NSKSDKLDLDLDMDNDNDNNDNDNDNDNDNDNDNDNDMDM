"""Private Speicers reader: complete documents, fail-closed fields and CLI."""
from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from decoders.Python.apps.Speicers_Pro_VPN import server_catalog_decoder as codec, file_decoder
from cloud.workers.python.catalog_vpn_bridge import decode

ROOT = Path(__file__).resolve().parents[1]


def seal_field(clear):
    rotated = ''.join(chr((ord(c)-65+3)%26+65) if 'A'<=c<='Z' else
        chr((ord(c)-97+3)%26+97) if 'a'<=c<='z' else c for c in clear)
    iv = bytes(range(16))
    return base64.urlsafe_b64encode(iv+AES.new(codec.FIELD_KEY,AES.MODE_CBC,iv).encrypt(pad(rotated.encode(),16))).decode()


def seal(text, glyph=False):
    if glyph:
        key = hashlib.sha256(codec.GLYPH_PASSWORD.hex().upper().encode()).digest()
        packed = base64.b64encode(AES.new(key,AES.MODE_CBC,bytes(16)).encrypt(pad(text.encode(),16)))
        return ''.join(codec.ALPHABET[b>>4]+codec.ALPHABET[b&15] for b in packed).encode()
    material = previous = b''
    salt = bytes(range(8))
    while len(material)<48:
        previous = hashlib.md5(previous+codec.CATALOG_PASSWORD+salt).digest()
        material += previous
    return base64.b64encode(b'WakkoDev'+salt+AES.new(material[:32],AES.MODE_CBC,material[32:48]).encrypt(pad(text.encode(),16)))


def catalog():
    return {'Version':'test-1','ReleaseNotes':'Prueba privada','Servers':[
        {codec.FIELD_NAMES['sName']:seal_field('Servidor A'),codec.FIELD_NAMES['ServerIP']:seal_field('example.invalid'),
         codec.FIELD_NAMES['ServerPass']:'','enabled':False,'serverType':1,'tunnelType':3,
         'ssh_userpass_enabled':False,'MIgkNbuX29MmGatZNVaFUj==':False,'unknown':{'keep':[True,None,0]}},
        {codec.FIELD_NAMES['sName']:seal_field('Servidor B'),'enabled':True,'serverType':0,'tunnelType':0},
    ]}


class SpeicersTests(unittest.TestCase):
    def test_complete_document_keeps_disabled_servers_flags_and_unknown_fields(self):
        original = catalog()
        result = codec.decode_catalog(seal(json.dumps(original)))
        expected = catalog()
        expected['Servers'][0][codec.FIELD_NAMES['sName']] = 'Servidor A'
        expected['Servers'][0][codec.FIELD_NAMES['ServerIP']] = 'example.invalid'
        expected['Servers'][1][codec.FIELD_NAMES['sName']] = 'Servidor B'
        self.assertEqual(result,expected)
        self.assertEqual(len(result['Servers']),2)
        self.assertFalse(result['Servers'][0]['enabled'])

    def test_secondary_glyph_asset_has_plain_inner_fields(self):
        obj = {'version':'9','servers':[{'serverName':'Local','password':'demo','enabled':False}], 'extra':[1,2]}
        self.assertEqual(codec.decode_catalog(seal(json.dumps(obj),True)),obj)

    def test_worker_run_never_downloads(self):
        source = seal(json.dumps(catalog()))
        with patch.object(codec,'download',side_effect=AssertionError('network')):
            self.assertEqual(json.loads(decode('speicers-pro-vpn',source)),codec.decode_catalog(source))

    def test_actual_isolated_worker_preserves_the_complete_catalog(self):
        sys.path.insert(0,str(ROOT/'cloud/workers/python'))
        from engine import decode_provider_catalog
        source=seal(json.dumps(catalog()))
        result=decode_provider_catalog('speicers-pro-vpn',source)
        self.assertEqual(result['structuredJson'],codec.decode_catalog(source))
        self.assertFalse(result['isPartial'])

    def test_invalid_inner_field_fails_entire_document(self):
        for bad in ('not encrypted',True,'A'*44):
            obj = catalog();obj['Servers'][0][codec.FIELD_NAMES['ServerIP']] = bad
            with self.assertRaises(codec.DecodeError):codec.run(seal(json.dumps(obj)))

    def test_duplicate_keys_nonfinite_wrong_schema_and_empty_lists_rejected(self):
        for text in ('{"Version":"1","Version":"2","Servers":[]}',
                '{"Version":"1","Servers":[],"x":NaN}',
                '{"Version":"1","Servers":[]}',
                '{"Version":"1","Servers":[{}]}','[]',
                '{"version":"9","servers":[]}'):
            with self.assertRaises(codec.DecodeError):codec.run(seal(text))

    def test_invalid_wire_limits_alphabet_utf8_and_header_rejected(self):
        for data in (b'',b'x'*(codec.MAX_BYTES+1),b'\xff',b'AAAA',b'{}',
                '▙▚!'.encode(),base64.b64encode(b'Salted__'+bytes(40))):
            with self.assertRaises(codec.DecodeError):codec.run(data)

    def test_excessive_depth_rejected_after_opening(self):
        obj=catalog();obj['extra']=[0]
        for _ in range(66):obj['extra']=[obj['extra']]
        with self.assertRaises(codec.DecodeError):codec.run(seal(json.dumps(obj)))

    def test_error_never_exposes_response_or_plaintext(self):
        marker='PRIVATE-DEMO-MARKER'
        with self.assertRaises(codec.DecodeError) as error:codec.run(seal(marker))
        self.assertNotIn(marker,str(error.exception))

    def test_file_decoder_reuses_independent_java_gcm_des_vectors(self):
        vectors=json.loads((ROOT/'tests/golden/fenix_vectors.json').read_text())
        for data in (vectors['profileGcm'].encode(),base64.b64decode(vectors['profileDesBase64'])):
            self.assertEqual(json.loads(file_decoder.run(data)),vectors['expectedProfile'])

    def test_cli_standalone_secure_output_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp=Path(tmp);script=tmp/'speicers_pro.py';shutil.copyfile(codec.__file__,script)
            src=tmp/'copy.enc';src.write_bytes(seal(json.dumps(catalog())))
            out=tmp/'out.json'
            cmd=[sys.executable,str(script),'--input',str(src),'-o',str(out)]
            result=subprocess.run(cmd,capture_output=True,timeout=20)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(out.stat().st_mode&0o777,0o600)
            before=out.read_bytes()
            result=subprocess.run(cmd,capture_output=True,timeout=20)
            self.assertEqual(result.returncode,1)
            self.assertEqual(out.read_bytes(),before)
            self.assertNotIn(b'example.invalid',result.stdout+result.stderr)

    def test_downloader_follows_only_fixed_get_and_limits_bytes(self):
        from unittest.mock import MagicMock
        body=seal(json.dumps(catalog()))
        response=MagicMock();response.status=200;response.headers={};response.read.return_value=body
        response.__enter__.return_value=response
        opener=MagicMock();opener.open.return_value=response
        with patch.object(codec,'build_opener',return_value=opener):
            self.assertEqual(codec.download_legacy(),body)
        args,kwargs=opener.open.call_args
        self.assertEqual(args[0].full_url,codec.CATALOG_URL)
        self.assertEqual(args[0].get_method(),'GET')
        self.assertEqual(kwargs['timeout'],25)
        response.read.assert_called_once_with(codec.MAX_BYTES+1)

    def test_redirects_rejected(self):
        with self.assertRaises(codec.DecodeError):
            codec._NoRedirect().redirect_request(None,None,302,'',{},'https://example.invalid/')

    @unittest.skipUnless(shutil.which('java'),'JDK required for independent oracle')
    def test_jdk_full_documents_and_unicode_fields(self):
        from scripts.apk_analysis.speicers_verify import verify
        obj=catalog();raw='Az ñÉ 中 ǅ 𐐀 😀\n'
        iv=bytes(range(16))
        obj['Servers'][0][codec.FIELD_NAMES['sInfo']]=base64.urlsafe_b64encode(
            iv+AES.new(codec.FIELD_KEY,AES.MODE_CBC,iv).encrypt(pad(raw.encode(),16))).decode()
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'private.enc';path.write_bytes(seal(json.dumps(obj)))
            self.assertTrue(verify(path)['jdkEqual'])
            secondary={'version':'9','servers':[{'serverName':'Prueba','enabled':False}]}
            path.write_bytes(seal(json.dumps(secondary),True))
            self.assertTrue(verify(path)['workerEqual'])


if __name__ == '__main__':unittest.main()
