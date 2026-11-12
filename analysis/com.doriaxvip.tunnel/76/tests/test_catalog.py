import base64
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT))
from decoders.Python.apps.Genis_VPN.codec import CATALOG_PASSWORD, DecodeError, MAX_BYTES, decode_catalog, decode_field
from decoders.Python.apps.Genis_VPN.server_catalog_decoder import NoRedirect, run
from cloud.workers.python.engine import decode_provider_catalog

FIXTURES = Path(__file__).with_name('fixtures')


def envelope(data):
    salt=b'FAKE076!';material=last=b''
    while len(material)<48:
        last=hashlib.md5(last+CATALOG_PASSWORD+salt).digest();material+=last
    return base64.b64encode(b'WakkoDev'+salt+AES.new(material[:32],AES.MODE_CBC,material[32:48]).encrypt(pad(data,16)))


class CatalogTests(unittest.TestCase):
    def test_independent_jca_full_document_vectors(self):
        for name in ('catalog','users'):
            with self.subTest(name=name):
                self.assertEqual(decode_catalog((FIXTURES/(name+'.enc')).read_bytes()),json.loads((FIXTURES/(name+'.json')).read_text()))

    def test_cli_and_render_preserve_all_metadata(self):
        expected=json.loads((FIXTURES/'catalog.json').read_text())
        self.assertEqual(json.loads(run((FIXTURES/'catalog.enc').read_bytes())),expected)
        p=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/Genis_VPN/server_catalog_decoder.py'),str(FIXTURES/'catalog.enc')],capture_output=True,text=True,check=True)
        self.assertEqual(json.loads(p.stdout),expected)

    def test_real_isolated_worker_preserves_entire_fixture(self):
        result=decode_provider_catalog('genis-vpn',(FIXTURES/'catalog.enc').read_bytes())
        expected=json.loads((FIXTURES/'catalog.json').read_text())
        self.assertEqual(result['structuredJson'],expected)
        self.assertEqual(json.loads(result['rawText']),expected)
        self.assertIs(result['isPartial'],False)

    def test_transport_errors_are_not_catalogs(self):
        data=(FIXTURES/'catalog.enc').read_bytes()
        for bad in (b'',b'<html>Site Unavailable</html>',data[:-4],b'!invalid!',b'X'*(MAX_BYTES+1),base64.b64encode(b'Salted__'+b'x'*40)):
            with self.subTest(length=len(bad)),self.assertRaises(DecodeError):decode_catalog(bad)

    def test_schema_and_duplicate_keys_fail_closed(self):
        for text in ('{}','{"Version":"1","Servers":[]}','{"Version":"1","Servers":[{}]}',
                     '{"Version":"1","Version":"2","Servers":[]}',
                     '{"Version":"1","Servers":[{"p0PgL3l0d89mnssz7ImPJA==":123}]}',
                     '{"Version":"1","Servers":[{"p0PgL3l0d89mnssz7ImPJA==":""}]}',
                     '{"Version":"1","Servers":[],"n":NaN}'):
            with self.subTest(text=text),self.assertRaises(DecodeError):decode_catalog(envelope(text.encode()))

    def test_nonempty_invalid_inner_field_never_returns_error_sentinel(self):
        for text in ('not-a-field','ERROR','AAAA',123,None):
            with self.subTest(value=text),self.assertRaises((ValueError,TypeError)):decode_field(text)
        self.assertEqual(decode_field(''),'')
        for malformed in ('not-a-field','%%%'):
            obj={'Version':'1','Servers':[{'p0PgL3l0d89mnssz7ImPJA==':malformed}]}
            with self.assertRaises(DecodeError):decode_catalog(envelope(json.dumps(obj).encode()))

    def test_no_arbitrary_url_or_redirect(self):
        with self.assertRaises(DecodeError):NoRedirect().redirect_request(None,None,None,None,None,None)

    def test_known_encrypted_field_cannot_change_to_boolean(self):
        raw=base64.b64decode((FIXTURES/'catalog.enc').read_bytes())
        material=last=b''
        while len(material)<48:
            last=hashlib.md5(last+CATALOG_PASSWORD+raw[8:16]).digest();material+=last
        from Crypto.Util.Padding import unpad
        obj=json.loads(unpad(AES.new(material[:32],AES.MODE_CBC,material[32:48]).decrypt(raw[16:]),16))
        obj['Servers'][0]['ACqWMY4zuZWzSEs8cZMXIw==']=False
        with self.assertRaises(DecodeError):decode_catalog(envelope(json.dumps(obj).encode()))

    def test_network_failure_never_falls_back_to_included(self):
        from decoders.Python.apps.Genis_VPN.server_catalog_decoder import download
        with patch('decoders.Python.apps.Genis_VPN.server_catalog_decoder.build_opener',side_effect=OSError('network')):
            with self.assertRaises(DecodeError):download()


if __name__=='__main__':unittest.main()
