"""Production Halcon codec/broker/isolated worker checks, synthetic JCA fixtures only."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from Crypto.Cipher import AES
from decoders.Python.apps.Halcon_R_Net import codec, server_catalog_decoder as catalog
from cloud.workers.python.engine import decode_provider_catalog, _child_env, DecodeFailure

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'analysis/com.halcon.connect/1391/tests/fixtures'
PASSWORD = 'S' * 65 + 'A' * 64
REQUEST_SECRET = 'synthetic-request-key!'

def seal(plain):
    cipher = AES.new(hashlib.sha256(PASSWORD.encode()).digest(), AES.MODE_GCM, nonce=bytes(range(12)))
    body, tag = cipher.encrypt_and_digest(plain)
    return symbols(bytes(range(12)) + body + tag)

def symbols(raw):
    return ''.join(codec.ALPHABET[b >> 4] + codec.ALPHABET[b & 15] for b in base64.b64encode(raw)).encode()

class HalconTests(unittest.TestCase):
    def setUp(self):
        self.expected = json.loads((FIXTURES/'catalog.expected.json').read_text())
        self.vector = (FIXTURES/'catalog.envelope').read_bytes()
        self.env = patch.dict(os.environ, {codec.PASSWORD_ENV: PASSWORD,
            catalog.REQUEST_SECRET_ENV: REQUEST_SECRET}, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_jca_vector_preserves_complete_document(self):
        self.assertEqual(codec.decode_catalog(self.vector), self.expected)
        self.assertEqual(json.loads(catalog.run(self.vector)), self.expected)

    def test_authenticated_real_schema_rejects_malformed_records(self):
        for change in [lambda d: d.update(servers=[]), lambda d: d.update(version=1),
                       lambda d: d['servers'][0].update(tunnelType=True),
                       lambda d: d['servers'][0].pop('payload'),
                       lambda d: d['servers'][0].update(serverName='')]:
            doc=json.loads(json.dumps(self.expected));change(doc)
            with self.assertRaises(codec.DecodeError): codec.decode_catalog(seal(json.dumps(doc).encode()))

    def test_wrong_key_and_modified_gcm_tag_fail(self):
        with patch.dict(os.environ,{codec.PASSWORD_ENV:'T'*65+'A'*64}):
            with self.assertRaises(codec.DecodeError): codec.decode_catalog(self.vector)
        text=self.vector.decode();lut={c:i for i,c in enumerate(codec.ALPHABET)}
        encoded=bytes(lut[text[i]]*16+lut[text[i+1]] for i in range(0,len(text),2))
        raw=bytearray(base64.b64decode(encoded));raw[-1]^=1
        with self.assertRaises(codec.DecodeError): codec.decode_catalog(symbols(raw))

    def test_malformed_truncated_html_and_plain_json_rejected(self):
        for data in [b'',b'<html>error</html>', b'{"version":"635"}', self.vector[:-1], symbols(bytes(27)),
                     b'x'*(codec.MAX_BYTES+1)]:
            with self.subTest(size=len(data)), self.assertRaises(codec.DecodeError): codec.decode_catalog(data)

    def test_duplicate_nonfinite_and_deep_json_rejected(self):
        for plain in [b'{"version":"1","version":"2"}',b'{"version":NaN}',
                      b'{"x":'+b'['*70+b'0'+b']'*70+b'}']:
            with self.assertRaises(codec.DecodeError): codec.decode_catalog(seal(plain))

    def test_missing_or_malformed_secrets_fail_before_network(self):
        for key in [codec.PASSWORD_ENV,catalog.REQUEST_SECRET_ENV]:
            for value in ['', 'bad\r\nInjected: secret']:
                with patch.dict(os.environ,{key:value}), patch.object(catalog,'build_opener') as network:
                    with self.assertRaises(codec.DecodeError): catalog.download()
                    network.assert_not_called()

    def test_original_post_signature_and_body(self):
        headers,body=catalog.request_data(1793692575)
        digest=hashlib.sha256(('1793692575'+REQUEST_SECRET).encode()).hexdigest()
        self.assertEqual(headers['X-Auth-Hash'],digest)
        self.assertEqual(headers['X-Timestamp'],'1793692575')
        self.assertEqual(headers['X-App-ID'],'HalconRNet_2026')
        self.assertEqual(body,f'hash={digest}&timestamp=1793692575'.encode())
        self.assertNotIn(PASSWORD.encode(),body)

    def test_fixed_download_rejects_redirect_html_encoding_and_http_errors(self):
        with self.assertRaises(codec.DecodeError): catalog._NoRedirect().redirect_request(None,None,302,'',{},'https://example.org/')
        class Response(io.BytesIO):
            status=200
            headers={}
        class Opener:
            def open(inner,request,timeout):
                self.assertEqual(request.full_url,catalog.SOURCE)
                self.assertEqual(request.get_method(),'POST')
                self.assertEqual(timeout,30)
                return Response(self.vector)
        with patch.object(catalog,'build_opener',return_value=Opener()):
            self.assertEqual(catalog.download(),self.vector)
        for body,headers in [(b'<html/>',{}),(b'',{}),(self.vector,{'Content-Encoding':'gzip'})]:
            response=Response(body);response.headers=headers
            with patch.object(catalog,'build_opener') as opener:
                opener.return_value.open.return_value=response
                with self.assertRaises(codec.DecodeError): catalog.download()
        with patch.object(catalog,'build_opener') as opener:
            opener.return_value.open.side_effect=HTTPError(catalog.SOURCE,403,'private-sentinel',{},None)
            with self.assertRaises(codec.DecodeError) as error:catalog.download()
            self.assertNotIn('private-sentinel',str(error.exception))

    def test_isolated_worker_forwards_content_key_only(self):
        original=subprocess.Popen;children=[]
        def spawn(*args,**kwargs):
            children.append(kwargs['env']);return original(*args,**kwargs)
        with patch.dict(os.environ,{'CLOUD_WORKER_TOKEN':'private-worker-token'}), patch('subprocess.Popen',side_effect=spawn):
            result=decode_provider_catalog('halcon-r-net',self.vector)
        self.assertEqual(result['structuredJson'],self.expected)
        self.assertEqual(json.loads(result['rawText']),self.expected)
        self.assertFalse(result['isPartial'])
        self.assertEqual(children[0][codec.PASSWORD_ENV],PASSWORD)
        self.assertNotIn(catalog.REQUEST_SECRET_ENV,children[0])
        self.assertNotIn('CLOUD_WORKER_TOKEN',children[0])
        self.assertNotIn(codec.PASSWORD_ENV,_child_env('/tmp/synthetic'))
        with patch.dict(os.environ,{codec.PASSWORD_ENV:''}):
            with self.assertRaises(DecodeFailure):decode_provider_catalog('halcon-r-net',self.vector)

    def test_production_cli_stdin_no_network(self):
        script=ROOT/'decoders/Python/apps/Halcon_R_Net/server_catalog_decoder.py'
        done=subprocess.run([sys.executable,str(script),'--stdin'],input=self.vector,capture_output=True,timeout=10)
        self.assertEqual(done.returncode,0,done.stderr)
        self.assertEqual(json.loads(done.stdout),self.expected)

if __name__=='__main__':unittest.main()
