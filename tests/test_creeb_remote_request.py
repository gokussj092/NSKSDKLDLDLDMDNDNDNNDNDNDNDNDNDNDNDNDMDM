"""Original CREEB50 update flow; synthetic requests only, no real tokens."""
import base64
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch
from urllib.error import HTTPError
from scripts.apk_analysis import creeb_vpn_remote_probe as probe


def request_fixture(token='synthetic-only-token'):
    return {'integrityToken':token,'nonce':base64.urlsafe_b64encode(bytes(16)).decode().rstrip('='),
        'packageName':'com.creebtunnel.vpn','diagnostics':{'eventId':str(uuid.uuid4()),'appVersion':'50.0',
        'appBuild':'50','androidSdk':30,'deviceModel':'Synthetic test','clientStage':'request_sent'}}


class CreebRemoteTests(unittest.TestCase):
    def test_original_preflight_digest_and_server_flag_order(self):
        current=b'current exact ciphertext';digest=hashlib.sha256(current).hexdigest()
        doc={'digest':digest,'bypassActive':True}
        self.assertEqual(probe.preflight(json.dumps(doc).encode(),current),'up-to-date')
        self.assertEqual(probe.preflight(json.dumps(doc).encode(),None),'integrity-required')
        self.assertEqual(probe.preflight(json.dumps(doc).encode(),b'different'),'server-authorized-tokenless')
        doc['bypassActive']=False
        self.assertEqual(probe.preflight(json.dumps(doc).encode(),b'different'),'integrity-required')
        for data in (b'<html>Unavailable</html>',b'{}',b'{"digest":"bad","bypassActive":true}'):
            self.assertEqual(probe.preflight(data,current),'unavailable')

    def test_original_request_file_is_private_and_bytes_token_nonce_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'request.json';raw=json.dumps(request_fixture(),indent=2).encode();p.write_bytes(raw);p.chmod(0o600)
            self.assertEqual(probe.original_request(p,'unavailable'),raw)
            p.chmod(0o644)
            with self.assertRaises(ValueError):probe.original_request(p,'unavailable')

    def test_missing_token_requires_original_failure_or_server_authorization(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'request.json';p.touch(mode=0o600);d=request_fixture('')
            p.write_text(json.dumps(d))
            with self.assertRaises(ValueError):probe.original_request(p,'unavailable')
            self.assertTrue(probe.original_request(p,'server-authorized-tokenless'))
            d['diagnostics'].update(clientStage='token_request_failed',clientFailure='token_request_failed')
            p.write_text(json.dumps(d));self.assertTrue(probe.original_request(p,'unavailable'))
            d['packageName']='wrong.app';p.write_text(json.dumps(d))
            with self.assertRaises(ValueError):probe.original_request(p,'unavailable')

    def test_fixed_get_post_headers_and_http_error_remain_diagnostic(self):
        class Response:
            status=200;headers={'Content-Type':'text/plain'}
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,limit):self.limit=limit;return b'response'
        class Opener:
            def open(self,request,timeout):self.request=request;self.timeout=timeout;return Response()
        for body,accept,timeout in ((None,'application/json',15),(b'{}','text/plain, application/json, */*',60)):
            opener=Opener()
            with patch.object(probe,'build_opener',return_value=opener):
                data,report=probe.exchange(body)
            self.assertEqual(opener.request.full_url,probe.URL)
            self.assertEqual(opener.request.get_header('Accept'),accept)
            self.assertEqual(opener.request.get_header('User-agent'),'CREEB-VPN-Android')
            self.assertEqual(opener.timeout,timeout);self.assertEqual(data,b'response')
            self.assertEqual(opener.request.get_header('Content-type'),'application/json; charset=utf-8' if body else None)
        self.assertIsNone(probe.NoRedirect().redirect_request())

    def test_explicit_offline_failure_never_claims_android_attestation(self):
        d=json.loads(probe.offline_failure_request())
        self.assertEqual(d['integrityToken'],'');self.assertEqual(d['diagnostics']['androidSdk'],0)
        self.assertEqual(len(base64.urlsafe_b64decode(d['nonce']+'==')),16)
        self.assertEqual(d['diagnostics']['clientStage'],'token_request_failed')

    def test_html_200_never_creates_json_or_claims_catalog_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'must-not-exist.json';out=io.StringIO();html=b'<html>Unavailable</html>'
            meta={'method':'GET','status':200,'bytes':len(html),'contentType':'text/html'}
            with patch.object(probe.sys,'argv',['probe','--empty-token-post','--catalog-output',str(target)]), \
                 patch.object(probe,'exchange',side_effect=[(html,meta),(html,{**meta,'method':'POST'})]),redirect_stdout(out):
                self.assertEqual(probe.main(),1)
            report=json.loads(out.getvalue());self.assertFalse(report['catalogValid']);self.assertFalse(target.exists())
            self.assertNotIn('synthetic-only-token',out.getvalue())

    def test_original_fresh_request_download_keeps_complete_synthetic_catalog(self):
        fixtures=json.loads((Path(__file__).parent/'golden/creeb_vpn_vectors.json').read_text())
        row=next(r for r in fixtures['documents'] if r['name']=='catalog');raw=row['cipher'].encode()
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'request.json';p.write_text(json.dumps(request_fixture()));p.chmod(0o600)
            target=Path(tmp)/'complete.json';out=io.StringIO()
            with patch.object(probe.sys,'argv',['probe','--request-file',str(p),'--catalog-output',str(target)]), \
                 patch.object(probe,'exchange',side_effect=[(b'<html/>',{'status':200}),(raw,{'status':200})]),redirect_stdout(out):
                self.assertEqual(probe.main(),0)
            self.assertEqual(json.loads(target.read_text()),row['expected'])
            self.assertEqual(target.stat().st_mode&0o777,0o600)
            self.assertTrue(json.loads(out.getvalue())['catalogValid'])
            self.assertNotIn('synthetic-only-token',out.getvalue())


if __name__=='__main__':unittest.main()
