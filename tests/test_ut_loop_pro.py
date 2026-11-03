"""Focused JDK parity, authentication, complete JSON and isolated worker checks."""
import base64
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from decoders.Python.apps.UT_Loop_Pro_VPN import codec, server_catalog_decoder as catalog
from cloud.workers.python.catalog_vpn_bridge import decode
from cloud.workers.python.engine import decode_provider_catalog

ROOT=Path(__file__).resolve().parents[1]


class UTLoopSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v=json.loads((ROOT/'tests/golden/ut_loop_pro_vectors.json').read_text())
        cls.raw=cls.v['cached'].encode()

    def test_complete_jdk_cache_cli_and_isolated_worker(self):
        expected=self.v['expected']
        self.assertEqual(json.loads(catalog.run(self.raw)),expected)
        self.assertEqual(json.loads(decode('ut-loop-pro-vpn',self.raw)),expected)
        result=decode_provider_catalog('ut-loop-pro-vpn',self.raw)
        self.assertEqual(result['structuredJson'],expected)
        self.assertEqual(json.loads(result['rawText']),expected)
        self.assertFalse(result['isPartial'])
        script=ROOT/'decoders/Python/apps/UT_Loop_Pro_VPN/server_catalog_decoder.py'
        r=subprocess.run([sys.executable,str(script),'--stdin'],input=self.raw,cwd='/tmp',capture_output=True,check=True)
        self.assertEqual(json.loads(r.stdout),expected)

    def test_rsa_gcm_schema_and_limits_fail_closed(self):
        signed=json.dumps(self.v['signed']).encode()
        with self.assertRaises(codec.DecodeError):codec.decode_catalog(signed)
        with patch.object(codec,'SIGNATURE_PUBLIC_KEY',base64.b64decode(self.v['testPublicKey'])):
            self.assertEqual(codec.decode_catalog(signed,require_signature=True),self.v['expected'])
            wrong_sig=dict(self.v['signed']);wrong_sig['data']+='\n'
            bad=[json.dumps(wrong_sig).encode(),json.dumps(self.v['badTagSigned']).encode(),
                 json.dumps(self.v['badSchemaSigned']).encode(),b'{"data":"x","data":"y","sig":"x"}',
                 b'',b'<html>Site Unavailable</html>',b'x'*(codec.MAX_BYTES+1),self.raw[:-5]]
            for raw in bad:
                with self.subTest(length=len(raw)),self.assertRaises(codec.DecodeError):catalog.run(raw)
        with self.assertRaises(codec.DecodeError):codec.decode_catalog(self.raw,require_signature=True)

    def test_jdk_banners_both_certificates_and_custom_delta(self):
        for raw in self.v['banners']+[self.v['legacyBanner']]:
            self.assertEqual(codec.decode_banner(raw.encode()),self.v['bannerExpected'])
        raw=self.v['banners'][0].replace('title="','title="A',1)
        for invalid in [raw.encode(),b'no quoted banner',b'<div title="AAAA">x</div>']:
            with self.assertRaises(codec.DecodeError):codec.decode_banner(invalid)
        script=ROOT/'decoders/Python/apps/UT_Loop_Pro_VPN/banner_decoder.py'
        r=subprocess.run([sys.executable,str(script)],input=self.v['legacyBanner'].encode(),cwd='/tmp',capture_output=True,check=True)
        self.assertEqual(r.stdout.decode(),self.v['bannerExpected'])

    def test_fixed_official_requests_credentials_and_remote_signature_required(self):
        requests=[]
        class Reply:
            status=200
            headers={}
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,limit):return json.dumps(self_outer.v['signed']).encode()
        class Opener:
            def open(self,request,timeout):requests.append(request);return Reply()
        self_outer=self
        with patch.object(catalog,'build_opener',return_value=Opener()),patch.object(codec,'SIGNATURE_PUBLIC_KEY',base64.b64decode(self.v['testPublicKey'])):
            catalog.download()
            self.assertEqual(json.loads(catalog.run(catalog.download(access='test-access',iid='test-iid'))),self.v['expected'])
            catalog.download(entitlement='test-entitlement')
        self.assertEqual(requests[0].full_url,catalog.CATALOG_URL)
        self.assertEqual(requests[0].get_method(),'GET')
        self.assertIsNone(requests[0].get_header('X-ota-access'))
        self.assertIsNone(requests[0].get_header('X-ota-iid'))
        self.assertEqual(requests[0].get_header('User-agent'),'Dalvik/2.1.0')
        self.assertEqual(requests[0].get_header('X-api-key'),catalog.API_KEY)
        self.assertEqual(requests[1].get_header('X-ota-access'),'test-access')
        self.assertEqual(requests[1].get_header('X-ota-iid'),'test-iid')
        self.assertEqual(requests[2].full_url,catalog.PREMIUM_URL)
        self.assertEqual(json.loads(requests[2].data),{'packageName':'loop.uchetechs.vpn.pro','entitlement':'test-entitlement'})
        self.assertEqual(requests[2].get_method(),'POST')
        with patch.object(catalog,'build_opener') as opener:
            for kwargs in [{'access':'x'},{'iid':'y'},{'access':'x\n','iid':'y'},
                           {'access':'','iid':'y'},{'entitlement':''},
                           {'access':'x','iid':'y','entitlement':'z'},{'user_agent':'invalid\nagent'}]:
                with self.assertRaises(codec.DecodeError):catalog.download(**kwargs)
            opener.assert_not_called()
        with self.assertRaises(codec.DecodeError):catalog._NoRedirect().redirect_request(None,None,None,None,None,None)

    def test_remote_html_unsigned_data_auth_and_network_errors_are_distinct(self):
        class Reply:
            status=200
            headers={}
            data=b''
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,limit):return self.data
        for data,headers,code in [
            (b'<html>Site Unavailable</html>',{'Content-Type':'text/html'},'REMOTE_HTML_RESPONSE'),
            (self.raw,{},'REMOTE_SIGNATURE_OR_CATALOG_INVALID'),
            (b'',{},'REMOTE_SIZE_INVALID'),
            (b'x'*(codec.MAX_BYTES+1),{},'REMOTE_SIZE_INVALID'),
            (b'encoded',{'Content-Encoding':'gzip'},'REMOTE_ENCODING_INVALID'),
        ]:
            response=Reply();response.data=data;response.headers=headers
            with patch.object(catalog,'build_opener') as opener:
                opener.return_value.open.return_value=response
                with self.assertRaises(catalog.RemoteError) as caught:catalog.download()
                self.assertEqual(caught.exception.code,code)
                self.assertEqual(caught.exception.observation['bytes'],len(data))
        with patch.object(catalog,'build_opener') as opener:
            opener.return_value.open.side_effect=HTTPError(catalog.CATALOG_URL,401,'private upstream message',{},io.BytesIO(b'private body'))
            with self.assertRaises(catalog.RemoteError) as caught:catalog.download()
            self.assertEqual(caught.exception.code,'REMOTE_AUTH_REJECTED')
            self.assertEqual(caught.exception.observation['httpStatus'],401)
            self.assertNotIn('private',str(caught.exception))
            opener.return_value.open.side_effect=OSError('private network details')
            with self.assertRaises(catalog.RemoteError) as caught:catalog.download()
            self.assertEqual(caught.exception.code,'REMOTE_NETWORK_ERROR')

    def test_probe_reports_metadata_without_catalog_values_or_credentials(self):
        signed=json.dumps(self.v['signed']).encode()
        output=io.StringIO()
        with patch.object(sys,'argv',['catalog','--probe']),patch.object(catalog,'download',return_value=signed), \
             patch.object(codec,'SIGNATURE_PUBLIC_KEY',base64.b64decode(self.v['testPublicKey'])),contextlib.redirect_stdout(output):
            self.assertEqual(catalog.main(),0)
        report=json.loads(output.getvalue())
        self.assertTrue(report['remoteSignatureVerified'])
        self.assertNotIn('Servers',report)
        self.assertEqual(report['sections']['Servers'],len(self.v['expected']['Servers']))
        self.assertNotIn(catalog.API_KEY,output.getvalue())
        output=io.StringIO()
        with patch.object(sys,'argv',['catalog','--probe']),patch.object(catalog,'download',side_effect=
             catalog.RemoteError('REMOTE_HTML_RESPONSE',{'httpStatus':200,'bytes':195})),contextlib.redirect_stdout(output):
            self.assertEqual(catalog.main(),1)
        self.assertEqual(json.loads(output.getvalue()),{'status':'error','code':'REMOTE_HTML_RESPONSE','httpStatus':200,'bytes':195})


if __name__=='__main__':unittest.main()
