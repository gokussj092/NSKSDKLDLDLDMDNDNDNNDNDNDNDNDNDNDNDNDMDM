"""Synthetic JCA vectors and signed updater boundaries; no live credentials."""
import base64,json,os,subprocess,sys,unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from decoders.Python.apps.ALFAISAL_Tunnel_Plus import codec,server_catalog_decoder as catalog
ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'decoders/Python/apps/ALFAISAL_Tunnel_Plus'
V=json.loads((ROOT/'tests/golden/alfaisal_vectors.json').read_text())
R=V['request'];ENV=dict(zip(catalog.ENV_NAMES,(R['apiKey'],R['signingKey'],R['deviceUuid'])))

def jca(mode,values):
    lines=''.join(str(mode)+'\t'+base64.b64encode(v.encode()).decode()+'\n' for v in values)
    p=subprocess.run(['java',str(ROOT/'tests/golden/alfaisal_oracle.java')],input=lines,text=True,capture_output=True,check=True,timeout=30)
    return [base64.b64decode(x) for x in p.stdout.splitlines()]

def seal(doc):return jca(1,[json.dumps(doc)])[0]

class Response:
    def __init__(self,data):self.data=data;self.status=200;self.headers={}
    def __enter__(self):return self
    def __exit__(self,*a):pass
    def read(self,limit):return self.data[:limit]

class AlfaisalTests(unittest.TestCase):
    def test_independent_jca_recreates_golden_cipher_fields_and_fallback(self):
        self.assertEqual([x.decode() for x in jca(1,V['plain'])],V['cipher'])
        self.assertEqual([x.decode() for x in jca(2,V['cipher']+[V['legacyProxy']])],V['plain']+[V['legacyProxy']])
        self.assertEqual(codec.decode_catalog(V['catalog'].encode()),V['expected'])
        self.assertEqual(json.loads(catalog.run(V['catalog'].encode())),V['expected'])

    def test_hmac_uses_exact_utf8_text_key_and_body_bytes_from_jca(self):
        body,headers=catalog.signed_request(R['apiKey'],R['signingKey'],R['deviceUuid'],timestamp=R['timestamp'],nonce=R['nonce'])
        self.assertEqual(body,R['body'].encode());self.assertEqual(headers['X-SIGNATURE'],R['signature'])
        self.assertEqual(jca(3,['\t'.join([R['signingKey'],str(R['timestamp']),R['nonce'],R['body']])])[0].decode(),R['signature'])

    def test_three_lists_unknown_values_and_legacy_proxy_are_preserved(self):
        d=codec.decode_catalog(V['catalog'].encode())
        self.assertEqual(d['Servers'][0]['UnknownCipher'],V['cipher'][0]);self.assertEqual(d['unknown'],V['expected']['unknown'])
        self.assertEqual(d['SSLNetworks'][0]['ProxySettings']['Squid'],V['legacyProxy'])
        self.assertIs(type(d['Networks'][0]['Protocol']),int)
        d=V['outer'].copy();d['Networks']=[]
        self.assertEqual(codec.decode_catalog(seal(d))['SSLNetworks'],V['expected']['SSLNetworks'])

    def test_complete_worker_and_historical_file_inventory(self):
        from cloud.workers.python.engine import decode_provider_catalog,load_runtime_file_engines
        result=decode_provider_catalog('alfaisal-tunnel-plus',V['catalog'].encode())
        self.assertEqual(result['structuredJson'],V['expected']);self.assertEqual(json.loads(result['rawText']),V['expected'])
        self.assertFalse(result['isPartial']);self.assertFalse(result['exporterCertified'])
        self.assertEqual(len(load_runtime_file_engines()),267)
        self.assertNotIn('js',load_runtime_file_engines())

    def test_invalid_outer_and_known_field_types_reject_the_whole_document(self):
        for raw in (b'',b'<html/>',b'private-sentinel',V['catalog'][:-8].encode()):
            with self.assertRaises(codec.DecodeError) as e:catalog.run(raw)
            self.assertNotIn('private-sentinel',str(e.exception))
        bad=[]
        for key,value in [('Servers',[]),('SSLNetworks',None),('Version',True)]:
            d=json.loads(json.dumps(V['outer']));d[key]=value;bad.append(d)
        for value in (False,'not-base64!'):
            d=json.loads(json.dumps(V['outer']));d['SSLNetworks'][0]['Payload']=value;bad.append(d)
        for raw in jca(1,[json.dumps(d) for d in bad]+['{"Version":"a","Version":"b"}']):
            with self.assertRaises(codec.DecodeError):catalog.run(raw)

    def test_size_depth_and_output_limits(self):
        with self.assertRaises(codec.DecodeError):catalog.run(b'x'*(codec.MAX_BYTES+1))
        d=V['outer'].copy();node=[]
        for _ in range(66):node=[node]
        d['unknown']=node
        with self.assertRaises(codec.DecodeError):catalog.run(seal(d))
        with self.assertRaises(codec.DecodeError):codec.render({'x':'x'*codec.MAX_BYTES})

    def test_missing_secrets_fail_before_transport(self):
        with patch.dict(os.environ,{},clear=True),patch.object(catalog,'build_opener',side_effect=AssertionError('network')):
            with self.assertRaises(codec.DecodeError):catalog.download()

    def test_signed_metadata_then_post_without_registering_or_retrying(self):
        calls=[]
        class Opener:
            def open(self,request,timeout):
                calls.append(request)
                if len(calls)==1:
                    self_url=request.full_url
                    assert self_url.startswith(catalog.METADATA+'?json_client_capability=2&device_uuid=')
                    assert request.get_method()=='GET' and timeout==10
                    assert request.get_header('X-api-key') is None
                    return Response(b'{"success":true,"json_requires_integrity":false}')
                assert request.full_url==catalog.SOURCE and request.get_method()=='POST' and timeout==20
                assert request.data==R['body'].encode()
                assert request.get_header('X-signature')==R['signature']
                return Response(V['catalog'].encode())
        with patch.dict(os.environ,ENV),patch.object(catalog,'build_opener',return_value=Opener()),patch.object(catalog.time,'time',return_value=R['timestamp']),patch.object(catalog.secrets,'token_hex',return_value=R['nonce']):
            self.assertEqual(catalog.download(),V['catalog'].encode())
        self.assertEqual(len(calls),2)

    def test_integrity_policy_failure_never_sends_post_or_fabricates_token(self):
        for meta in (b'{"json_requires_integrity":true}',b'{"success":false,"json_requires_integrity":false}',b'{}',b'<html/>'):
            calls=[]
            class Opener:
                def open(self,r,timeout):calls.append(r);return Response(meta)
            with patch.dict(os.environ,ENV),patch.object(catalog,'build_opener',return_value=Opener()):
                with self.assertRaises(codec.DecodeError):catalog.download()
            self.assertEqual(len(calls),1)

    def test_redirect_and_upstream_failures_are_sanitized(self):
        with self.assertRaises(codec.DecodeError):catalog._NoRedirect().redirect_request(None,None,None,None,None,None)
        calls=[]
        class Opener:
            def open(self,r,timeout):
                calls.append(r)
                if len(calls)==1:return Response(b'{"json_requires_integrity":false}')
                raise HTTPError(catalog.SOURCE,503,'private-sentinel',{},None)
        with patch.dict(os.environ,ENV),patch.object(catalog,'build_opener',return_value=Opener()):
            with self.assertRaises(codec.DecodeError) as e:catalog.download()
            self.assertNotIn('private-sentinel',str(e.exception))
        self.assertEqual(len(calls),2)

    def test_cli_outside_checkout_matches_full_document(self):
        r=subprocess.run([sys.executable,str(APP/'server_catalog_decoder.py'),'--stdin'],input=V['catalog'].encode(),capture_output=True,cwd='/tmp',timeout=30)
        self.assertEqual(r.returncode,0);self.assertEqual(r.stderr,b'');self.assertEqual(json.loads(r.stdout),V['expected'])

if __name__=='__main__':unittest.main()
