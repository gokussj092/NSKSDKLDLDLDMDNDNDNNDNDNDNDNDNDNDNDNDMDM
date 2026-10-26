"""MNR build 31: JDK-derived whole documents, online references and isolated routes."""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from decoders.Python.apps.MNR_TUNNEL_PLUS import codec
from scripts.apk_analysis.mnr_verify import oracle, reference

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'cloud/workers/python'))


def seal(text, mode='profile'):
    return oracle([('seal-'+mode,text.encode())])[0]


class MnrTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fields=oracle([('seal-field',v.encode()) for v in ('host.example.invalid','GET / HTTP/1.1\r\n中 ñ 😀\r\n','')])
        cls.field_values=[x.decode() for x in fields]
        cls.catalog={'Version':'synthetic','Servers':[{'Name':'Server ñ',**{k:cls.field_values[0] for k in codec.SERVER_FIELDS},
            'ServerPort':'443','unknown':{'keep':[True,None,1]},'FLAG':'test','id':'0123456789abcdef'}],
            'Networks':[{'Name':'Network 😀',**{k:cls.field_values[1] for k in codec.NETWORK_FIELDS},
                'wsPayload':True,'wsProxyPayload':False,'ProxyPort':'8080','unknownCipher':cls.field_values[0]}],
            'ReleaseNotes':'keep','UseTimer':True,'Other':{'unknown':['x',False]}}
        cls.catalog_data=seal(json.dumps(cls.catalog,ensure_ascii=False),'catalog')
        cls.expected=json.loads(json.dumps(cls.catalog))
        for row in cls.expected['Servers']:
            for key in codec.SERVER_FIELDS:row[key]='host.example.invalid'
        for row in cls.expected['Networks']:
            for key in codec.NETWORK_FIELDS:row[key]='GET / HTTP/1.1\r\n中 ñ 😀\r\n'
        cls.profiles=[{'http_p':'proxy.example.invalid:80','ssl_h':'sni.example.invalid','v2_c':'vless://synthetic',
            'udp_s':'host:443','TunnelType':6,'isPassON':False,'MyPass':'','DeviceID':'','ExpireDate':0,
            'useCustomProxy':True,'isMsg':True,'Message':'ñ 😀','unknown':{'a':[True,None,0]}},
            {'CPayload':'GET / HTTP/1.1\r\n','ServerUser':'synthetic-user','ServerPass':'synthetic-pass',
             'V2Ray':'vmess://synthetic','UdpServer':'synthetic:443','TunnelType':7,'isPassON':True,
             'MyPass':'synthetic-lock','DeviceID':'synthetic-device','ExpireDate':1,'unknown':{'keep':'all'}}]
        cls.profile_data=oracle([('seal-profile',json.dumps(obj,ensure_ascii=False).encode()) for obj in cls.profiles])

    def test_complete_catalog_and_all_field_slots_equal_jdk(self):
        actual=codec.decode_catalog(self.catalog_data)
        self.assertEqual(actual,self.expected)
        expected,count=reference(self.catalog_data)
        self.assertEqual(actual,expected)
        self.assertEqual(count,21)
        self.assertIs(actual['Networks'][0]['wsPayload'],True)
        self.assertEqual(actual['Networks'][0]['unknownCipher'],self.field_values[0])

    def test_unicode_cipher_digits_are_preserved_without_stripping(self):
        value=self.field_values[1]
        self.assertTrue(value[0].isspace())
        self.assertEqual(codec.decrypt_layer(value,codec.FIELD_SECRET,codec.FIELD_ALPHABET),'GET / HTTP/1.1\r\n中 ñ 😀\r\n')
        with self.assertRaises(ValueError):codec.decrypt_layer(value.strip(),codec.FIELD_SECRET,codec.FIELD_ALPHABET)
        self.assertEqual(codec.decrypt_layer(self.field_values[2],codec.FIELD_SECRET,codec.FIELD_ALPHABET),'')

    def test_local_and_cloud_profile_schemas_keep_password_hwid_and_expiration(self):
        for data,expected in zip(self.profile_data,self.profiles):
            self.assertEqual(codec.decode_profile(data),expected)
            self.assertEqual(reference(data,True)[0],expected)
        self.assertEqual(codec.decode_profile(self.profile_data[1])['MyPass'],'synthetic-lock')

    def test_malformed_layers_schemas_unicode_and_resource_limits_fail(self):
        for data in (b'',b'bad',self.profile_data[0][:-3],b'abc.def.ghi',b'X'*(codec.MAX_BYTES+1)):
            with self.assertRaises(ValueError):codec.decode_profile(data)
        bad=['{"TunnelType":1,"TunnelType":2}', '{"x":NaN}', '{"x":1e999}',
             '{"x":"\\ud800"}', '[]', '{"Version":"1","Servers":{},"Networks":[]}',
             '{"Version":"1","Servers":[{}],"Networks":[]}',
             json.dumps({'Version':'1','Servers':[{'Name':'x','ServerIP':True}],'Networks':[]})]
        sealed=oracle([('seal-catalog',text.encode()) for text in bad])
        for data in sealed:
            with self.assertRaises(ValueError):codec.decode_catalog(data)
        with self.assertRaises(ValueError):codec.decode_profile(self.catalog_data)
        with self.assertRaises(ValueError):codec.decode_catalog(self.profile_data[0])
        with self.assertRaises(ValueError):codec.render({'x':'x'*codec.MAX_BYTES})
        nested={};value=nested
        for _ in range(66):value['x']={};value=value['x']
        with self.assertRaises(ValueError):codec.render(nested)

    def test_workers_return_entire_file_text_and_catalog_without_network(self):
        from cloud.workers.python.engine import decode_file,decode_text,decode_provider_catalog
        result=decode_provider_catalog('mnr-tunnel-plus',self.catalog_data)
        self.assertEqual(result['structuredJson'],self.expected);self.assertFalse(result['isPartial'])
        for data,expected in zip(self.profile_data,self.profiles):
            for result in (decode_file('stp',data),decode_text(data.decode())):
                self.assertEqual(result['structuredJson'],expected)
                self.assertEqual(json.loads(result['rawText']),expected)
                self.assertFalse(result['isPartial'])

    def test_reference_normalization_and_fixed_metadata_media_flow(self):
        key='AbC123xyZ0';url=codec.reference_url('mnrtunneludp://'+key)
        self.assertTrue(url.endswith('/o/mnrtunneludp%3A%2FAbC123xyZ0.sky'))
        self.assertEqual(url,codec.reference_url(key))
        metadata={'name':'mnrtunneludp:/'+key+'.sky','bucket':codec.BUCKET,'downloadTokens':'synthetic-token,second'}
        calls=[]
        def download(address,limit=codec.MAX_BYTES):
            calls.append((address,limit))
            return json.dumps(metadata).encode() if len(calls)==1 else self.profile_data[1]
        with patch.object(codec,'_download',side_effect=download):
            self.assertEqual(codec.decode_profile(codec.download_profile(key)),self.profiles[1])
        self.assertEqual(calls,[(url,256*1024),(url+'?alt=media&token=synthetic-token',codec.MAX_BYTES)])
        for invalid in ('../x','https://127.0.0.1/private','mnrtunneludp://'+key+'/extra',key+'.sky',key+'?x=y'):
            with self.assertRaises(ValueError):codec.reference_url(invalid)
        for bad in ({**metadata,'bucket':'attacker.invalid'},{**metadata,'name':'other.sky'},
                    {**metadata,'downloadTokens':'token&url=evil'},{}):
            with patch.object(codec,'_download',return_value=json.dumps(bad).encode()) as call:
                with self.assertRaises(ValueError):codec.download_profile(key)
                self.assertEqual(call.call_count,1)

    def test_download_transport_bounds_redirect_and_fixed_catalog_source(self):
        class Response:
            status=200;headers={}
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def read(self,n):return self.catalog_data[:n]
        response=Response();response.catalog_data=self.catalog_data
        class Opener:
            def open(self,request,timeout):
                self.seen=(request.full_url,timeout,request.headers)
                return response
        opener=Opener()
        with patch.object(codec,'build_opener',return_value=opener):
            self.assertEqual(codec.download_catalog(),self.catalog_data)
            self.assertEqual(opener.seen[0],codec.CATALOG_URL);self.assertEqual(opener.seen[1],25)
            response.headers={'Content-Encoding':'gzip'}
            with self.assertRaises(ValueError):codec.download_catalog()
            response.headers={};response.catalog_data=b'x'*(codec.MAX_BYTES+1)
            with self.assertRaises(ValueError):codec.download_catalog()
        with self.assertRaises(ValueError):codec._NoRedirect().redirect_request(None,None,302,'',{},'https://example.invalid')

    def test_cli_standalone_private_output_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);script=root/'mnr_tunnel_plus.py'
            shutil.copyfile(ROOT/'decoders/Python/apps/MNR_TUNNEL_PLUS/codec.py',script)
            env={k:v for k,v in os.environ.items() if k!='PYTHONPATH'}
            for index,(flag,data,expected) in enumerate([('--input',self.catalog_data,self.expected),
                ('--file',self.profile_data[0],self.profiles[0]),('--file',self.profile_data[1],self.profiles[1])]):
                incoming=root/f'input-{index}';incoming.write_bytes(data);output=root/f'result-{index}.json'
                argv=[sys.executable,str(script),flag,str(incoming),'--output',str(output)]
                result=subprocess.run(argv,cwd=folder,env=env,capture_output=True,timeout=15)
                self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(json.loads(output.read_bytes()),expected)
                self.assertEqual(output.stat().st_mode&0o777,0o600)
                again=subprocess.run(argv,cwd=folder,env=env,capture_output=True,timeout=15)
                self.assertEqual(again.returncode,1);self.assertEqual(json.loads(output.read_bytes()),expected)
            result=subprocess.run([sys.executable,str(script),'--text',self.profile_data[1].decode(),'--summary'],
                cwd=folder,env=env,capture_output=True,timeout=15)
            self.assertEqual(result.returncode,0);self.assertEqual(json.loads(result.stdout),{'kind':'profile'})

    def test_registries_leave_frozen_android_routes_unchanged(self):
        from spdecode.registry import get_decoder,get_supported_extension
        from cloud.workers.python.engine import load_file_engines,load_runtime_file_engines
        self.assertEqual(get_supported_extension('Synthetic.STP'),'stp')
        self.assertTrue(get_decoder('stp').script.endswith('/MNR_TUNNEL_PLUS/file_decoder.py'))
        self.assertNotIn('stp',load_file_engines());self.assertEqual(len(load_file_engines()),240)
        self.assertIn('stp',load_runtime_file_engines())
        self.assertNotIn('sft',load_runtime_file_engines())


if __name__=='__main__':unittest.main()
