"""TunelGuard 12.8 independent full-document, CLI and isolated Cloud regression."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from decoders.Python.apps.TunelGuard_VPN import codec, file_decoder as files, server_catalog_decoder as catalog
ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'decoders/Python/apps/TunelGuard_VPN'
V=json.loads((ROOT/'tests/golden/tunelguard_vectors.json').read_text())

def wrap_catalog(obj):
    nonce=bytes(range(12));c=AES.new(codec.CATALOG_KEY,AES.MODE_GCM,nonce=nonce);c.update(codec.PREFIX)
    raw,tag=c.encrypt_and_digest((obj if isinstance(obj,str) else json.dumps(obj)).encode())
    return codec.PREFIX+base64.urlsafe_b64encode(nonce).rstrip(b'=')+b'.'+base64.urlsafe_b64encode(raw+tag).rstrip(b'=')

def wrap_file(obj):
    iv=bytes(range(16));raw=(obj if isinstance(obj,str) else json.dumps(obj)).encode()
    return base64.b64encode(iv+AES.new(codec.FILE_KEY,AES.MODE_CBC,iv).encrypt(pad(raw,16)))

class TunelGuardTests(unittest.TestCase):
    def test_full_catalog_and_utf8_message_preserve_sections_unknowns_and_types(self):
        with patch.object(catalog,'download',side_effect=AssertionError('network')):
            self.assertEqual(json.loads(catalog.run(V['catalog'].encode())),V['expectedCatalog'])
        self.assertEqual(codec.decode_catalog(V['utf8Catalog'].encode()),V['expectedUtf8Catalog'])
        self.assertEqual([len(codec.NAMES[k]) for k in ['servers','tweaks','profile']],[32,8,16])

    def test_full_profile_modified_utf8_and_embedded_server_preserve_lock_metadata(self):
        result=json.loads(files.run(V['profile'].encode()))
        self.assertEqual(result,V['expectedProfile']);p=result['TGV_CONFIG']
        self.assertEqual(p['MyPass'],'synthetic-password');self.assertEqual(p['DeviceID'],'synthetic-hwid')
        self.assertIs(p['isPassON'],True);self.assertIsInstance(p['Server'],str)
        self.assertEqual(json.loads(p['Server']),V['expectedCatalog']['Servers'][0])
        for name in codec.NAMES['profile']:self.assertIn('🙂 漢',p[name])

    def test_catalog_tag_nonce_ciphertext_and_prefix_tampering_never_retry_cbc(self):
        parts=V['catalog'].encode().split(b'.');bad=[V['catalog'].replace('STGCM2.TG.','STGCM2.X.').encode()]
        for part in [2,3]:
            original=base64.urlsafe_b64decode(parts[part]+b'='*(-len(parts[part])%4))
            for pos in [0,len(original)-1]:
                raw=bytearray(original);raw[pos]^=1;p=parts.copy();p[part]=base64.urlsafe_b64encode(raw).rstrip(b'=');bad.append(b'.'.join(p))
        for payload in bad:
            with patch.object(codec,'decode_profile',side_effect=AssertionError('fallback')):
                with self.assertRaises(codec.DecodeError):catalog.run(payload)

    def test_catalog_json_duplicates_nonfinite_depth_and_invalid_fields_fail_closed(self):
        for text in ['{"version":"x","version":"y","Servers":[],"Tweaks":[]}',
            '{"version":"x","Servers":[null],"Tweaks":[]}',
            '{"version":"x","Servers":[],"Tweaks":[],"a":NaN}',
            '{"version":"x","Servers":[],"Tweaks":[],"a":1e999}',
            '{"version":"x","Servers":[],"Tweaks":[],"message":"u8:!"}']:
            with self.assertRaises(codec.DecodeError):catalog.run(wrap_catalog(text))
        obj=json.loads(json.dumps(V['catalogWire']));obj['Servers'][0]['SSHHost']=['private-invalid-input']
        with self.assertRaises(codec.DecodeError) as e:catalog.run(wrap_catalog(obj))
        self.assertNotIn('private-invalid-input',str(e.exception))
        obj=V['catalogWire'].copy();obj['unknown']=[0]
        for _ in range(65):obj['unknown']=[obj['unknown']]
        with self.assertRaises(codec.DecodeError):catalog.run(wrap_catalog(obj))

    def test_empty_nullable_fields_are_preserved_without_app_defaults(self):
        obj=json.loads(json.dumps(V['catalogWire']));obj['Servers'][0].update(SSHHost='',WireGuardDetails=None)
        result=codec.decode_catalog(wrap_catalog(obj))['Servers'][0]
        self.assertEqual(result['SSHHost'],'');self.assertIsNone(result['WireGuardDetails'])
        obj=json.loads(json.dumps(V['profileWire']));obj['TGV_CONFIG'].update(Server='',Payload='')
        result=codec.decode_profile(wrap_file(obj))['TGV_CONFIG'];self.assertEqual(result['Server'],'');self.assertEqual(result['Payload'],'')

    def test_cbc_padding_profile_schema_and_inner_encodings_reject_corruption(self):
        raw=bytearray(base64.b64decode(V['profile']));raw[-1]^=1
        for payload in [base64.b64encode(raw),b'bad',b'AAAA',wrap_file('{}'),wrap_file({'TGV_CONFIG':{'TunnelType':True}})]:
            with self.assertRaises(codec.DecodeError):files.run(payload)
        for key,value in [('Payload','!'),('Server','{bad}'),('Server',False)]:
            obj=json.loads(json.dumps(V['profileWire']));obj['TGV_CONFIG'][key]=value
            with self.assertRaises(codec.DecodeError):files.run(wrap_file(obj))

    def test_limits_reject_complete_oversize_documents(self):
        for run,limit in [(files.run,codec.MAX_FILE_BYTES),(catalog.run,codec.MAX_BYTES)]:
            for data in [b'',b'x'*(limit+1)]:
                with self.assertRaises(codec.DecodeError):run(data)
        with self.assertRaises(codec.DecodeError):codec.render({'x':'x'*codec.MAX_BYTES})

    def test_fixed_download_fails_on_404_redirects_html_or_compression(self):
        self.assertEqual(catalog.CATALOG_URL,'https://raw.githubusercontent.com/eddyme23/octo/refs/heads/main/xxTG.js')
        class Response:
            status=200;headers={};data=V['catalog'].encode()
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,size):return self.data[:size]
        with patch.object(catalog,'build_opener') as op:
            op.return_value.open.return_value=Response();self.assertEqual(catalog.download(),V['catalog'].encode())
            self.assertEqual(op.return_value.open.call_args.args[0].full_url,catalog.CATALOG_URL)
            for data in [b'',b'<html>404</html>',b'x'*(codec.MAX_BYTES+1)]:
                with patch.object(Response,'data',data),self.assertRaises(codec.DecodeError):catalog.download()
            with patch.object(Response,'status',404),self.assertRaises(codec.DecodeError):catalog.download()
            with patch.object(Response,'headers',{'Content-Encoding':'gzip'}),self.assertRaises(codec.DecodeError):catalog.download()
            op.return_value.open.side_effect=HTTPError(catalog.CATALOG_URL,404,'Not Found',{},None)
            with self.assertRaises(codec.DecodeError):catalog.download()
        with self.assertRaises(codec.DecodeError):catalog._NoRedirect().redirect_request(None,None,302,'',{},'https://example.invalid')

    def test_real_isolated_file_and_catalog_routes_preserve_complete_json(self):
        sys.path.insert(0,str(ROOT/'cloud/workers/python'))
        from engine import decode_file,decode_provider_catalog,load_file_engines,load_runtime_file_engines
        self.assertEqual(len(load_file_engines()),240);self.assertEqual(load_runtime_file_engines()['tgv']['name'],'TunelGuard VPN 12.8')
        for result,expected in [(decode_file('tgv',V['profile'].encode()),V['expectedProfile']),
            (decode_provider_catalog('tunelguard-vpn',V['catalog'].encode()),V['expectedCatalog'])]:
            self.assertEqual(result['structuredJson'],expected);self.assertFalse(result['isPartial'])

    def test_cli_stdin_and_files_from_outside_repo_and_private_error_sanitization(self):
        env={k:v for k,v in os.environ.items() if k!='PYTHONPATH'}
        with tempfile.TemporaryDirectory() as d:
            for script,key,expected in [('file_decoder.py','profile','expectedProfile'),('server_catalog_decoder.py','catalog','expectedCatalog')]:
                source=Path(d)/'sample.enc';source.write_text(V[key]);stdin=[] if script=='file_decoder.py' else ['--stdin']
                for flags in [[str(source)],stdin]:
                    p=subprocess.run([sys.executable,str(APP/script),*flags],input=V[key].encode(),capture_output=True,cwd=d,env=env,timeout=10)
                    self.assertEqual(p.returncode,0,p.stderr.decode());self.assertEqual(json.loads(p.stdout),V[expected])
                p=subprocess.run([sys.executable,str(APP/script),*stdin],input=b'private-invalid-input',capture_output=True,cwd=d,env=env,timeout=10)
                self.assertNotEqual(p.returncode,0);self.assertFalse(p.stdout);self.assertNotIn(b'private-invalid-input',p.stderr)

    @unittest.skipUnless(shutil.which('java'),'JDK unavailable')
    def test_independent_jdk_reproduces_whole_documents_and_all_fields(self):
        tasks=[('catalog',V['catalog']),('file',V['profile'])];expected=[V['catalogWire'],V['profileWire']];pairs=[]
        for fields,wire,plain in [(codec.NAMES['root'],V['catalogWire'],V['expectedCatalog']),
            (codec.NAMES['servers'],V['catalogWire']['Servers'][0],V['expectedCatalog']['Servers'][0]),
            (codec.NAMES['tweaks'],V['catalogWire']['Tweaks'][0],V['expectedCatalog']['Tweaks'][0])]:
            for k in fields:pairs.append(('xor',wire[k],plain[k]))
        pairs.append(('xor',V['catalogWire']['message'],V['expectedCatalog']['message']))
        for k in codec.NAMES['profile']:pairs.append(('double',V['expectedProfile']['TGV_CONFIG'][k],V['profileWire']['TGV_CONFIG'][k]))
        tasks += [(op,text) for op,text,out in pairs]
        data=''.join(op+'\t'+base64.b64encode(s.encode()).decode()+'\n' for op,s in tasks)
        p=subprocess.run(['java',str(ROOT/'tests/golden/tunelguard_oracle.java')],input=data,text=True,capture_output=True,timeout=30)
        self.assertEqual(p.returncode,0,p.stderr);out=[base64.b64decode(s).decode() for s in p.stdout.splitlines()]
        self.assertEqual([json.loads(s) for s in out[:2]],expected);self.assertEqual(out[2:],[v for op,text,v in pairs])

    def test_original_icon_and_cloud_only_android_registration(self):
        icon=(APP/'TunelGuard_VPN.png').read_bytes();self.assertEqual(icon,(ROOT/'cloud/web/public/server-vpn-icons/tunelguard-vpn.png').read_bytes())
        self.assertEqual(hashlib.sha256(icon).hexdigest(),'bdc4bca16e4c9fc0c446e90cf683eef1fe57f7a10de9c451e8c5ec30890f3f6a')
        self.assertEqual(hashlib.sha256((APP/'TunelGuard_VPN.webp').read_bytes()).hexdigest(),'a1be636abb359351a1902fe22b45be1dd11e652b0274320f9e4d34cdd931788b')
        source=(ROOT/'android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudFileFormats.kt').read_text()
        self.assertIn('"tgv" to "TunelGuard VPN 12.8"',source);self.assertIn('portStatus="cloud_server_only"',source)

if __name__=='__main__':unittest.main()
