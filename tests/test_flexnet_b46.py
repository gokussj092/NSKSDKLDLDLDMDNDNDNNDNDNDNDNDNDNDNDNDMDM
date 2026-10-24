"""Focused B46 format/key/field checks plus explicit v1-v5 compatibility."""
import base64
import gzip
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from Crypto.Cipher import AES
from decoders.Python import flex, flexnet_b42 as codec
from tests.test_independent_batch_crypto_a import flex_fixture

ROOT=Path(__file__).resolve().parents[1]
V=json.loads((ROOT/'tests/golden/flexnet_b46_vectors.json').read_text())
KEY=bytes.fromhex(V['fileKey'])
SETUP=bytes.fromhex(V['offlineKey'])
ONLINE=base64.b64decode(V['online'])

def online_xml(xml):
    packed=gzip.compress(xml.encode())
    header=ONLINE[:41]+struct.pack('>I',len(packed)+16)
    cipher=AES.new(KEY,AES.MODE_GCM,nonce=header[29:41]);cipher.update(header)
    body,tag=cipher.encrypt_and_digest(packed)
    return header+body+tag

class FlexB46Smoke(unittest.TestCase):
    def test_jdk_v5_v6_complete_original_and_opened_properties(self):
        for name,kwargs in [('offline',{}),('online',{'file_key':KEY}),('v6',{'offline_key':SETUP})]:
            data=base64.b64decode(V[name]);result=codec.decode(data,**kwargs)
            self.assertEqual(codec.decrypt_profile_xml(data,**kwargs),V['xml'])
            self.assertEqual(len(result['rawProperties']),7)
            self.assertEqual(result['rawProperties']['customSni'],'visible.example.invalid')
            self.assertEqual(result['decodedProperties']['customSni'],'real.example.invalid')
            self.assertEqual(result['protectedFields']['proxyPayload'],'GET /safe HTTP/1.1\r\nHost: real.example.invalid\r\n\r\n')
            self.assertEqual(result['decodedProperties']['custom.unknown'],'keep-me')
            normalized=json.loads(flex.run(data,**kwargs))
            self.assertEqual(normalized['rawProperties'],result['rawProperties'])
            self.assertEqual(normalized['tunnel']['sni'],'real.example.invalid')
        from cloud.workers.python.engine import decode_file
        result=decode_file('flex',base64.b64decode(V['offline']))
        self.assertEqual(result['structuredJson']['protectedFields']['customSni'],'real.example.invalid')
        self.assertFalse(result['isPartial'])

    def test_required_keys_build_limits_and_authenticated_v6(self):
        for name,code in [('online','ONLINE_AUTH_REQUIRED'),('v6','OFFLINE_KEY_REQUIRED')]:
            data=base64.b64decode(V[name])
            with self.assertRaises(codec.DecodeError) as e:codec.decode(data)
            self.assertEqual(e.exception.code,code);self.assertIsNone(flex.run(data))
        self.assertEqual(codec.inspect_profile(ONLINE)['minimumClientBuild'],46)
        with self.assertRaises(codec.DecodeError) as e:codec.inspect_profile(ONLINE,client_build=42)
        self.assertEqual(e.exception.code,'MINIMUM_BUILD')
        for name,kwargs in [('online',{'file_key':b'x'*32}),('v6',{'offline_key':b'x'*32})]:
            with self.assertRaises(codec.DecodeError) as e:codec.decode(base64.b64decode(V[name]),**kwargs)
            self.assertEqual(e.exception.code,'AUTH_FAILED')
        raw=bytearray(base64.b64decode(V['v6']));raw[-1]^=1
        self.assertIsNone(codec.run(bytes(raw),offline_key=SETUP))
        raw=bytearray(ONLINE);struct.pack_into('>I',raw,9,47)
        with self.assertRaises(codec.DecodeError) as e:codec.inspect_profile(bytes(raw))
        self.assertEqual(e.exception.code,'MINIMUM_BUILD')

    def test_protected_field_binding_and_tag_fail_without_alias_fallback(self):
        from xml.etree import ElementTree as ET
        for change in ['alias','tag','missing']:
            root=ET.fromstring(V['xml']);entries={x.get('key'):x for x in root if x.tag=='entry'}
            if change=='alias':entries['customSni'].text='changed.example.invalid'
            elif change=='missing':root.remove(entries['file.routeFields'])
            else:
                doc=json.loads(entries['file.routeData'].text)
                raw=bytearray(base64.b64decode(doc['fields']['customSni']['c']));raw[-1]^=1
                doc['fields']['customSni']['c']=base64.b64encode(raw).decode()
                entries['file.routeData'].text=json.dumps(doc)
            data=online_xml(ET.tostring(root,encoding='unicode'))
            self.assertIsNone(codec.run(data,file_key=KEY));self.assertIsNone(flex.run(data,file_key=KEY))

    def test_v1_v2_v3_v4_and_original_b42_vectors_are_retained(self):
        props={'tunnelType':'3','sshServer':'legacy.example.invalid','unknown':'keep'}
        for version,minimum in [(1,0),(2,0),(3,28),(4,39)]:
            data=flex_fixture(version,minimum,props)
            self.assertEqual(json.loads(flex.run(data))['rawProperties'],props)
            if version==4:
                data=data[:15]+b'\x01\x04test'+data[15:]
                self.assertEqual(json.loads(flex.run(data))['rawProperties'],props)
        old=json.loads((ROOT/'tests/golden/flexnet_b42_vectors.json').read_text())
        for name,kwargs in [('offline',{}),('online',{'file_key':bytes.fromhex(old['fileKey'])})]:
            self.assertEqual(codec.decrypt_profile_xml(base64.b64decode(old[name]),**kwargs),old['xml'])
        self.assertEqual(codec.decode(base64.b64decode(old['catalog'])),old['catalogExpected'])

    def test_both_cli_entrypoints_accept_authorized_keys_outside_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);source=p/'profile.flex';key=p/'key.bin'
            for name,option,material in [('online','--file-key-file',KEY),('v6','--offline-key-file',SETUP)]:
                source.write_bytes(base64.b64decode(V[name]));key.write_bytes(material)
                for script in ['flex.py','flexnet_b42.py']:
                    result=subprocess.run([sys.executable,str(ROOT/'decoders/Python'/script),str(source),option,str(key)],cwd=tmp,capture_output=True,timeout=10)
                    self.assertEqual(result.returncode,0,result.stderr.decode())
                    self.assertEqual(json.loads(result.stdout)['protectedFields']['customSni'],'real.example.invalid')
                    failed=subprocess.run([sys.executable,str(ROOT/'decoders/Python'/script),str(source)],cwd=tmp,capture_output=True,timeout=10)
                    self.assertEqual(failed.returncode,1);self.assertEqual(failed.stdout,b'')

if __name__=='__main__':unittest.main()
