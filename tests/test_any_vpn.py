"""ANY build 40: complete catalogs and .dtk, isolated workers and Termux CLI."""
import base64
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock,patch
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from decoders.Python.apps.ANY_VPN import codec,file_decoder,server_catalog_decoder

ROOT=Path(__file__).resolve().parents[1]


def seal(text):
    return base64.b64encode(AES.new(codec.KEY,AES.MODE_CBC,bytes(16)).encrypt(pad(text.encode(),16))).decode()


def server():
    return {'Name':'Synthetic server','ServerIPHost':seal('example.invalid'),'ServerPass':seal('demo'),
        'ServerUser':'','serverType':1,'AutoLogIn':False,'Fake':False,'unknown':[None,True,7]}


def network():
    return {'Name':'Synthetic network','Payload':seal('GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n'),
        'SNIHost':seal('example.invalid'),'Squid':seal(''),'vsni':'','TunnelType':3,'P_CustomCa':'plain certificate'}


def catalog():
    return {'Version':'test.1','Servers':[server()], 'Networks':[network()],
        'Notes':'Prueba ñ 😀','config_url':seal('https://example.invalid/catalog'),
        'account_api':seal('https://example.invalid/account'),'AdvanceSettings':[{'enabled':False,'port':'8080'}]}


class AnyTests(unittest.TestCase):
    def test_complete_catalog_preserves_names_plain_certificates_and_flags(self):
        obj=catalog();expected=catalog()
        expected['Servers'][0]['ServerIPHost']='example.invalid';expected['Servers'][0]['ServerPass']='demo'
        expected['Networks'][0]['Payload']='GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n'
        expected['Networks'][0]['SNIHost']='example.invalid';expected['Networks'][0]['Squid']=''
        expected['config_url']='https://example.invalid/catalog';expected['account_api']='https://example.invalid/account'
        actual=codec.decode_catalog(seal(json.dumps(obj)).encode())
        self.assertEqual(actual,expected)
        self.assertEqual(codec.decode_catalog(json.dumps(obj).encode()),expected)

    def test_dtk_normalizes_nested_json_strings_without_losing_other_fields(self):
        obj={'server':json.dumps(server()),'network':json.dumps(network()),'extra':{'enabled':False}}
        actual=codec.decode_profile(seal(json.dumps(obj)).encode())
        self.assertEqual(actual['server']['ServerPass'],'demo')
        self.assertEqual(actual['network']['SNIHost'],'example.invalid')
        self.assertEqual(actual['extra'],obj['extra'])
        self.assertFalse(actual['server']['AutoLogIn'])

    def test_network_only_and_server_only_sections(self):
        for section,data in [('network',network()),('server',server())]:
            result=codec.decode_profile(seal(json.dumps({section:json.dumps(data)})).encode())
            self.assertEqual(set(result),{section})
            self.assertEqual(result[section]['Name'],data['Name'])

    def test_encrypted_field_failure_rejects_whole_catalog(self):
        for bad in ('not encrypted',True,'A'*24):
            obj=catalog();obj['Servers'][0]['ServerIPHost']=bad
            with self.assertRaises(codec.DecodeError):codec.decode_catalog(seal(json.dumps(obj)).encode())

    def test_duplicate_invalid_structures_nonfinite_and_depth(self):
        for text in ('[]','{"Version":"1","Version":"2"}',
                '{"Version":"1","Servers":[],"Networks":[]}',
                '{"Version":"1","Servers":[{}],"Networks":[{}]}',
                '{"Version":"1","x":NaN}'):
            with self.assertRaises(codec.DecodeError):codec.decode_catalog(seal(text).encode())
        obj=catalog();obj['unknown']=[1]
        for _ in range(66):obj['unknown']=[obj['unknown']]
        with self.assertRaises(codec.DecodeError):codec.decode_catalog(seal(json.dumps(obj)).encode())

    def test_nested_profile_json_rejects_duplicates_and_incompatible_wrappers(self):
        for obj in ({},{'network':'[]'},{'network':'{"a":1,"a":2}'},{'network':True},{'server':'not JSON'},{'server':{'unrelated':1}}):
            with self.assertRaises(codec.DecodeError):codec.decode_profile(seal(json.dumps(obj)).encode())

    def test_input_limits_padding_utf8_and_base64(self):
        for data in (b'',b'x'*(codec.MAX_BYTES+1),b'\xff',b'AA',b'not base64'):
            with self.assertRaises(codec.DecodeError):codec.decode_catalog(data)
        source=bytearray(base64.b64decode(seal(json.dumps(catalog()))));source[-1]^=1
        with self.assertRaises(codec.DecodeError):codec.decode_catalog(base64.b64encode(source))

    def test_error_messages_never_include_input_or_plaintext(self):
        marker='PRIVATE-TEST-MARKER'
        with self.assertRaises(codec.DecodeError) as error:codec.decode_profile(seal(marker).encode())
        self.assertNotIn(marker,str(error.exception))

    def test_offline_entrypoints_do_not_download(self):
        with patch.object(codec,'download',side_effect=AssertionError('network')):
            self.assertEqual(json.loads(server_catalog_decoder.run(seal(json.dumps(catalog())).encode()))['Version'],'test.1')
            self.assertIn('network',json.loads(file_decoder.run(seal(json.dumps({'network':json.dumps(network())})).encode())))

    def test_fixed_get_replays_official_agent_and_bounded_identity_response(self):
        response=MagicMock();response.__enter__.return_value=response;response.status=200;response.headers={}
        response.read.return_value=seal(json.dumps(catalog())).encode()
        opener=MagicMock();opener.open.return_value=response
        with patch.object(codec,'build_opener',return_value=opener):codec.download()
        args,kwargs=opener.open.call_args;req=args[0]
        self.assertEqual(req.full_url,codec.CATALOG_URL);self.assertEqual(req.get_method(),'GET')
        self.assertEqual(req.get_header('User-agent'),'okhttp/5.0.0-alpha.12')
        self.assertEqual(kwargs['timeout'],25);response.read.assert_called_once_with(codec.MAX_BYTES+1)

    def test_redirect_and_http_errors_are_sanitized(self):
        with self.assertRaises(codec.DecodeError):codec.NoRedirect().redirect_request(None,None,302,'',{},'https://example.invalid')
        with patch.object(codec,'build_opener',side_effect=OSError('PRIVATE-RESPONSE')):
            with self.assertRaises(codec.DecodeError) as error:codec.download()
        self.assertNotIn('PRIVATE-RESPONSE',str(error.exception))

    def test_standalone_cli_writes_0600_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);script=root/'any_vpn.py';shutil.copyfile(codec.__file__,script)
            source=root/'test.dtk';source.write_text(seal(json.dumps({'network':json.dumps(network())})))
            output=root/'out.json';cmd=[sys.executable,str(script),'--file',str(source),'-o',str(output)]
            result=subprocess.run(cmd,capture_output=True,timeout=20)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(output.stat().st_mode&0o777,0o600);original=output.read_bytes()
            self.assertEqual(subprocess.run(cmd,capture_output=True,timeout=20).returncode,1)
            self.assertEqual(output.read_bytes(),original)

    @unittest.skipUnless(shutil.which('java'),'Independent JDK oracle needs Java')
    def test_complete_jdk_and_isolated_worker_for_catalog_and_two_profiles(self):
        from scripts.apk_analysis.any_vpn_verify import verify
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'test.enc';path.write_text(seal(json.dumps(catalog())))
            self.assertTrue(verify(path)['workerEqual'])
            for obj in ({'network':json.dumps(network())},{'server':json.dumps(server()),'network':json.dumps(network())}):
                path.write_text(seal(json.dumps(obj)));self.assertTrue(verify(path,True)['jdkEqual'])


if __name__=='__main__':unittest.main()
