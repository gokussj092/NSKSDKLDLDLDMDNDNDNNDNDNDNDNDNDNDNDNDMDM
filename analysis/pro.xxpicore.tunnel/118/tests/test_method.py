"""Fictional independent vectors, malformed inputs and isolated Cloud behavior."""
import json,subprocess,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.XXPICore_Tunnel.codec import decode_catalog,DecodeError,MAX_BYTES
from decoders.Python.apps.XXPICore_Tunnel.server_catalog_decoder import run
from cloud.workers.python.engine import decode_provider_catalog,DecodeFailure
F=Path(__file__).with_name('fixtures')
class MethodTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw=(F/'catalog.enc').read_bytes();cls.expected=json.loads((F/'expected.json').read_text())
    def test_independent_whole_object(self):self.assertEqual(decode_catalog(self.raw),self.expected)
    def test_render_preserves_unicode_and_unknown_fields(self):
        text=run(self.raw);self.assertIn('日本語',text);self.assertEqual(json.loads(text),self.expected)
    def test_all_three_modes_and_nested_fields(self):
        d=decode_catalog(self.raw);self.assertEqual(d['Password'],'demo-pass')
        self.assertEqual(d['Servers'][0]['ServerIPHost'],'vpn.example.org')
        self.assertEqual(d['Networks'][0]['V2Ray']['SNIHost'],'example.org')
    def test_empty_or_html(self):
        for raw in (b'',b'<html>Site Unavailable</html>',b'{}',b'[]',b'\xff'):
            with self.subTest(raw=raw[:10]),self.assertRaises(DecodeError):decode_catalog(raw)
    def test_truncated_and_corrupt(self):
        for raw in (self.raw[:-1],self.raw[:-16],b'!'+self.raw[1:]):
            with self.assertRaises(DecodeError):decode_catalog(raw)
    def test_incomplete_ambiguous_or_invalid_schema(self):
        for name,value in json.loads((F/'invalid.json').read_text()).items():
            with self.subTest(name=name),self.assertRaises(DecodeError):decode_catalog(value.encode())
    def test_size_limit(self):
        with self.assertRaises(DecodeError):decode_catalog(b'A'*(MAX_BYTES+1))
    def test_cli_file_and_stdin(self):
        script=ROOT/'decoders/Python/apps/XXPICore_Tunnel/server_catalog_decoder.py'
        for args,data in (([str(F/'catalog.enc')],None),(['--stdin'],self.raw)):
            r=subprocess.run([sys.executable,str(script),*args],input=data,capture_output=True,timeout=20)
            self.assertEqual(r.returncode,0);self.assertEqual(json.loads(r.stdout),self.expected)
    def test_cli_sanitizes_error(self):
        r=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/XXPICore_Tunnel/server_catalog_decoder.py'),'--stdin'],input=b'<html>private diagnostic</html>',capture_output=True)
        self.assertEqual(r.returncode,1);self.assertEqual(r.stdout,b'');self.assertNotIn(b'private',r.stderr)
    def test_isolated_worker_whole_object(self):
        d=decode_provider_catalog('xxpicore-tunnel',self.raw)
        self.assertEqual(d['structuredJson'],self.expected);self.assertFalse(d['isPartial']);self.assertEqual(d['providerId'],'xxpicore-tunnel')
    def test_isolated_worker_rejects_html(self):
        with self.assertRaises(DecodeFailure):decode_provider_catalog('xxpicore-tunnel',b'<html>bad</html>')
if __name__=='__main__':unittest.main()
