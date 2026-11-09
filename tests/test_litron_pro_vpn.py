"""Whole Pro catalog and observed nine inner fields; base identity stays separate."""
import hashlib,importlib.util,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from decoders.Python.apps.Litron_Pro_VPN import codec,server_catalog_decoder as cli
ROOT=Path(__file__).resolve().parents[1];DOS=ROOT/'analysis/com.litron.udp/11'
V=json.loads((DOS/'tests/fixtures/vectors.json').read_text())
class LitronProTests(unittest.TestCase):
    def test_complete_two_layer_json_keeps_unknown_fields_types_and_protocols(self):
        self.assertEqual(codec.decode_catalog(V['catalog'].encode()),V['expected'])
        self.assertEqual(json.loads(codec.run(V['catalog'].encode())),V['expected'])
    def test_only_observed_server_keys_are_opened(self):
        r=codec.decode_catalog(V['catalog'].encode())
        self.assertEqual(r['Password'],'root plaintext is untouched')
        self.assertEqual(r['Servers'][0]['VendorOpaque'],'YWJjZA==');self.assertEqual(r['Servers'][0]['Json'],'{"nested":[1,true]}')
    def test_empty_inactive_fields_are_preserved(self):
        self.assertEqual(codec.decode_catalog(V['catalog'].encode())['Servers'][1],V['expected']['Servers'][1])
    def test_android_base64_ascii_line_wrapping_is_supported(self):
        wrapped=' \t\r\n'.join(V['catalog'][i:i+60] for i in range(0,len(V['catalog']),60))
        self.assertEqual(codec.decode_catalog(wrapped.encode()),V['expected'])
    def test_corrupt_data_never_returns_partial_or_echoes_input(self):
        for b in [b'',b'<html>private-marker</html>',b'\xff',V['catalog'][:-1].encode(),V['catalog'].encode()+b'!']:
            with self.subTest(size=len(b)),self.assertRaises(ValueError) as e:codec.decode_catalog(b)
            self.assertNotIn('private-marker',str(e.exception))
    def test_valid_outer_with_invalid_schema_json_unicode_or_inner_field_is_rejected(self):
        for x in V['invalidCatalogs']:
            with self.assertRaises(ValueError):codec.decode_catalog(x.encode())
    def test_input_and_output_limits_fail_instead_of_cutting_json(self):
        with self.assertRaises(ValueError):codec.decode_catalog(b'x'*(codec.MAX_INPUT+1))
        with patch.object(codec,'MAX_OUTPUT',32),self.assertRaises(ValueError):codec.decode_catalog(V['catalog'].encode())
    def test_base_and_pro_cannot_be_mixed(self):
        from decoders.Python.apps.Litron_VPN import codec as base
        b=json.loads((ROOT/'analysis/com.fleet.vpn/25/tests/fixtures/vectors.json').read_text())
        with self.assertRaises(ValueError):codec.decode_catalog(b['catalog'].encode())
        with self.assertRaises(ValueError):base.decode_catalog(V['catalog'].encode())
    def test_actual_isolated_worker_keeps_every_field(self):
        from cloud.workers.python.engine import decode_provider_catalog,DecodeFailure
        r=decode_provider_catalog('litron-pro-vpn',V['catalog'].encode())
        self.assertEqual(r['structuredJson'],V['expected']);self.assertEqual(json.loads(r['rawText']),V['expected']);self.assertFalse(r['isPartial'])
        with self.assertRaises(DecodeFailure):decode_provider_catalog('litron-pro',V['catalog'].encode())
    def test_cli_file_stdin_outside_checkout(self):
        script=ROOT/'decoders/Python/apps/Litron_Pro_VPN/server_catalog_decoder.py'
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'fixture.bin';p.write_text(V['catalog'])
            for args in [[str(p)],['--stdin']]:
                r=subprocess.run([sys.executable,str(script),*args],input=V['catalog'].encode(),cwd=d,capture_output=True,timeout=15)
                self.assertEqual(r.returncode,0);self.assertEqual(json.loads(r.stdout),V['expected'])
    def test_fixed_download_and_redirect_denial(self):
        class Reply:
            status=200;headers={}
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def read(self,n):return V['catalog'].encode()[:n]
        with patch.object(cli,'build_opener') as p:
            p.return_value.open.return_value=Reply();self.assertEqual(cli.download(),V['catalog'].encode())
            request=p.return_value.open.call_args.args[0];self.assertEqual(request.full_url,'https://godtechprime.github.io/litroproadfix.txt');self.assertEqual(request.get_header('Accept-encoding'),'identity')
        with self.assertRaises(ValueError):cli._NoRedirect().redirect_request(None)
    def test_exact_icon_from_supplied_pro_apk(self):
        a=(ROOT/'decoders/Python/apps/Litron_Pro_VPN/Litron_Pro_VPN.png').read_bytes();b=(ROOT/'cloud/web/public/server-vpn-icons/litron-pro-vpn.png').read_bytes()
        self.assertEqual(a,b);self.assertEqual(len(a),165852);self.assertEqual(hashlib.sha256(a).hexdigest(),'625e93856e82f750a0a4590537aac184d8c9110a13877c446d2dcff9a043a887')
    def test_whole_independent_jca_comparison(self):
        p=DOS/'tools/verify.py';s=importlib.util.spec_from_file_location('pro_proof',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'fixture.bin';p.write_text(V['catalog']);r=m.verify(p)
        self.assertTrue(r['wholeIndependentJcaParity']);self.assertEqual(r['innerFieldsCompared'],9)
if __name__=='__main__':unittest.main()
