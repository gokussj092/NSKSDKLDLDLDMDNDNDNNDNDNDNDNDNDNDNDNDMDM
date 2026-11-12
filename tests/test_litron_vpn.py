"""Only com.fleet.vpn: whole JCA vectors, owner icon, strict Unicode and worker."""
import hashlib,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from decoders.Python.apps.Litron_VPN import codec,server_catalog_decoder as cli
ROOT=Path(__file__).resolve().parents[1];DOS=ROOT/'analysis/com.fleet.vpn/25'
V=json.loads((DOS/'tests/fixtures/vectors.json').read_text())
class LitronTests(unittest.TestCase):
    def test_complete_catalog_preserves_lists_types_and_unknown_fields(self):
        self.assertEqual(codec.decode_catalog(V['catalog'].encode()),V['expected'])
        self.assertEqual(json.loads(codec.run(V['catalog'].encode())),V['expected'])
    def test_unicode_carrier_is_not_stripped_or_normalized(self):
        data=V['catalog'].encode();self.assertTrue(V['catalog'][0].isspace())
        self.assertEqual(codec.decode_catalog(data),V['expected'])
        with self.assertRaises(ValueError):codec.decode_catalog(V['catalog'].strip().encode())
    def test_all_owner_helper_field_variants_and_plain_strings(self):
        for hidden,plain in zip(V['hidden'],V['plain']):self.assertEqual(codec.hidden(hidden),plain)
        for s in ['YWJjZA==','test.example.invalid','ñ 😀',''] :self.assertEqual(codec.hidden(s),s)
    def test_damaged_transport_is_rejected_without_echoing_contents(self):
        for data in [b'',b'<html>private-marker</html>',b'\xff',V['catalog'][:-1].encode(),V['catalog'].encode()+b'x']:
            with self.subTest(size=len(data)),self.assertRaises(ValueError) as e:codec.decode_catalog(data)
            self.assertNotIn('private-marker',str(e.exception))
    def test_valid_ciphertext_with_bad_json_or_schema_is_rejected(self):
        for carrier in V['invalidCatalogs']:
            with self.assertRaises(ValueError):codec.decode_catalog(carrier.encode())
    def test_input_and_output_limits_do_not_truncate_json(self):
        with self.assertRaises(ValueError):codec.decode_catalog(b'x'*(codec.MAX_INPUT+1))
        with patch.object(codec,'MAX_OUTPUT',32),self.assertRaises(ValueError):codec.decode_catalog(V['catalog'].encode())
    def test_isolated_worker_returns_every_field_and_pro_rejects_base_bytes(self):
        from cloud.workers.python.engine import decode_provider_catalog,DecodeFailure
        r=decode_provider_catalog('litron-vpn',V['catalog'].encode())
        self.assertEqual(r['structuredJson'],V['expected']);self.assertEqual(json.loads(r['rawText']),V['expected']);self.assertFalse(r['isPartial'])
        with self.assertRaises(DecodeFailure):decode_provider_catalog('litron-pro-vpn',V['catalog'].encode())
    def test_cli_file_and_stdin_outside_checkout(self):
        script=ROOT/'decoders/Python/apps/Litron_VPN/server_catalog_decoder.py'
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'synthetic.bin';path.write_text(V['catalog'])
            for args in [[str(path)],['--stdin']]:
                r=subprocess.run([sys.executable,str(script),*args],input=V['catalog'].encode(),cwd=folder,capture_output=True,timeout=15)
                self.assertEqual(r.returncode,0,r.stderr.decode());self.assertEqual(json.loads(r.stdout),V['expected'])
    def test_download_preserves_exact_bytes_and_fixed_endpoint(self):
        class Reply:
            status=200;headers={}
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def read(self,n):return V['catalog'].encode()[:n]
        with patch.object(cli,'build_opener') as p:
            p.return_value.open.return_value=Reply();self.assertEqual(cli.download(),V['catalog'].encode())
            req=p.return_value.open.call_args.args[0];self.assertEqual(req.full_url,'https://godtechprime.github.io/latestv2ray.txt')
            self.assertEqual(req.get_header('Accept-encoding'),'identity')
        with self.assertRaises(ValueError):cli._NoRedirect().redirect_request(None)
    def test_owner_icon_is_original_and_identical_in_both_locations(self):
        a=(ROOT/'decoders/Python/apps/Litron_VPN/Litron_VPN.png').read_bytes();b=(ROOT/'cloud/web/public/server-vpn-icons/litron-vpn.png').read_bytes()
        self.assertEqual(a,b);self.assertEqual(len(a),86055);self.assertEqual(hashlib.sha256(a).hexdigest(),'38a931316e6ea65793f377eccd66924790a3ff273d250d8955b6b48a7867aae0')
    def test_whole_independent_java_and_owner_reference(self):
        import importlib.util
        p=DOS/'tools/verify.py';s=importlib.util.spec_from_file_location('litron_proof',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'fixture.bin';p.write_text(V['catalog']);r=m.verify(p,False)
        self.assertTrue(r['wholeIndependentJcaParity']);self.assertTrue(r['wholeProvidedHelperParity']);self.assertFalse(r['providedAutoInstallerCalled'])
if __name__=='__main__':unittest.main()
