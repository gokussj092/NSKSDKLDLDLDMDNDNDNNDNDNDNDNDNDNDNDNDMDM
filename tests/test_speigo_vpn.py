"""Two independent SpeiGo catalogs, synthetic authenticated whole documents."""
import base64,hashlib,importlib.util,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from decoders.Python.apps.SpeiGo_VPN import codec,server_catalog_decoder as configs,ssh_catalog_decoder as ssh
ROOT=Path(__file__).resolve().parents[1];DOS=ROOT/'analysis/netfree.mx.speigovpn/159'
V=json.loads((DOS/'tests/fixtures/vectors.json').read_text());A=base64.b64decode(V['configs']);B=base64.b64decode(V['ssh']);PUBLIC=bytes.fromhex(V['testPublicKey'])
class SpeigoTests(unittest.TestCase):
    def test_complete_documents_preserve_unknown_types_unicode_and_source_sections(self):
        with patch.object(codec,'SIGNATURE_PUBLIC_KEY',PUBLIC):
            self.assertEqual(json.loads(configs.run(A)),V['expectedConfigs']);self.assertEqual(json.loads(ssh.run(B)),V['expectedSsh'])
    def test_provider_signature_is_required_and_has_no_env_override(self):
        for data,purpose in [(A,1),(B,2)]:
            with self.assertRaises(ValueError):codec.decode_catalog(data,purpose)
        with patch.dict('os.environ',{'SPEIGO_PUBLIC_KEY':PUBLIC.hex()}),self.assertRaises(ValueError):configs.run(A)
    def test_crossed_sources_are_rejected_even_with_valid_test_signature(self):
        with patch.object(codec,'SIGNATURE_PUBLIC_KEY',PUBLIC):
            for run,data in [(configs.run,B),(ssh.run,A)]:
                with self.assertRaises(ValueError):run(data)
    def test_signed_bad_tags_fields_json_schema_and_conflicting_metadata_are_rejected(self):
        with patch.object(codec,'SIGNATURE_PUBLIC_KEY',PUBLIC):
            for b64 in V['invalid']:
                with self.subTest(b64=b64[:12]),self.assertRaises(ValueError):configs.run(base64.b64decode(b64))
    def test_corrupt_truncated_html_empty_and_oversize_fail_without_partial_or_input_echo(self):
        for data in [b'',b'<html>private-marker</html>',A[:-1],A+b'xx',b'x'*(codec.MAX_BYTES+1)]:
            with self.assertRaises(ValueError) as e:configs.run(data)
            self.assertNotIn('private-marker',str(e.exception))
    def test_other_providers_material_is_not_mutated(self):
        from decoders.Python.apps.SuperFlash_VPN import codec as other
        before=(other.ROOT_KEY,other.CONTEXT,other.SIGNATURE_PUBLIC_KEY)
        with patch.object(codec,'SIGNATURE_PUBLIC_KEY',PUBLIC):configs.run(A);ssh.run(B)
        self.assertEqual(before,(other.ROOT_KEY,other.CONTEXT,other.SIGNATURE_PUBLIC_KEY))
        with self.assertRaises(ValueError):other.decode_catalog(A)
    def test_allowlisted_bridge_returns_two_separate_complete_documents(self):
        from cloud.workers.python.catalog_vpn_bridge import decode
        with patch.object(codec,'SIGNATURE_PUBLIC_KEY',PUBLIC):
            self.assertEqual(json.loads(decode('speigo-vpn-configs',A)),V['expectedConfigs']);self.assertEqual(json.loads(decode('speigo-vpn-ssh',B)),V['expectedSsh'])
        with self.assertRaises(ValueError):decode('speigo-vpn',A)
    def test_actual_child_and_cli_do_not_accept_the_synthetic_signer(self):
        from cloud.workers.python.engine import decode_provider_catalog,DecodeFailure
        with self.assertRaises(DecodeFailure):decode_provider_catalog('speigo-vpn-configs',A)
        with tempfile.TemporaryDirectory() as cwd:
            r=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/SpeiGo_VPN/ssh_catalog_decoder.py'),'--stdin'],input=B,cwd=cwd,capture_output=True,timeout=15)
        self.assertNotEqual(r.returncode,0);self.assertEqual(r.stdout,b'')
    def test_fixed_downloads_keep_bytes_and_sources_separate(self):
        class Reply:
            status=200;headers={}
            def __init__(self,b):self.b=b
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,n):return self.b[:n]
        with patch.object(configs,'build_opener') as p:
            for purpose,data in [(1,A),(2,B)]:
                p.return_value.open.return_value=Reply(data);self.assertEqual(configs.download(purpose),data);req=p.return_value.open.call_args.args[0];self.assertEqual(req.full_url,configs.SOURCES[purpose]);self.assertEqual(req.get_header('Accept-encoding'),'identity')
        with self.assertRaises(ValueError):configs._NoRedirect().redirect_request(None)
    def test_original_icon_is_identical_in_both_locations(self):
        a=(ROOT/'decoders/Python/apps/SpeiGo_VPN/SpeiGo_VPN.png').read_bytes();b=(ROOT/'cloud/web/public/server-vpn-icons/speigo-vpn.png').read_bytes()
        self.assertEqual(a,b);self.assertEqual(len(a),21564);self.assertEqual(hashlib.sha256(a).hexdigest(),'09acd58c6af0d0892530574cd33e3d417ed1743bea741337de33f56b87dc6581')
    def test_independent_jca_and_host_sodium_whole_fixture_parity(self):
        p=DOS/'tools/verify.py';s=importlib.util.spec_from_file_location('speigo_reference',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
        for data,expected in [(A,V['expectedConfigs']),(B,V['expectedSsh'])]:self.assertEqual(m.reference(data,PUBLIC)[0],expected)
if __name__=='__main__':unittest.main()
