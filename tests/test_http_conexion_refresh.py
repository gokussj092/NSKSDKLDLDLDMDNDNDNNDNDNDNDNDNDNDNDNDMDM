import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from decoders.Python.apps.HTTP_Conexion import codec, firebase, server_catalog_decoder as cli
ROOT=Path(__file__).resolve().parents[1]
DOSSIER=ROOT/'analysis/com.doriaxvpn.unlimited/129'
spec=importlib.util.spec_from_file_location('conexion_refresh_vectors',DOSSIER/'tools/make_vectors.py')
vectors=importlib.util.module_from_spec(spec);spec.loader.exec_module(vectors)
SOURCE='https://raw.githubusercontent.com/soportecrisdev/Gen/main/rotated'


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.data=(DOSSIER/'tests/fixtures/catalog.txt').read_bytes()
        self.expected=json.loads((DOSSIER/'tests/fixtures/expected.json').read_text())
        self.wire=json.loads((DOSSIER/'tests/fixtures/wire.json').read_text())
        firebase._cached=None;firebase._expires=0;firebase._retry_after=0

    def test_pair_rotation_is_automatic_and_validates_destination(self):
        value=firebase.select_config({'entries':{'ockla_url':SOURCE,'gretta_pass':'nueva-©-clave'}})
        self.assertEqual(value,{'source':SOURCE,'password':'nueva-©-clave'})
        for url in ['http://raw.githubusercontent.com/a/b/main/x','https://127.0.0.1/a/b/main/x',
                    'https://attacker.invalid/a/b/main/x','https://raw.githubusercontent.com@attacker.invalid/a/b/main/x',
                    SOURCE+'?q=1',SOURCE+'#x',SOURCE+'\n','https://raw.githubusercontent.com:443/a/b/main/x']:
            with self.subTest(url=url),self.assertRaises(ValueError):firebase.select_config({'entries':{'ockla_url':url,'gretta_pass':'x'}})

    def test_missing_values_never_reuse_obsolete_constants(self):
        for reply in [{},{'entries':{}},{'entries':{'ockla_url':SOURCE}},
                      {'entries':{'ockla_url':SOURCE,'gretta_pass':''}},
                      {'entries':{'ockla_url':SOURCE,'gretta_pass':'x'*1025}}]:
            with self.assertRaises(ValueError):firebase.select_config(reply)

    def test_real_protocol_uses_only_fis_issued_mock_token_then_deletes(self):
        calls=[];fid='c'+'A'*21
        def transport(url,headers,body=None,method='POST'):
            calls.append((url,headers,body,method))
            if url.endswith('/installations'):
                self.assertEqual(body['authVersion'],'FIS_v2');self.assertNotIn('Authorization',headers)
                return {'fid':fid,'refreshToken':'synthetic-refresh','authToken':{'token':'synthetic-issued'}}
            if url.endswith('/firebase:fetch'):
                self.assertEqual(headers['X-Goog-Firebase-Installations-Auth'],'synthetic-issued')
                self.assertEqual(body['appInstanceIdToken'],'synthetic-issued')
                self.assertEqual(body['appVersion'],'1.2.9')
                return {'entries':{'ockla_url':SOURCE,'gretta_pass':'new-password'}}
            self.assertEqual(method,'DELETE');self.assertEqual(headers['Authorization'],'FIS_v2 synthetic-refresh');return {}
        self.assertEqual(firebase.fetch_config(transport)['password'],'new-password');self.assertEqual(len(calls),3)

    def test_invalid_config_still_deletes_temporary_installation(self):
        methods=[]
        def transport(url,headers,body=None,method='POST'):
            methods.append(method)
            if url.endswith('/installations'):return {'fid':'c'+'B'*21,'refreshToken':'synthetic-refresh','authToken':{'token':'synthetic-issued'}}
            return {}
        with self.assertRaises(ValueError):firebase.fetch_config(transport)
        self.assertEqual(methods,['POST','POST','DELETE'])

    def test_cache_expiration_force_and_failure_cooldown(self):
        with patch.object(firebase.time,'monotonic',return_value=100) as now,patch.object(firebase,'fetch_config',return_value={'source':SOURCE,'password':'one'}) as fetch:
            result=firebase.resolve_config();result['password']='changed-locally'
            self.assertEqual(firebase.resolve_config()['password'],'one');self.assertEqual(fetch.call_count,1)
            fetch.return_value={'source':SOURCE,'password':'two'}
            self.assertEqual(firebase.resolve_config(force=True)['password'],'two');self.assertEqual(fetch.call_count,2)
            now.return_value=4000
            self.assertEqual(firebase.resolve_config()['password'],'two');self.assertEqual(fetch.call_count,3)
            fetch.side_effect=OSError('private-marker')
            with self.assertRaises(ValueError):firebase.resolve_config(force=True)
            with self.assertRaises(ValueError):firebase.resolve_config()
            self.assertEqual(fetch.call_count,4)

    def test_rotated_password_matches_jca_cli_and_real_isolated_worker(self):
        from cloud.workers.python.engine import decode_provider_catalog
        password='rotated-©-fictional'
        raw=vectors.transform('E',[json.dumps(self.wire).encode()],password.encode())[0]
        with self.assertRaises(ValueError):codec.run(raw)
        bundled=codec.pack_catalog(raw,password)
        self.assertEqual(json.loads(codec.run(bundled)),self.expected)
        result=decode_provider_catalog('http-conexion',bundled)
        self.assertEqual(result['structuredJson'],self.expected);self.assertFalse(result['isPartial'])
        self.assertEqual(codec.CATALOG_PASSWORD,b'\xc2\xa9risdev~')

    def test_invalid_bundle_does_not_become_plaintext_or_leak_secrets(self):
        for value in [{'kind':'other','passwordBase64':'eA==','catalogBase64':'eA=='},
                      {'kind':'spdecode-http-conexion-config-v1','passwordBase64':'AA==','catalogBase64':'eA=='},
                      {'kind':'spdecode-http-conexion-config-v1','passwordBase64':'eA==','catalogBase64':'eA==','url':SOURCE}]:
            with self.assertRaises(ValueError):codec.run(json.dumps(value).encode())

    def test_cli_retries_with_one_fresh_pair_on_rotation(self):
        wrong=codec.pack_catalog(self.data,'obsolete-fictional')
        good=codec.pack_catalog(self.data,codec.CATALOG_PASSWORD.decode())
        output=io.StringIO()
        with patch.object(sys,'argv',['decoder']),patch.object(cli,'download',side_effect=[wrong,good]) as download,contextlib.redirect_stdout(output):
            self.assertEqual(cli.main(),0)
        self.assertEqual(json.loads(output.getvalue()),self.expected)
        self.assertEqual(download.call_count,2);self.assertEqual(download.call_args.kwargs,{'force':True})


if __name__=='__main__':unittest.main()
