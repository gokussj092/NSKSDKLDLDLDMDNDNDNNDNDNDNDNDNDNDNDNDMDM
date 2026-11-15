"""Auto build recovery: persistent history, real HTTPError path and negative cases."""
import io,json,os,subprocess,tempfile,unittest,warnings
from pathlib import Path
from urllib.error import HTTPError,URLError
from unittest.mock import patch
from decoders.Python.apps.Tunneltweak import network,build_history as h
ROOT=Path(__file__).resolve().parents[1]
CATALOG=json.dumps(json.loads((ROOT/'tests/golden/tunneltweak_vectors.json').read_text())['wrapper']).encode()
class Reply:
    headers={}
    def __init__(self,status,data):self.status=status;self.data=data
    def __enter__(self):return self
    def __exit__(self,*a):pass
    def read(self,n):return self.data[:n]
class BuildHistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.path=Path(self.tmp.name)/'builds.json'
    def download(self,answers,key=None):
        calls=[]
        class Opener:
            def open(_,r,timeout):
                self.assertTrue(0<timeout<=25);calls.append(r);answer=answers[len(calls)-1]
                if isinstance(answer,Exception):raise answer
                return Reply(*answer)
        with patch.object(network,'build_opener',return_value=Opener()):
            result=network.download(state_path=self.path,api_key=key)
        return result,calls
    def update(self,n=54):
        data=json.dumps({'status':'update_required','minVersionCode':n}).encode()
        return HTTPError(network.CATALOG_URL,426,'',{},io.BytesIO(data))
    def test_seed_matches_server_copy_and_records_only_metadata(self):
        self.assertEqual(h.SEED_PATH.read_bytes(),(ROOT/'cloud/web/content/tunneltweak-builds.seed.json').read_bytes())
        r,calls=self.download([(200,CATALOG)],'private-test-key');self.assertEqual(r,CATALOG)
        s=h.validate(json.loads(self.path.read_text()));self.assertEqual(s['auto']['build'],53)
        self.assertEqual(s['builds'][-1]['working'],True);self.assertEqual(self.path.stat().st_mode&0o777,0o600)
        self.assertNotIn('private-test-key',self.path.read_text());self.assertNotIn('data',s)
    def test_http426_jumps_to_advertised_minimum_and_reuses_it_after_restart(self):
        r,calls=self.download([self.update(57),(200,CATALOG)])
        self.assertEqual([x.get_header('X-app-version') for x in calls],['53','57']);self.assertEqual(r,CATALOG)
        s=h.load(self.path);self.assertEqual(s['auto']['build'],57)
        self.assertFalse(next(x for x in s['builds'] if x['build']==53)['working']);self.assertTrue(s['builds'][-1]['working'])
        _,calls=self.download([(200,CATALOG)]);self.assertEqual(calls[0].get_header('X-app-version'),'57')
    def test_explicit_update_without_minimum_tries_one_higher(self):
        _,calls=self.download([(426,b'{"status":"update_required"}'),(200,CATALOG)])
        self.assertEqual([x.get_header('X-app-version') for x in calls],['53','54'])
    def test_outages_authorization_and_throttling_never_bump_the_build(self):
        for e in [URLError(TimeoutError()),*[HTTPError(network.CATALOG_URL,n,'',{},io.BytesIO(b'private-error')) for n in [401,403,429,503]]]:
            with self.subTest(error=type(e).__name__),self.assertRaises(ValueError):self.download([e])
            s=h.load(self.path);self.assertEqual(s['auto']['build'],53);self.assertTrue(s['builds'][-1]['working'])
    def test_bad_update_documents_do_not_invent_unbounded_builds(self):
        for n in [0,-1,True,54.5,'54',53,2147483648]:
            with self.subTest(value=n),self.assertRaises(ValueError):self.download([self.update(n)])
            self.assertEqual(h.load(self.path)['auto']['build'],53)
    def test_three_attempt_budget_saves_pending_candidate(self):
        with self.assertRaises(ValueError):self.download([self.update(54),self.update(55),self.update(56)])
        s=h.load(self.path);self.assertEqual(s['auto']['build'],56);self.assertIsNone(s['builds'][-1]['working'])
        self.assertFalse(s['builds'][-2]['working'])
    def test_html_error_json_and_invalid_carriers_never_mark_success(self):
        for data in [b'<html>private-marker</html>',b'{}',b'{"status":"error"}',b'{"data":"abc"}',b'\xff',CATALOG.decode().encode('utf-16'),CATALOG[:-1]+b',"invalid":NaN}']:
            with self.subTest(data=data[:8]),self.assertRaises(ValueError):self.download([(200,data)])
        self.assertEqual(h.load(self.path)['builds'][-1]['successes'],1)
        self.assertNotIn('private-marker',self.path.read_text())
    def test_unrelated_or_malformed_http426_does_not_retire_a_working_build(self):
        for data in [b'{}',b'<html>upgrade</html>',b'{"status":"error"}']:
            with self.assertRaises(ValueError):self.download([(426,data)])
            self.assertTrue(h.load(self.path)['builds'][-1]['working']);self.assertEqual(h.load(self.path)['auto']['build'],53)
    def test_invalid_state_and_symlinks_do_not_overwrite_other_files(self):
        victim=Path(self.tmp.name)/'victim';victim.write_text('private-marker');self.path.symlink_to(victim)
        with warnings.catch_warnings():warnings.simplefilter('ignore');self.download([(200,CATALOG)])
        self.assertEqual(victim.read_text(),'private-marker');self.assertFalse(self.path.is_symlink());h.validate(h.load(self.path))
    def test_node_and_python_share_the_same_history_contract(self):
        self.download([self.update(54),(200,CATALOG)])
        script="""import {resolveTunneltweakCatalog} from './cloud/web/lib/tunneltweak-builds.mjs';
import {readFileSync} from 'node:fs';
const catalog=Buffer.from(JSON.stringify(JSON.parse(readFileSync('tests/golden/tunneltweak_vectors.json','utf8')).wrapper));
await resolveTunneltweakCatalog(async build=>{if(build!==54)throw Error('WRONG_BUILD');return {data:catalog};},{statePath:process.argv[1]});"""
        subprocess.run(['node','--input-type=module','-e',script,str(self.path)],cwd=ROOT,check=True,capture_output=True)
        self.assertEqual(h.load(self.path)['builds'][-1]['successes'],2)
if __name__=='__main__':unittest.main()
