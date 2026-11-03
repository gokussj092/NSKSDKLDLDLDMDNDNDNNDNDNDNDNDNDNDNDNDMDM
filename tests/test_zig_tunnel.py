"""Original-Java vectors and complete multi-list ZiG catalog validation."""
import json,base64,subprocess,sys,unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from decoders.Python.apps.ZiG_Tunnel import codec,server_catalog_decoder as catalog
ROOT=Path(__file__).resolve().parents[1];APP=ROOT/'decoders/Python/apps/ZiG_Tunnel'
V=json.loads((ROOT/'tests/golden/zig_vectors.json').read_text())
def java(mode,values):
 s=''.join(mode+'\t'+base64.b64encode(v.encode()).decode()+'\n' for v in values)
 p=subprocess.run(['java',str(ROOT/'tests/golden/zig_oracle.java')],input=s,text=True,capture_output=True,check=True,timeout=30)
 return [base64.b64decode(x).decode() for x in p.stdout.splitlines()]
class ZigTests(unittest.TestCase):
 def test_original_java_vectors_include_utf16_emoji_and_crlf(self):
  for clear,cipher in zip(V['plain'][1:],V['cipher'][1:]):self.assertEqual(codec.decrypt(cipher),clear)
  self.assertEqual(java('E',V['plain']),V['cipher']);self.assertEqual(java('D',V['cipher']),V['plain'])
 def test_complete_catalog_opens_all_confirmed_field_contexts(self):
  self.assertEqual(codec.decode_catalog(V['catalog'].encode()),V['expected']);self.assertEqual(json.loads(catalog.run(V['catalog'].encode())),V['expected'])
 def test_three_optional_lists_and_settings_unknown_types_are_preserved(self):
  d=codec.decode_catalog(V['catalog'].encode())
  for name in ('DirectNetworks','DNSNetworks','UDPNetworks'):self.assertEqual(d[name],[])
  self.assertEqual(d['JSONsettings'],V['outer']['JSONsettings']);self.assertEqual(d['unknown'],V['outer']['unknown']);self.assertEqual(d['Servers'][0]['UnknownCipher'],V['outer']['Servers'][0]['UnknownCipher']);self.assertIs(d['Servers'][0]['AutoLogIn'],False)
 def test_ssl_only_network_catalog_is_valid(self):
  d=V['outer'].copy();d.pop('HTTPNetworks');data=java('E',[json.dumps(d)])[0].encode();out=codec.decode_catalog(data);self.assertEqual(out['SSLNetworks'],V['expected']['SSLNetworks']);self.assertNotIn('HTTPNetworks',out)
 def test_malformed_outer_json_duplicates_and_schema_reject(self):
  for data in (b'',b'<html/>',b'private-sentinel',V['catalog'][:-8].encode()):
   with self.assertRaises(codec.DecodeError) as e:catalog.run(data)
   self.assertNotIn('private-sentinel',str(e.exception))
  bad=[{'Version':'x','Servers':[],'HTTPNetworks':[]},{**V['outer'],'Version':False},{**V['outer'],'SSLNetworks':'bad'}]
  for wire in java('E',[json.dumps(v) for v in bad]+['{"Version":"1","Version":"2"}']):
   with self.assertRaises(codec.DecodeError):catalog.run(wire.encode())
 def test_malformed_known_field_invalidates_entire_catalog(self):
  for value in (True,'not-base64!'):
   d=json.loads(json.dumps(V['outer']));d['Servers'][0]['ServerIP']=value
   with self.assertRaises(codec.DecodeError):catalog.run(java('E',[json.dumps(d)])[0].encode())
 def test_input_depth_output_limits(self):
  with self.assertRaises(codec.DecodeError):catalog.run(b'x'*(codec.MAX_BYTES+1))
  with self.assertRaises(codec.DecodeError):codec.render({'x':'x'*codec.MAX_BYTES})
  node=[]
  for _ in range(66):node=[node]
  d={**V['outer'],'deep':node}
  with self.assertRaises(codec.DecodeError):catalog.run(java('E',[json.dumps(d)])[0].encode())
 def test_complete_worker_and_cli_outside_checkout(self):
  from cloud.workers.python.engine import decode_provider_catalog,load_runtime_file_engines
  out=decode_provider_catalog('zig-tunnel',V['catalog'].encode());self.assertEqual(out['structuredJson'],V['expected']);self.assertEqual(json.loads(out['rawText']),V['expected']);self.assertFalse(out['isPartial']);self.assertFalse(out['exporterCertified'])
  r=subprocess.run([sys.executable,str(APP/'server_catalog_decoder.py'),'--stdin'],input=V['catalog'].encode(),capture_output=True,cwd='/tmp',timeout=20)
  self.assertEqual(r.returncode,0);self.assertEqual(r.stderr,b'');self.assertEqual(json.loads(r.stdout),V['expected']);self.assertEqual(len(load_runtime_file_engines()),256)
 def test_original_user_agent_fixed_source_redirects_and_sanitized_failure(self):
  class Opener:
   def open(self,r,timeout):
    assert r.full_url=='https://zimbotunnel.co.zw/default_config.hs' and r.get_method()=='GET' and r.get_header('User-agent')=='okhttp/5.3.2' and timeout==25
    raise HTTPError(catalog.SOURCE,403,'private-sentinel',{},None)
  with patch.object(catalog,'build_opener',return_value=Opener()):
   with self.assertRaises(codec.DecodeError) as e:catalog.download()
   self.assertNotIn('private-sentinel',str(e.exception))
  with self.assertRaises(codec.DecodeError):catalog._NoRedirect().redirect_request(None,None,None,None,None,None)
if __name__=='__main__':unittest.main()
