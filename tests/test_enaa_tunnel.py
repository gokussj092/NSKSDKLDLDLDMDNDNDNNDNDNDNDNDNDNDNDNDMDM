"""Enaa: independent libsodium/JCA vectors and offline worker boundaries."""
import base64,json,subprocess,sys,unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from decoders.Python.apps.Enaa_Tunnel import codec,server_catalog_decoder as catalog,file_decoder
ROOT=Path(__file__).resolve().parents[1];APP=ROOT/'decoders/Python/apps/Enaa_Tunnel'
V=json.loads((ROOT/'tests/golden/enaa_vectors.json').read_text())
class EnaaTests(unittest.TestCase):
 def test_all_independent_jca_envelopes_match_complete_documents(self):
  for case in V['documents']:
   fn=file_decoder.run if case['kind']=='file' else catalog.run
   expected={'application':'Enaa Tunnel','extension':'.enaa','config':case['expected']} if case['kind']=='file' else case['expected']
   self.assertEqual(json.loads(fn(case['wire'].encode())),expected)
 def test_argon2_memory_and_version_match_independent_libsodium_vector(self):
  from argon2.low_level import hash_secret_raw,Type
  d=V['kdf'];self.assertEqual(hash_secret_raw(d['password'].encode(),bytes.fromhex(d['saltHex']),3,8192,1,32,Type.ID).hex(),d['keyHex'])
 def test_unknown_ciphertext_and_scalar_types_remain_unchanged(self):
  case=next(x for x in V['documents'] if x['kind']=='catalog' and x['mode']=='plain');d=json.loads(case['wire']);d['unknown']=d['Servers'][0]['ServerIPHost'];d['Networks'][0]['URI']=d['unknown']
  out=json.loads(catalog.run(json.dumps(d).encode()));self.assertEqual(out['unknown'],d['unknown']);self.assertEqual(out['Networks'][0]['URI'],d['unknown']);self.assertFalse(out['Networks'][0]['Enabled']);self.assertEqual(out['Networks'][0]['future'],d['Networks'][0]['future'])
 def test_bad_tag_rejects_whole_catalog_and_profile(self):
  for kind in ('catalog','file'):
   case=next(x for x in V['documents'] if x['kind']==kind and x['mode']=='export');wire=case['wire'];raw=bytearray(base64.b64decode(wire[:3]+wire[4:]));raw[-1]^=1;bad=base64.b64encode(raw).decode();bad=bad[:3]+'Q'+bad[3:]
   with self.assertRaises(codec.DecodeError):(catalog.run if kind=='catalog' else file_decoder.run)(bad.encode())
 def test_known_inner_corruption_rejects_without_partial_output(self):
  case=next(x for x in V['documents'] if x['kind']=='catalog' and x['mode']=='plain');doc=json.loads(case['wire']);raw=bytearray(base64.b64decode(doc['Networks'][0]['Payload']));raw[-1]^=1;doc['Networks'][0]['Payload']=base64.b64encode(raw).decode()
  with self.assertRaises(codec.DecodeError):catalog.run(json.dumps(doc).encode())
 def test_schema_duplicates_depth_and_size_fail(self):
  for raw in (b'',b'<html/>',b'{"Version":"1","Version":"2"}',b'x'*(codec.MAX_BYTES+1),b'{"Version":"x","Servers":[],"Networks":[]}',b'{"Version":NaN}'):
   with self.assertRaises(ValueError):catalog.run(raw)
 def test_worker_catalog_file_and_inventory_are_complete(self):
  from cloud.workers.python.engine import decode_provider_catalog,decode_file,load_file_engines,load_runtime_file_engines
  for kind in ('catalog','file'):
   case=next(x for x in V['documents'] if x['kind']==kind and x['mode']=='export')
   result=decode_provider_catalog('enaa-tunnel',case['wire'].encode()) if kind=='catalog' else decode_file('enaa',case['wire'].encode())
   expected=case['expected'] if kind=='catalog' else {'application':'Enaa Tunnel','extension':'.enaa','config':case['expected']}
   self.assertEqual(result['structuredJson'],expected);self.assertEqual(json.loads(result['rawText']),expected);self.assertFalse(result['isPartial'])
   if kind=='catalog':self.assertFalse(result['exporterCertified'])
  self.assertEqual(len(load_file_engines()),240);self.assertEqual(len(load_runtime_file_engines()),267)
 def test_cli_runs_outside_checkout_and_errors_are_sanitized(self):
  case=V['documents'][0];r=subprocess.run([sys.executable,str(APP/'file_decoder.py'),'-'],input=case['wire'].encode(),capture_output=True,cwd='/tmp',timeout=20)
  self.assertEqual(r.returncode,0);self.assertEqual(json.loads(r.stdout)['config'],case['expected']);self.assertEqual(r.stderr,b'')
  class Opener:
   def open(self,r,timeout):
    assert r.full_url==catalog.SOURCE and r.get_header('User-agent')=='Enaa Tunnel' and timeout==25
    raise HTTPError(catalog.SOURCE,403,'private-sentinel',{},None)
  with patch.object(catalog,'build_opener',return_value=Opener()):
   with self.assertRaises(codec.DecodeError) as e:catalog.download()
   self.assertNotIn('private-sentinel',str(e.exception))
  with self.assertRaises(codec.DecodeError):catalog._NoRedirect().redirect_request(None,None,None,None,None,None)
if __name__=='__main__':unittest.main()
