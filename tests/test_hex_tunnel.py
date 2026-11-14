"""Complete file parity against independent JCA fixtures; never use user profiles."""
import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'decoders/Python/apps/Hex_Tunnel'
spec=importlib.util.spec_from_file_location('hex_tunnel_reader',APP/'file_decoder.py')
reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
V=json.loads((ROOT/'tests/golden/hexcm_vectors.json').read_text())['documents']
VALID=[c for c in V if not c.get('reject')]

class HexTunnelTests(unittest.TestCase):
    def test_full_independent_documents_both_variants_and_lock_values(self):
        self.assertEqual(len(VALID),12)
        for case in VALID:
            with self.subTest(case=case['name']):
                doc,method=reader.decode_with_method(case['wire'].encode())
                self.assertEqual(doc,case['expected'])
                self.assertEqual(doc['server']['future'],case['expected']['server']['future'])
                self.assertEqual('chacha' in method,case['variant']=='double')
                out=json.loads(reader.run(case['wire'].encode()))
                self.assertEqual(out['config'],case['expected']);self.assertTrue(out['signatureVerified'])
    def test_all_authenticated_but_invalid_documents_fail_without_partial_result(self):
        for case in V:
            if case.get('reject'):
                with self.subTest(case=case['name']),self.assertRaises(reader.DecodeError):
                    reader.run(case['wire'].encode())
    def test_outer_authentication_truncation_and_unrelated_data_are_rejected(self):
        for case in VALID:
            raw=bytearray(base64.b64decode(case['wire']));raw[-1]^=1
            for wire in (base64.b64encode(raw),case['wire'][:40].encode(),b'{}',b'<html/>',b''):
                with self.assertRaises(reader.DecodeError):reader.run(wire)
    def test_wrong_types_and_input_budget_are_bounded(self):
        for data in (None,'text',b'x'*(reader.MAX_BYTES+1)):
            with self.assertRaises(reader.DecodeError):reader.decode_file(data)
    def test_base64_line_breaks_are_supported(self):
        wire=VALID[0]['wire'];wrapped='\r\n'.join(wire[i:i+64] for i in range(0,len(wire),64))
        self.assertEqual(reader.decode_file(wrapped.encode()),VALID[0]['expected'])
    def test_cli_runs_as_one_file_outside_checkout(self):
        p=subprocess.run([sys.executable,str(APP/'file_decoder.py'),'-','--raw'],input=VALID[0]['wire'].encode(),
            cwd='/tmp',capture_output=True,timeout=20)
        self.assertEqual(p.returncode,0);self.assertEqual(json.loads(p.stdout),VALID[0]['expected']);self.assertEqual(p.stderr,b'')
        p=subprocess.run([sys.executable,str(APP/'file_decoder.py'),'-'],input=b'private-input-sentinel',
            cwd='/tmp',capture_output=True,timeout=20)
        self.assertEqual(p.returncode,1);self.assertEqual(p.stdout,b'');self.assertNotIn(b'sentinel',p.stderr)
    def test_cloud_worker_returns_whole_configuration(self):
        from cloud.workers.python.engine import decode_file
        for case in VALID:
            out=decode_file('hexcm',case['wire'].encode())
            self.assertFalse(out['isPartial']);self.assertEqual(out['structuredJson']['config'],case['expected'])
            self.assertEqual(json.loads(out['rawText'])['config'],case['expected'])
    def test_cloud_rejects_corruption_and_unneeded_id_credentials(self):
        from cloud.workers.python.engine import decode_file, DecodeFailure
        raw=bytearray(base64.b64decode(VALID[0]['wire']));raw[-1]^=1
        with self.assertRaises(DecodeFailure) as failure:
            decode_file('hexcm',base64.b64encode(raw))
        self.assertEqual(failure.exception.code,'DECODE_FAILED')
        with self.assertRaises(DecodeFailure) as failure:
            decode_file('hexcm',VALID[0]['wire'].encode(),credentials={'hwid':'synthetic-id'})
        self.assertEqual(failure.exception.code,'CREDENTIALS_NOT_ALLOWED')
    def test_cloud_catalog_is_file_only_and_c0_is_unchanged(self):
        from cloud.workers.python.engine import load_file_engines,load_runtime_file_engines
        self.assertEqual(len(load_file_engines()),240);self.assertEqual(len(load_runtime_file_engines()),267)
        self.assertNotIn('hexcm',load_file_engines())
        entries=json.loads((ROOT/'cloud/web/content/file-formats.json').read_text())['formats']
        entry=next(x for x in entries if x['suffix']=='hexcm')
        self.assertEqual(entry,{'suffix':'hexcm','name':'Hex Tunnel / HexVPN 1.7.3-Rev','kind':'file',
            'offlineSupported':False,'cloudSupported':True,'credentialFields':['password']})
    def test_bot_routes_exact_extension(self):
        from spdecode.registry import get_supported_extension,DECODER_REGISTRY
        self.assertEqual(get_supported_extension('profile.HEXCM'),'hexcm')
        self.assertEqual(DECODER_REGISTRY['hexcm'].script,'decoders/Python/apps/Hex_Tunnel/file_decoder.py')

if __name__=='__main__':unittest.main()
