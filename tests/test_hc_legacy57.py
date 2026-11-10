"""Complete HC revision-57 records vs frozen libsodium/native JNI goldens."""
import base64,gzip,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from decoders.Python import _hc_legacy57 as codec
from decoders.Python.HTTPCUSTOM import run
from cloud.workers.python.engine import decode_file,DecodeFailure

ROOT=Path(__file__).resolve().parents[1]
FIXTURE=json.loads((ROOT/'tests/golden/hc_legacy57.json').read_text())
if FIXTURE.get('encoding')=='gzip+base64':FIXTURE=json.loads(gzip.decompress(base64.b64decode(FIXTURE['payload'])))
CASES=FIXTURE['cases']

def wire(case,carrier=0):
    value=base64.b64decode(case['data'])
    for _ in range(carrier):value=value.decode('latin-1').encode('utf-8')
    return value

class Legacy57Tests(unittest.TestCase):
    def test_complete_record_all_32_slots_and_metadata(self):
        for name,case in CASES.items():
            if case['tamper']:continue
            for carrier in (0,1,2,5):
                with self.subTest(name=name,carrier=carrier):
                    actual=codec.decode(wire(case,carrier))
                    self.assertEqual(actual,case['expected'])
                    self.assertEqual(len(actual['Config']),32)
                    self.assertIn('unknown22',actual['Config'])
                    self.assertIn('psiphon2',actual['Config'])
                    self.assertEqual(json.loads(run(wire(case,carrier))),actual)
                    self.assertEqual(json.loads(actual['Config']['v2rayConfig']),
                        json.loads(case['expected']['Config']['v2rayConfig']))

    def test_original_build564_native_string_vectors(self):
        fixture=json.loads((ROOT/'analysis/xyz.easypro.httpcustom/564/generated/native_codec_vectors.json').read_text())
        for case in fixture['vectors']:
            with self.subTest(algorithm=case['algorithm']):
                self.assertEqual(codec.field_layers(case['encoded'],representation=f"native{case['algorithm']}"),case['plaintext'])

    def test_each_authenticated_layer_and_inner_json_reject_corruption(self):
        for name,case in CASES.items():
            if not case['tamper']:continue
            for carrier in (0,1,2):
                with self.subTest(name=name,carrier=carrier):
                    with self.assertRaises((ValueError,UnicodeError)):
                        codec.decode(wire(case,carrier))

    def test_cloud_worker_keeps_structure_and_reports_unresolved_fields(self):
        for name in ('build564-hwid0','build565-hwid1','unresolved'):
            case=CASES[name]
            with self.subTest(name=name):
                result=decode_file('hc',wire(case,1))
                self.assertEqual(result['structuredJson'],case['expected'])
                self.assertEqual(result['isPartial'],name=='unresolved')
                self.assertEqual(result['warnings'],['HC_UNRESOLVED_FIELDS']if name=='unresolved'else[])
        with self.assertRaises(DecodeFailure):decode_file('hc',wire(CASES['bad-field'],1))

    def test_standalone_canonical_and_provider_cli_return_complete_json(self):
        with tempfile.TemporaryDirectory()as folder:
            file=Path(folder)/'synthetic.hc';case=CASES['build565-hwid1'];file.write_bytes(wire(case,1))
            for script in ('decoders/Python/HTTPCUSTOM.py','decoders/Python/apps/HTTP_Custom/file_decoder.py'):
                with self.subTest(script=script):
                    result=subprocess.run([sys.executable,str(ROOT/script),str(file)],cwd=folder,capture_output=True,timeout=15)
                    self.assertEqual(result.returncode,0,result.stderr.decode())
                    self.assertEqual(json.loads(result.stdout),case['expected'])

def native_parity(executable):
    from tests.test_offline_hc_native_parity import call
    count=0
    for name,case in CASES.items():
        for carrier in ((0,1,2)if case['tamper']else(0,1,2,5)):
            result=call(executable,wire(case,carrier))
            if case['tamper']:
                assert result.returncode!=0 and not result.stdout,(name,carrier,'corrupt input accepted')
            else:
                assert result.returncode==0,(name,carrier,result.stderr.decode()[:180])
                assert json.loads(result.stdout)==case['expected'],(name,carrier,'complete JSON differs from independent fixture')
            count+=1
    print(f'PASS: HC revision 57 complete fields, metadata and integrity: {count} native cases')
    return count

if __name__=='__main__':unittest.main()
