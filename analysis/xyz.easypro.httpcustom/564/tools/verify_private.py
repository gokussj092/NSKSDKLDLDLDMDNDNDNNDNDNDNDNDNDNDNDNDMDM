"""Private HC sample: compare server, C++, full field preservation and layers.

Print only counts, package/build metadata, hashes and JSON key names. Never
print profile values, passwords, host names, UUIDs or static format material.
"""
import argparse,base64,hashlib,json,subprocess,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT))
from decoders.Python.HTTPCUSTOM import HCConstants as C,HCDecryptor as D
from decoders.Python._hc_legacy57 import decode,open_seal,JKL_EXPORT_565
from cloud.workers.python.engine import decode_file
from tests.test_offline_hc_native_parity import call

def main():
    p=argparse.ArgumentParser();p.add_argument('sample',type=Path);p.add_argument('native_executable')
    p.add_argument('--output',type=Path);a=p.parse_args();raw=a.sample.read_bytes()
    outer=json.loads(D._abc_decrypt(D._extract_initial_payload(raw,'e382e4b8adc386f09f9293'),C.CHACHA_KEYS[5]))
    cfg=outer['cfg'];nonce=(cfg['b']*2).encode()[:8]
    content=open_seal(bytes.fromhex(cfg['content']),C.CHACHA_KEYS[1],C.STATIC_NONCE)
    slots=content.decode().split('[splitConfig]')
    intermediate=open_seal(bytes.fromhex(slots[26]),C.CHACHA_KEYS[2],nonce)
    one=base64.b64decode(intermediate,validate=True)
    two=bytes(v^JKL_EXPORT_565[i%20]for i,v in enumerate(one))
    clear=base64.b64decode(two,validate=True)
    server=decode_file('hc',raw);native=call(a.native_executable,raw)
    native_json=json.loads(native.stdout)if native.returncode==0 else None
    expected=decode(raw)
    assert server['structuredJson']==expected==native_json,'Cross-consumer JSON differs'
    assert expected['Config']['v2rayConfig'].encode()==clear
    # Exercise the actual broker response gate without any network/service.
    gate=subprocess.run(['node','--input-type=module','-e','''
import {fetchWorker} from './cloud/web/lib/c3-gateway.mjs';
let input='';for await(const chunk of process.stdin)input+=chunk;
process.env.WORKER_INTERNAL_URL='http://decoder-worker:8787';
const reply=await fetchWorker('file',{format:'hc'},{workerToken:'synthetic-test-only'},
  {fetchImpl:async()=>Response.json(JSON.parse(input))});
process.stdout.write(String(reply.status));
'''],input=json.dumps(server),text=True,capture_output=True,cwd=ROOT,timeout=15)
    assert gate.returncode==0 and gate.stdout=='200','Broker rejected intact private result'
    report={'input_sha256':hashlib.sha256(raw).hexdigest(),'input_size':len(raw),
        'declared_app_build':cfg['verApp'],'format_revision':outer['verCfg'],
        'field_count':len(slots),'retained_fields':len(expected['Config']),
        'v2ray_json_bytes':len(clear),'v2ray_json_keys':list(json.loads(clear)),
        'v2ray_layers_bytes':[len(intermediate),len(one),len(clear)],
        'unresolved_fields':expected['UnresolvedFields'],
        'complete_server_native_equality':True,'worker_partial':server['isPartial'],
        'worker_warning_codes':server['warnings'],'broker_response_gate_status':200}
    text=json.dumps(report,indent=2)+'\n'
    if a.output:a.output.write_text(text)
    print(text)
if __name__=='__main__':main()
