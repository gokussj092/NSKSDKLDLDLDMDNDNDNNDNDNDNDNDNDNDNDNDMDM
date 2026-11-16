"""Check whether n16 reuses n15's content family, separately from its HWID slot.

Fixed structural hypotheses, owner-provided credentials, and all AEAD tags
must verify. This never reports JSON from an unauthenticated stream.
"""
import importlib.util,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.HTTP_Custom.codec import open_envelope
from decode_batch import decode

def main():
    script,samples=map(Path,sys.argv[1:3]);auth=json.load(sys.stdin)
    s=importlib.util.spec_from_file_location('r',script);r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
    r._open_outer_v4=open_envelope
    for path in sorted(samples.glob('*.hc')):
        raw=path.read_bytes();e=open_envelope(raw)
        if (e.get('b'),e.get('e'))!=(12,'n16'):continue
        salt=bytes.fromhex(e['g']);aad=r._aad_base_v4(e,bool(e.get('h')))
        if not (1<=e['l']<=10 and 8192<=e['m']<=256*1024*1024):raise ValueError('KDF limits')
        pw=r._argon2id13(auth['password'].encode(),salt[:16],e['l'],e['m'])
        for name,pk in [('n15-content-with-password',pw),('n15-content-password-only-in-slot',b'')]:
            key=r._derive_n15(salt,aad,pk)
            r._v4_section_material=lambda env,password=None,hwid=None,k=key:(k,aad,12)
            try:
                result=decode(r,raw,auth)
                print(json.dumps({'sample':path.name,'hypothesis':name,'all_layers_authenticated':True,'profiles':len(result['profiles'])}))
            except r.HCDecryptError:print(json.dumps({'sample':path.name,'hypothesis':name,'all_layers_authenticated':False}))
if __name__=='__main__':main()
