"""Bounded family-5 wrap hypotheses informed by the original JNI argument trace.

The trace passes HWID, seed, password-derived bytes and empty info; it does
not pass build/features. No password, HWID or key value is enumerated.
"""
import importlib.util,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.HTTP_Custom.codec import open_envelope

def main():
    script,samples=map(Path,sys.argv[1:3]);auth=json.load(sys.stdin)
    s=importlib.util.spec_from_file_location('r',script);r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
    for p in sorted(samples.glob('*.hc')):
        e=open_envelope(p.read_bytes())
        if (e.get('b'),e.get('e'))!=(12,'n16'):continue
        if not (1<=e['l']<=10 and 8192<=e['m']<=256*1024*1024):raise ValueError('KDF limits')
        salt=bytes.fromhex(e['g']);aad=r._aad_base_v4(e,True)
        pw=r._argon2id13(auth['password'].encode(),salt[:16],e['l'],e['m'])
        results=[]
        for mode,device in [('as-provided',auth['hwid'].strip().encode()),('historical-uppercase',r._v4_norm_hwid(auth['hwid']))]:
            for prefix in (0xf1,0xf2):
                folded=r._finish_hmac_state_v4(r.N15_OPAD_STATE,
                    r._finish_hmac_state_v4(r.N15_IPAD_STATE,bytes([prefix])+r.V4_CERT_DIGEST+device))
                for label in (b'hc-config-hwid-wrap-v12',b'hc-config-hwid-v12',b'hc-config-wrap-v12'):
                    key=r._hkdf_sha256(folded+pw,salt,label);ok=False
                    for slot in e['o']:
                        try:opened=r._xchacha20poly1305_decrypt(key,bytes.fromhex(slot['a']),aad+b'\0w',bytes.fromhex(slot['b']));ok=len(opened)==32
                        except r.HCDecryptError:pass
                    results.append({'normalization':mode,'domain_prefix':hex(prefix),'label':label.decode(),'slot_authenticated':ok})
        print(json.dumps({'sample':p.name,'hypotheses':results},ensure_ascii=False))
if __name__=='__main__':main()
