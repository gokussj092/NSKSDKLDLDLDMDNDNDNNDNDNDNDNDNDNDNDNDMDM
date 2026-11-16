"""Seven structural KDF hypotheses, with fixed owner-supplied HWID/password.

Unknown n16 remains unsupported unless the wrapped slot AND all sections pass.
No HWID, password, key or plaintext values are emitted.
"""
import importlib.util,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.HTTP_Custom.codec import open_envelope

def main():
    script,samples=map(Path,sys.argv[1:3]);auth=json.load(sys.stdin)
    spec=importlib.util.spec_from_file_location('supplied_hc',script)
    r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
    for p in sorted(samples.glob('*.hc')):
        raw=p.read_bytes();e=open_envelope(raw)
        if (e.get('b'),e.get('e'))!=(12,'n16'):continue
        salt=bytes.fromhex(e['g']);aad=r._aad_base_v4(e,True);device=r._v4_norm_hwid(auth['hwid'])
        if not (1<=e['l']<=10 and 8192<=e['m']<=256*1024*1024):raise ValueError('KDF limits')
        pw=r._argon2id13(auth['password'].encode(),salt[:16],e['l'],e['m'])
        def fold(data):
            return r._finish_hmac_state_v4(r.N15_OPAD_STATE,
                r._finish_hmac_state_v4(r.N15_IPAD_STATE,b'\xf1'+r.V4_CERT_DIGEST+data))
        kdf=lambda ikm:r._hkdf_sha256(ikm,salt,b'hc-config-content-v12')
        base=kdf(fold(aad)+pw)
        transcript=r._transcript_v4(e,salt,auth['hwid'])
        candidates={
          'content-key-direct-slot':base,
          'aad-pipe-hwid-fold':kdf(fold(aad+b'|hwid|'+device)+pw),
          'aad-zero-hwid-fold':kdf(fold(aad+b'\0hwid\0'+device)+pw),
          'device-in-ikm-before-password':kdf(fold(aad)+device+pw),
          'device-in-ikm-after-password':kdf(fold(aad)+pw+device),
          'new-fold-historical-hwid-transcript':kdf(fold(transcript)+pw),
          'content-key-with-historical-hwid-info':r._hkdf_sha256(base+pw,salt,r._info_v4(e,auth['hwid'])),
        }
        results=[]
        for name,key in candidates.items():
            opened=False
            for slot in e['o']:
                try:
                    secret=r._xchacha20poly1305_decrypt(key,bytes.fromhex(slot['a']),aad+b'\0w',bytes.fromhex(slot['b']))
                    opened=len(secret)==32
                except r.HCDecryptError:pass
            results.append({'hypothesis':name,'slot_authenticated':opened})
        print(json.dumps({'sample':p.name,'hypotheses':results},ensure_ascii=False))

if __name__=='__main__':main()
