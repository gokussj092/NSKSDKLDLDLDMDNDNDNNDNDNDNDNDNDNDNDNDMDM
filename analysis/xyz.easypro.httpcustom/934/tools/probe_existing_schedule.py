"""Test the previously verified KDF on new schemas, without emitting cleartext.

This is an explicitly unverified compatibility experiment, not a decoder.
Credentials arrive on stdin and are never logged.
"""
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.HTTP_Custom import codec as c
h=c.historical

def candidate(e,auth,diagnose=False):
    seed=h._env_key(e);features=h._features(e);build=h._n_bytes(e)
    locked=e['e'] in ('n16','n18');device=h._norm_hwid(auth.get('hwid')) if locked else None
    t=b'HCCFG\0'+c.PKG+b'\0' +b'1\0'+features+b'\0'+build+b'\0'
    if device is not None:t+=b'hwid\0'+device+b'\0'
    ikm=(h._c0 if '--historical-fold' in sys.argv else c.native_fold)(t+seed);protection=b'|0'
    if h._h_flag(e):
        pk,protection=h._pw_kdf(e,auth.get('password'),seed);ikm+=pk
    info=b'app-config|'+e['e'].encode()+b'|'+c.PKG+b'|1|'+features+b'|'+build
    if device is not None:info+=b'|hwid|'+device
    key=h._hkdf(ikm,seed,info)
    aad=(b'HCCFG|'+str(e['b']).encode()+b'|XCHACHA20P1305|NATIVE-HKDF-SHA256|'
         +e['e'].encode()+b'|'+c.PKG+b'|1|'+features+protection+b'|'+build)
    if locked:
        for slot in e['o']:
            try:key=h._xdec(key,bytes.fromhex(slot['a']),aad+b'\0w',bytes.fromhex(slot['b']));break
            except h.HCError:pass
    if diagnose:return key,aad
    return h._dec_section(e['i'],key,aad)

def main():
    auth=json.load(sys.stdin)
    for path in sorted(Path(sys.argv[1]).glob('*.hc')):
        e=c.open_envelope(path.read_bytes())
        if e['b']!=12:continue
        try:
            plain=candidate(e,auth);json.loads(plain)
            print(path.name,'MAIN_AUTHENTICATED',len(plain))
        except Exception as error:
            # Stream-only output is used exclusively to reject a KDF hypothesis.
            # It is never returned as decoded user data or saved as cleartext.
            from Crypto.Cipher import ChaCha20_Poly1305
            key,aad=candidate(e,auth,True)
            section=e['i'];cipher=ChaCha20_Poly1305.new(key=key,nonce=bytes.fromhex(section['b']))
            plain=cipher.decrypt(bytes.fromhex(section['c'])[:-16])
            try:json.loads(plain);looks_json=True
            except (ValueError,UnicodeError):looks_json=False
            print(path.name,type(error).__name__,str(error),'diagnostic_json_shape',looks_json)

if __name__=='__main__':main()
