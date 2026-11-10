"""Preserve the failed/corrective field-layer research without private output.

This is a manual local-file recipe, never an unattended F7/connection adapter.
Only existing format variants and the supplied library are inspected.
"""
import argparse,base64,json,string,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.HTTPCUSTOM import HCDecryptor as D,HCConstants as C
from Crypto.Cipher import ChaCha20,ChaCha20_Poly1305,AES
from Crypto.Util.Padding import unpad

def main():
    p=argparse.ArgumentParser();p.add_argument('sample',type=Path);a=p.parse_args()
    raw=a.sample.read_bytes()
    outer=json.loads(D._abc_decrypt(D._extract_initial_payload(raw,'e382e4b8adc386f09f9293'),C.CHACHA_KEYS[5]))
    cfg=outer['cfg'];slots=D._abc_decrypt(cfg['content'],C.CHACHA_KEYS[1]).split('[splitConfig]')
    nonce=(cfg['b']*2).encode()[:8];encrypted=bytes.fromhex(slots[26])
    data=D._abc_decrypt(slots[26],C.CHACHA_KEYS[2],nonce).encode()
    print('authenticated_container_shape',outer['verCfg'],cfg['verApp'],len(slots))
    # This failed check motivated inspecting the native libsodium framing.
    try:ChaCha20_Poly1305.new(key=C.CHACHA_KEYS[2],nonce=nonce).decrypt_and_verify(encrypted[:-16],encrypted[-16:]);ietf=True
    except ValueError:ietf=False
    print('pycryptodome_ietf_mac_accepts',ietf)
    inner=base64.b64decode(data,validate=True)
    allowed=set((string.ascii_letters+string.digits+'+/=').encode())
    for period in (8,10,16,20,32):
        counts=[sum(all((v^k)in allowed for v in inner[i::period])for k in range(256))for i in range(period)]
        print('base64_xor_constraints',period,counts)
    # Known historical double-Base64 masks fail; shifting the already-known
    # historical pattern by 24 matches the observed build-565 local format.
    for name,key in [('historical',C.JKL_KEY_OLD),('native3',C.JKL_KEY_NEW),
                     ('observed565',bytes((v+24)%256 for v in C.JKL_KEY_OLD))]:
        try:
            out=base64.b64decode(bytes(v^key[i%20]for i,v in enumerate(inner)),validate=True)
            obj=json.loads(out.decode());print('layer_candidate',name,'json_bytes',len(out),'keys',list(obj))
        except (ValueError,UnicodeError):print('layer_candidate',name,'not-json')
    # The 16-byte historical slot must not be guessed into arbitrary text.
    block=bytes.fromhex(slots[17]);hits=[]
    for category,keys in [('rst',C.RST_KEYS),('historical_format',C.CHACHA_KEYS)]:
        for index,key in enumerate(keys):
            try:
                text=unpad(AES.new(key,AES.MODE_ECB).decrypt(block),16)
                hits.append((category,index,len(text)))
            except ValueError:pass
    print('unresolved_slot17_known_aes_candidates',hits)
    print('slot24_is_existing_split_marker',slots[24]=='[splitPsiphon][splitPsiphon]')
if __name__=='__main__':main()
