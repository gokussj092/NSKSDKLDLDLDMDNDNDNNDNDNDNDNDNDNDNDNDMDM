"""Independent AEAD backend and KDF port on private samples; negative checks.

No plaintext/keys are logged. The original reader's AEAD implementation is
replaced by PyCryptodome for the second verification, with tag checks intact.
"""
import argparse,importlib.util,json
from pathlib import Path
import sys
from Crypto.Cipher import ChaCha20_Poly1305
from n15_content import derive
from decode_batch import decode

def load(path):
    s=importlib.util.spec_from_file_location('hc_revision',path)
    r=importlib.util.module_from_spec(s);s.loader.exec_module(r);return r

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('reader',type=Path);p.add_argument('samples',type=Path);a=p.parse_args()
    auth=json.load(sys.stdin);r=load(a.reader)
    original_material=r._v4_section_material;original_aead=r._xchacha20poly1305_decrypt
    reports=[]
    for path in sorted(a.samples.glob('*.hc')):
        raw=path.read_bytes()
        try:expected=decode(r,raw,auth)
        except r.HCDecryptError:continue
        calls=[]
        def aead(key,nonce,aad,ct):
            cipher=ChaCha20_Poly1305.new(key=key,nonce=nonce);cipher.update(aad)
            try:value=cipher.decrypt_and_verify(ct[:-16],ct[-16:])
            except ValueError as error:raise r.HCDecryptError('independent AEAD authentication failed') from error
            calls.append(len(value));return value
        def material(env,password=None,hwid=None):
            if (env.get('b'),env.get('e'))!=(12,'n15'):return original_material(env,password,hwid)
            aad=r._aad_base_v4(env,bool(env.get('h')));seed=bytes.fromhex(env['g'])
            pk=r._argon2id13(password.encode(),seed[:16],env['l'],env['m']) if env.get('h') else b''
            return derive(seed,aad,pk),aad,12
        try:
            r._v4_section_material=material;r._xchacha20poly1305_decrypt=aead
            actual=decode(r,raw,auth)
            assert actual==expected,'Independent backend/port mismatch'
            verified_calls=len(calls)
            tampered=bytearray(raw);tampered[-1]^=1
            try:decode(r,bytes(tampered),auth)
            except (ValueError,UnicodeError):outer_rejected=True
            else:raise AssertionError('Tampered outer accepted')
            wrong_password_rejected=None
            if expected['format']['h']:
                try:decode(r,raw,{**auth,'password':'synthetic-wrong-password'})
                except r.HCDecryptError:wrong_password_rejected=True
                else:raise AssertionError('Wrong password accepted')
            reports.append({'sample':path.name,'full_json_equal':True,'independent_aead_layers':verified_calls,
                            'tampered_outer_rejected':outer_rejected,'wrong_password_rejected':wrong_password_rejected})
        finally:r._v4_section_material=original_material;r._xchacha20poly1305_decrypt=original_aead
    print(json.dumps({'verified':len(reports),'samples':reports},ensure_ascii=False,indent=2))

if __name__=='__main__':main()
