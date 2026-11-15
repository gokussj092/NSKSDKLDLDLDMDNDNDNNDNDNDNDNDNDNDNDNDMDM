#!/usr/bin/env python3
"""Fictional fixtures: JCA fields, host libsodium AEAD and synthetic signer."""
import argparse,base64,copy,ctypes as C,hashlib,json,struct
from pathlib import Path
from verify import java,sodium,FIELDS
def make(output):
    lib=sodium();pub=C.create_string_buffer(32);secret=C.create_string_buffer(64)
    lib.crypto_sign_seed_keypair(pub,secret,C.c_char_p(hashlib.sha256(b'SP-DECODE-SPEIGO-SYNTHETIC-SIGNER-ONLY').digest()))
    lib.crypto_sign_detached.argtypes=[C.c_void_p,C.POINTER(C.c_ulonglong),C.c_char_p,C.c_ulonglong,C.c_void_p]
    lib.crypto_aead_xchacha20poly1305_ietf_encrypt.argtypes=[C.c_void_p,C.POINTER(C.c_ulonglong),C.c_char_p,C.c_ulonglong,C.c_char_p,C.c_ulonglong,C.c_void_p,C.c_char_p,C.c_char_p]
    ctx=bytes.fromhex('af9d380863dc5c05851192e82d6fda880ce0346f877ab0c093000c7dbe372194')
    def sign(data):
        message=hashlib.sha256(b'SV5C-SIG-V2\0'+data+bytes.fromhex('d2f5270a3b6c91e4')).digest();sig=C.create_string_buffer(64);n=C.c_ulonglong()
        assert lib.crypto_sign_detached(sig,C.byref(n),message,32,secret)==0
        return data+sig.raw
    def seal(purpose,metadata,records,damage=False):
        meta=json.dumps(metadata,ensure_ascii=False,separators=(',',':')).encode();header=struct.pack('<4sBBHIII',b'SV5C',2,purpose,0,112,len(records),len(meta));mh=hashlib.sha256(meta).digest();out=header+meta
        keys=java(['key\t'+str(purpose)+'\t'+str(i)+'\t'+base64.b64encode(mh).decode() for i in range(len(records))])
        for i,(record,key) in enumerate(zip(records,keys)):
            raw=record if isinstance(record,bytes) else json.dumps(record,ensure_ascii=False,separators=(',',':')).encode();nonce=hashlib.sha256(b'synthetic-nonce'+bytes([purpose,i])).digest()[:24]
            aad=header+mh+bytes.fromhex('38d6e952af04b17b')+struct.pack('<III',112,i,len(raw))+bytes([purpose])+ctx
            encrypted=C.create_string_buffer(len(raw)+16);n=C.c_ulonglong();assert lib.crypto_aead_xchacha20poly1305_ietf_encrypt(encrypted,C.byref(n),raw,len(raw),aad,len(aad),None,nonce,key)==0
            ciphertext=encrypted.raw
            if damage:ciphertext=ciphertext[:-1]+bytes([ciphertext[-1]^1])
            out+=struct.pack('<II',i,len(raw))+nonce+ciphertext
        return sign(out)
    expected={};encoded={};invalid=[]
    for purpose,section in [(1,'Servers'),(2,'Usuarios')]:
        fields=FIELDS['servers' if purpose==1 else 'users'];record={k:'fixture.'+str(i)+'.example.invalid' for i,k in enumerate(fields)}
        record.update({'Plain':'YWJjZA==','Unknown':{'list':[1,None,True]},'NestedJson':'{"example":"ssh.invalid"}'})
        doc={'Version':'fixture159','ReleaseNotes':'Solo prueba ñ 😀\nsegunda línea',section:[{'Presentation':'preserved',**record}]};expected[section]=doc
        packed=copy.deepcopy(record)
        for key,value in zip(fields,java(['seal\t'+base64.b64encode(record[k].encode()).decode() for k in fields])):packed[key]=value.decode()
        meta={**doc,section:[{'Presentation':'preserved'}]};encoded[section]=base64.b64encode(seal(purpose,meta,[packed])).decode()
        if purpose==1:
            invalid.append(seal(purpose,meta,[packed],True))
            for raw in [b'[]',b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":1e999}',b'{"x":"\\ud800"}'] :invalid.append(seal(purpose,meta,[raw]))
            bad=copy.deepcopy(packed);bad[fields[0]]='broken-field.invalid';invalid.append(seal(purpose,meta,[bad]))
            bad=copy.deepcopy(packed);bad['Presentation']='conflict';invalid.append(seal(purpose,meta,[bad]))
            badmeta=copy.deepcopy(meta);badmeta['Servers'].append({'Extra':True});invalid.append(seal(purpose,badmeta,[packed]))
    result={'provenance':'Synthetic .invalid data and separate test Ed25519 signer; cannot sign provider catalogs','testPublicKey':pub.raw.hex(),'configs':encoded['Servers'],'ssh':encoded['Usuarios'],'expectedConfigs':expected['Servers'],'expectedSsh':expected['Usuarios'],'invalid':[base64.b64encode(x).decode() for x in invalid]}
    Path(output).write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('output',type=Path);a=p.parse_args();make(a.output)
