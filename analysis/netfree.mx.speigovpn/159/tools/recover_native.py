#!/usr/bin/env python3
"""Extract app-wide format constants from the pinned ARMv7 library, statically.

KDF at0x17f20, AAD at0x18678, HMAC at0x20d74. No APK/SO code is run.
"""
import argparse,hashlib,json,struct,zipfile
from pathlib import Path
def recover(folder):
    folder=Path(folder);b=(folder/'libspeigoshield.so').read_bytes()
    if hashlib.sha256(b).hexdigest()!='d36f50a2dcd3a6821d041d188ad492e9c6e681913508d05c3bfb10601603f700':raise ValueError('UNINSPECTED_NATIVE')
    # PC-relative loads at17f34/17f40,17f38/17f56,180d4/180d6.
    def rel(pool,pc):return (struct.unpack_from('<I',b,pool)[0]+pc)&0xffffffff
    if rel(0x1831c,0x17f44)!=0x1c28 or rel(0x18320,0x17f5a)!=0x1c70 or rel(0x18324,0x180da)!=0x1c90:raise ValueError('KDF_XREF_CHANGED')
    if b[0x1c28:0x1c3b]!=b'SVR5B2-BASE-KDF-V1\0' or b[0x1c58:0x1c6a]!=b'SVR5B2-REC-KDF-V1\0':raise ValueError('KDF_DOMAIN_CHANGED')
    with zipfile.ZipFile(folder/'base.apk') as z:
        properties=z.read('assets/LICENSE').decode('latin1').splitlines()
    fields=[line.split('=',1)[1].strip().encode() for line in properties if line.startswith('SSH_UDP=')]
    if len(fields)!=1 or fields[0]!=b'Diablo2105AZW8Es':raise ValueError('FIELD_INPUT_CHANGED')
    result={'librarySha256':hashlib.sha256(b).hexdigest(),'machine':'ARMv7 Thumb2','kdfAddress':'0x17f20','aadAddress':'0x18678','hmacAddress':'0x20d74','release':112,
        'signaturePublicKey':b[0x1c01:0x1c21].hex(),'root':b[0x1c90:0x1cb0].hex(),'context':b[0x1c70:0x1c90].hex(),'baseSalt':b[0x18660:0x18670].hex(),
        'recordSalt':'0f34b5982d7ae6c1','aadSalt':'38d6e952af04b17b','signatureSuffix':struct.pack('<Q',(-1976679760609675822)&((1<<64)-1)).hex(),
        'fieldInput':'Diablo2105AZW8Es','scope':'public app-wide file format inputs; no account credentials or remote session','apkCodeExecuted':False}
    (folder/'native-material.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();recover(a.private)
