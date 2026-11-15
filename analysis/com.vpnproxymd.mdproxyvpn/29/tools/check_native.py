#!/usr/bin/env python3
"""Build29 Go CU/DO/decrypt constants and call-site checks; no SO execution."""
import argparse, hashlib, json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'scripts/apk_analysis'))
sys.path.insert(0,str(ROOT))
from go_inspect import GoImage
from decoders.Python.ultra import VPNS_SD

def check(path):
    path=Path(path)
    sha=hashlib.sha256(path.read_bytes()).hexdigest()
    if sha!='f7a1be6ef0cf4939e480cb772dbbaf49e68246a4ca205258e052e4215f015260':raise ValueError('NATIVE_MISMATCH')
    image=GoImage(path); prefix='github.com/2dust/AndroidLibXrayLite.'
    expected={'CU':(0x10195c0,1056),'decrypt':(0x1016040,576),'DO':(0x10169d0,944)}
    for name,layout in expected.items():
        if image.functions.get(prefix+name)!=layout:raise ValueError('LAYOUT_MISMATCH')
    code={name:list(image.disassemble(*v)) for name,v in expected.items()}
    checks={'CU':['0x101960c mov x3, #3','0x1019618 mov x5, #0x31','0x1019624 bl #0x801530 net/http.NewRequestWithContext','0x1019644 mov x1, #0xa','0x1019664 mov x2, #0xc'],
            'decrypt':['0x1016088 bl #0x5854b0 runtime.concatstring2','0x1016140 mov x13, #3','0x1016144 mov x14, #0x2000','0x1016148 mov x15, #1','0x101614c mov x0, #2','0x1016150 bl #0x686740 golang.org/x/crypto/argon2.deriveKey','0x1016154 bl #0x66dd60 crypto/aes.NewCipher','0x101615c bl #0x66c300 crypto/cipher.NewGCM'],
            'DO':['0x1016b74 mov x13, #3','0x1016b78 mov x14, #0x2000','0x1016b7c mov x15, #1','0x1016b80 mov x0, #2','0x1016b84 bl #0x686740 golang.org/x/crypto/argon2.deriveKey']}
    for name,lines in checks.items():
        if not all(line in code[name] for line in lines):raise ValueError('INSTRUCTION_MISMATCH')
    if not any('github.com/2dust/AndroidLibXrayLite.decrypt' in line for line in code['CU']):raise ValueError('CU_DECRYPT_MISSING')
    profile=VPNS_SD['mdproxy']
    if image.read(0x366387,32)!=profile['password'] or image.read(0x34bf1e,16)!=profile['password2']:raise ValueError('CONSTANT_MISMATCH')
    recipe={'method':image.read(0x33e123,3).decode(),'url':image.read(0x37f147,49).decode(),'header':image.read(0x3451d1,10).decode(),'agent':image.read(0x347595,12).decode()}
    if recipe!={'method':'GET','url':profile['url'],'header':'User-Agent','agent':'MD PROXY VPN'}:raise ValueError('REQUEST_MISMATCH')
    return {'nativeSha256':sha,'functions':{k:{'address':hex(v[0]),'bytes':v[1]} for k,v in expected.items()},'recipe':recipe,'argon2id':{'version':19,'memoryKiB':8192,'iterations':3,'parallelism':1,'keyBytes':32},'commonFormatConstantsMatch':True,'apkCodeExecuted':False}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('library',type=Path);p.add_argument('--report',type=Path);a=p.parse_args();r=check(a.library)
    if a.report:a.report.write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps(r))
