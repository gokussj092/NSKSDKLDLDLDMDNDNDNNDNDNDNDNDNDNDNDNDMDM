#!/usr/bin/env python3
"""Check original bounded ARM64 primitives against JCA and Python on real fields."""
import argparse,base64,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from native_oracle import NativePrimitives
from verify import dispatch,oracle
from decoders.Python.apps.Xhypher_Tunnel_Pro import codec
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args();d=a.private
    lib=d/'unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libovpn3.so'
    entries=dispatch(json.loads((d/'outer.json').read_text()));rows=[]
    for mode in range(3):
        unique=list(dict.fromkeys(v for _,_,m,v in entries if m==mode))
        rows.extend((mode,v) for v in sorted(unique,key=len)[:3])
    expected=oracle(rows)
    for (mode,text),plain in zip(rows,expected):
        native=NativePrimitives(lib)
        if mode==0:
            raw=unpad(AES.new(codec.KEY16,AES.MODE_CBC,codec.MATERIAL['IV']).decrypt(base64.b64decode(text)),16)
            assert native.xxtea(raw,codec.KEY16).decode()==plain
        elif mode==1:
            raw=base64.b64decode(text);clear=native.threefish(raw,codec.HKDF32)
            size=(len(clear.rstrip(b'\0'))+15)//16*16
            assert unpad(AES.new(codec.HKDF16,AES.MODE_CBC,codec.MATERIAL['IV']).decrypt(clear[:size]),16).decode()==plain
        else:
            raw=native.invisible(text);assert raw==codec.decode_invisible(text)
            clear=native.xxtea(raw,codec.PBKDF32)
            assert unpad(AES.new(codec.PBKDF32,AES.MODE_CBC,clear[:16]).decrypt(clear[16:]),16).decode()==plain
    report={'status':'VERIFIED_REAL','nativeFields':len(rows),'perMode':3,'originalArm64EqualJCAAndPython':True,
      'scope':'isolated XXTEA, Threefish and invisible carrier; no JNI or Android startup'}
    (d/'native-verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
