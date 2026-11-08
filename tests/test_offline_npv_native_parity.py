"""Native-only NPV differential signed v1/v5/v6, legacy and text fixtures."""
from __future__ import annotations
import base64
import copy
import json
import struct
import subprocess
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from decoders.Python import npvs, npvs_v1, NPVTUNNEL, npvs_identity
from tests.test_npvs_v1_legacy import make_v1
from tests.golden.npvs_protected_generate import make
from decoders.Python.apps.NPV_Tunnel import text_decoder

def call(exe,raw,pw="",identity=""):
    parts=(pw.encode(),identity.encode(),raw)
    framed=b"".join(struct.pack(">I",len(v))+v for v in parts)
    return subprocess.run([exe],input=framed,capture_output=True)

def compare(exe,raw,expected,pw="",identity=""):
    result=call(exe,raw,pw,identity)
    if result.returncode:
        raise AssertionError(("decoder failed",result.stderr.decode(errors="replace")[:300]))
    actual=json.loads(result.stdout)
    assert actual==expected,("parity mismatch",actual,expected)

def negative(exe,raw,pw="",identity=""):
    r=call(exe,raw,pw,identity)
    assert r.returncode!=0,"Unauthenticated NPV input accepted"

def main(exe):
    count=0
    for protected in (False,True):
        inp,cred,plain=make_v1(passphrase=protected,embedded=True)
        pw=(cred or {}).get("password","")
        expected=npvs_v1.decode_npvs_v1_complete(inp,password=pw or None)
        compare(exe,inp,expected,pw)
        count+=1
        negative(exe,inp[:-1]+bytes([inp[-1]^1]),pw);count+=1
        if protected:
            negative(exe,inp,"bad-password");count+=1
            negative(exe,inp);count+=1
    identity=npvs_identity.generate()
    for version in (5,6):
        for recipient in (False,True):
            if version==6 and not recipient:continue
            fixture=make(recipient=recipient,version=version,identity=identity if recipient else None)
            pw="" if recipient else fixture["password"]
            ident=json.dumps(identity) if recipient else ""
            expected=npvs.decode_npvs_complete(fixture["data"],
                **({"recipient_key":identity} if recipient else {"password":pw}))
            compare(exe,fixture["data"],expected,pw,ident);count+=1
            negative(exe,fixture["data"][:-1]+bytes([fixture["data"][-1]^1]),pw,ident);count+=1
            if recipient:
                negative(exe,fixture["data"],pw,"");count+=1
                other=npvs_identity.generate()
                negative(exe,fixture["data"],pw,json.dumps(other));count+=1
            else:
                negative(exe,fixture["data"],"bad-password");count+=1
                negative(exe,fixture["data"]);count+=1
    # Authenticated fields use a fixed mock nonce and inventory MAC; no partial
    # success when altering any tag or layout.
    obj={"configs":[{"host":"example.invalid","port":443,"nested":
        ["npvs1:"+base64.urlsafe_b64encode("日本語".encode()).decode().rstrip("="),False,None]}]}
    payload=json.dumps(obj,ensure_ascii=False,separators=(",",":")).encode()
    wrapped=b"npvt-ssh://"+base64.urlsafe_b64encode(payload).rstrip(b"=")
    compare(exe,wrapped,text_decoder.decode(wrapped.decode()));count+=1
    expected=[obj,obj,{"extra":"preserved"}]
    raw=json.dumps(expected,ensure_ascii=False).encode()
    link=b"npvt://"+base64.b64encode(raw)
    compare(exe,link,text_decoder.decode(link.decode()));count+=1
    negative(exe,b"npvt://!");count+=1
    for source in (b"NPVS",b"NPVT1,wrong,invalid",b"NOT-NPV"):
        negative(exe,source);count+=1
    # Historical whitebox CTR, deliberately synthetic and complete arrays.
    tables=NPVTUNNEL.load_whitebox_state()
    iv=bytes(range(16))
    plain=json.dumps([{"alpha":"example.org","x":None},{"beta":2}]).encode()
    stream=b"";counter=bytearray(iv)
    for i in range(0,len(plain),16):
        stream+=NPVTUNNEL.whitebox_encrypt_block(counter,*tables)
        for k in range(15,-1,-1):
            counter[k]=(counter[k]+1)&255
            if counter[k]:break
    payload=iv+bytes(a^b for a,b in zip(plain,stream))
    for prefix in (b"NPVT1",b"NPVTSUB1"):
        encrypted=prefix+b"meta,"+base64.urlsafe_b64encode(payload).rstrip(b"=")
        compare(exe,encrypted,json.loads(plain));count+=1
    print(f"PASS: NPV signed v1/v5/v6, ECDH, legacy and URI native parity: {count} cases")

if __name__=="__main__":main(sys.argv[1])
