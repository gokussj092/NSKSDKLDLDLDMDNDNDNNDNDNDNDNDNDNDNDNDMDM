#!/usr/bin/env python3
"""Generate independent Phase E Android file fixtures from original Python engines.

27 registered suffixes, 13 source modules, source bytes and exact Python result
strings; no private user configurations, network I/O or nondeterministic keys.
"""
from __future__ import annotations
import argparse
import base64
import gzip
import hashlib
import hmac
import json
import struct
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from scripts.android_a24_catalog import generate as audited_android_catalog
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Util.Padding import pad
from decoders.Python import (
    sentinel,itv,eut,v2box_export,slipnet,juanscript,wyrlite,wyrvpn,
    intvpn,fthp,ar_pro,ec,xor_family
)
from spdecode.registry import DECODER_REGISTRY
from tests.test_config_batch_crypto_b import ec_encrypt

MODULES={name+".py":module for name,module in (
    ("sentinel",sentinel),("itv",itv),("eut",eut),("v2box_export",v2box_export),
    ("slipnet",slipnet),("juanscript",juanscript),("wyrlite",wyrlite),
    ("wyrvpn",wyrvpn),("intvpn",intvpn),("fthp",fthp),("ar_pro",ar_pro),
    ("ec",ec),("xor_family",xor_family))}
B=lambda data:base64.b64encode(data).decode("ascii")
NONCE=bytes(range(12))
SALT=bytes(range(16))
DOC={"Server":"test.invalid","Port":443,"Enabled":False,"Note":"日本語","Empty":"","Nested":{"number":7}}
def js(data):return json.dumps(data,ensure_ascii=False,separators=(",",":")).encode("utf-8")
def gcm(key,clear,nonce=NONCE):
    engine=AES.new(key,AES.MODE_GCM,nonce=nonce)
    ct,tag=engine.encrypt_and_digest(clear)
    return ct+tag
def aesCbc(key,iv,clear):return AES.new(key,AES.MODE_CBC,iv).encrypt(pad(clear,16))

def encrypt_sources():
    data={}
    # E.1 source algorithms
    salt=SALT; key=hashlib.sha256(sentinel.KEY_A+salt).digest()
    raw=gcm(key,js(DOC))
    inner={"keySalt":B(salt),"iv":B(NONCE),"hmac":B(hmac.digest(key,NONCE+raw,"sha256")),"data":B(raw)}
    outer=js({"version":1,"configData":inner,"name":"Sample"})
    clear=b"STCF"+bytes([1])+outer
    transformed=bytearray(b^sentinel.KEY_A[i%32] for i,b in enumerate(clear))
    for i in range(0,len(transformed),32):
        if i+16<len(transformed):transformed[i:i+16]=transformed[i:i+16][::-1]
    data["sentinel.py"]=bytes(transformed)

    xml=b'<entry key="Server">test.invalid</entry><entry key="Port">443</entry>'
    data["itv.py"]=bytes(range(32))+NONCE+AES.new(bytes(range(32)),AES.MODE_GCM,nonce=NONCE).encrypt(xml)

    eutKey=eut.EUTDecoder.pad_key(eut.EUTDecoder.AES_KEY);iv=SALT
    nested=B(aesCbc(eutKey,iv,js(DOC)))+":"+B(iv)
    content=js({"settings":nested,"Enabled":False})
    data["eut.py"]=("eut-settings://"+B(aesCbc(eutKey,iv,content))+":"+B(iv)).encode()

    wrapper={"magic":"v2box_export","nonce":B(NONCE),
             "tag":B(gcm(v2box_export.V2BOX_KEY,js(DOC))[-16:]),
             "ciphertext":B(gcm(v2box_export.V2BOX_KEY,js(DOC))[:-16]),
             "isPasswordProtected":False}
    data["v2box_export.py"]=B(js(wrapper)).encode()

    parts=[""]*44;parts[0]="3";parts[1]="SSH";parts[2]="Synthetic";parts[3]="slip.example"
    parts[14]="sshuser";parts[15]="sshpass";parts[28]="443"
    ct=gcm(bytes.fromhex("214f052025b2f949605a5429ec3d5fa80c2022c168ad946e68852d447214dbd3"),
           "|".join(parts).encode())
    data["slipnet.py"]=("slipnet-enc://"+B(NONCE+ct)).encode()

    compressed=gzip.compress(js(DOC),mtime=0)
    jkey=hashlib.pbkdf2_hmac("sha256",juanscript.DEFAULT_PASSWORD.encode(),SALT,120000,32)
    body=struct.pack(">I",len(SALT))+SALT+struct.pack(">I",len(NONCE))+NONCE+gcm(jkey,compressed)
    token=B(body).rstrip("=")
    digest=hashlib.sha256(token.encode()).hexdigest()[:16]
    data["juanscript.py"]=("2:"+token+"."+digest).encode()

    # E.2 source algorithms
    chacha=ChaCha20_Poly1305.new(key=wyrlite.V2_HARDCODED_KEY,nonce=NONCE)
    encrypted,tag=chacha.encrypt_and_digest(js(DOC))
    data["wyrlite.py"]=B(NONCE+tag+encrypted).encode()

    wyrInner=gcm(wyrvpn.KEY.encode(),b"nested.host")
    wyrDoc={"Server":"wyr.example","sni":B(b"v01"+NONCE+wyrInner),"Port":443}
    data["wyrvpn.py"]=("wyrvpn://"+B(b"v01"+NONCE+gcm(wyrvpn.KEY.encode(),js(wyrDoc)))).encode()

    intInner=gcm(intvpn.K,b"nested.int")
    nested="djAx"+B(NONCE)+B(intInner)
    intDoc={"Server":"int.example","Nested":{"sni":nested},"Port":443}
    data["intvpn.py"]=("intvpn://djAx"+B(NONCE)+B(gcm(intvpn.K,js(intDoc)))).encode()

    fkey=hashlib.pbkdf2_hmac("sha256",b"furious0982",SALT,1000,16)
    data["fthp.py"]=(".".join((B(SALT),B(NONCE),B(gcm(fkey,js(DOC)))))).encode()

    encryptedField=AES.new(ar_pro.FIELD_KEY.key,AES.MODE_CFB,
        iv=ar_pro.FIELD_KEY.iv,segment_size=128).encrypt(b"nested.sni")
    arDoc={**DOC,"SNIHost":B(encryptedField)}
    data["ar_pro.py"]=B(aesCbc(ar_pro.MAIN_KEY.key,ar_pro.MAIN_KEY.iv,js(arDoc))).encode()

    data["ec.py"]=B(ec_encrypt(js(DOC))).encode()
    xorKey=xor_family.XORDecoder.XOR_KEY
    innerXor=bytes(b^xorKey[i%len(xorKey)] for i,b in enumerate(b"nested.sni")).hex()
    xorDoc={**DOC,"SNIHost":innerXor}
    data["xor_family.py"]=bytes(b^xorKey[i%len(xorKey)] for i,b in enumerate(js(xorDoc))).hex().encode()
    assert len(data)==13
    return data

def generate():
    catalog=audited_android_catalog()
    entries=[x for x in catalog["entries"] if x["migrationPhase"]=="E"]
    if len(entries)!=27:raise ValueError(f"Expected 27 E formats, found {len(entries)}")
    src=encrypt_sources()
    vectors=[]
    for row in sorted(entries,key=lambda x:x["suffix"]):
        moduleName=row["script"].rsplit("/",1)[-1]
        raw=src[moduleName]
        result=MODULES[moduleName].run(raw)
        if result is None:raise ValueError(f"Python {moduleName} failed {row['suffix']}")
        if result.startswith("[Error]"):raise ValueError(f"Python error {row['suffix']}")
        vectors.append({"suffix":row["suffix"],"module":moduleName,"mode":"outer",
            "encodedInput":B(raw),"expected":result})
    # Extra cases verify both AES-GCM/ChaCha WyrLite profiles, SlipNet optional
    # header, FTHP second password, password-protected V2Box and exact field data.
    key=hashlib.pbkdf2_hmac("sha256",wyrlite.DEFAULT_PASSWORD.encode(),b"",10000,32)
    wyrlAES= B(NONCE+gcm(key,js(DOC))[-16:]+gcm(key,js(DOC))[:-16]).encode()
    extra=[
        ("wyrlite","wyrlite.py","aes_gcm",wyrlAES),
        ("slipnet","slipnet.py","optional_header",b"slipnet-enc://"+
         B(b"\x01"+base64.b64decode(src["slipnet.py"].split(b"://",1)[1])).encode()),
    ]
    fkey2=hashlib.pbkdf2_hmac("sha256",b"Version6",SALT,1000,16)
    extra.append(("fthp","fthp.py","secondary_key",
                  (".".join((B(SALT),B(NONCE),B(gcm(fkey2,js(DOC)))))).encode()))
    locked={"magic":"v2box_export","nonce":B(NONCE),"tag":B(b"\x00"*16),
            "ciphertext":B(b"\x00"*16),"isPasswordProtected":True}
    extra.append(("v2box","v2box_export.py","password_required",B(js(locked)).encode()))
    for suffix,moduleName,mode,raw in extra:
        output=MODULES[moduleName].run(raw)
        if output is None:raise ValueError(f"Cannot decode {mode}: {suffix}")
        vectors.append({"suffix":suffix,"module":moduleName,"mode":mode,
                        "encodedInput":B(raw),"expected":output})
    return {"schemaVersion":1,"suffixCount":27,"caseCount":len(vectors),
            "modules":sorted(MODULES),"vectors":vectors}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--fixtures",type=Path,required=True)
    args=ap.parse_args()
    doc=generate()
    args.fixtures.parent.mkdir(parents=True,exist_ok=True)
    args.fixtures.write_text(json.dumps(doc,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(f"[E] {doc['suffixCount']} aliases, {doc['caseCount']} source reference vectors")

if __name__=="__main__":main()
