#!/usr/bin/env python3
"""Reproducible, source-derived Phase F parity fixtures.

All encryption is local and produces synthetic non-user data. Every vector is
checked by the original Python decoder before Android is allowed to use it.
No real credentials, sessions, network I/O or personal configurations.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from scripts.android_a24_catalog import generate as audited_android_catalog
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad
from Crypto.Protocol.KDF import PBKDF2
from decoders.Python import flex,izph,n4,crev,ktr,zoba,dev,ltm,vn7
from tests.test_renz_family import threefish_encrypt256_block
from tests.test_renz_legacy_types import legacy_encrypt

SOURCES={
    "flex.py":flex,"izph.py":izph,"n4.py":n4,"crev.py":crev,
    "ktr.py":ktr,"zoba.py":zoba,"dev.py":dev,"ltm.py":ltm,"vn7.py":vn7
}
TEXT={"Server":"test.invalid","Port":443,"Enabled":False,
      "Notes":"Japanese 日本語","Routes":["SSH","V2Ray"]}
IV=bytes(range(16))
NONCE=bytes(range(12))
SALT=bytes(range(32))
def js(obj):return json.dumps(obj,ensure_ascii=False,separators=(",",":")).encode("utf-8")
def b64(raw):return base64.b64encode(raw)
def gcm(key,plain,nonce=NONCE,aad=None):
    cipher=AES.new(key,AES.MODE_GCM,nonce=nonce)
    if aad:cipher.update(aad)
    ct,tag=cipher.encrypt_and_digest(plain)
    return ct+tag
def cbc(key,iv,plain):return AES.new(key,AES.MODE_CBC,iv).encrypt(pad(plain,16))


def xxtea_encrypt(plain:bytes,key:bytes,delta:int)->bytes:
    """Strict modulo-32 inverse of source CREV/Zoba/DEV variant."""
    mask=0xffffffff
    words=[0]*((len(plain)+3)//4+1)
    for i,b in enumerate(plain):words[i//4]|=b<<((i%4)*8)
    words[-1]=len(plain)
    key=key[:16].ljust(16,b"\0")
    k=struct.unpack("<4I",key)
    n=len(words)
    assert n>=2
    total=0
    for _ in range(6+52//n):
        total=(total+delta)&mask
        e=(total>>2)&3
        z=words[-1]
        for p in range(n):
            y=words[(p+1)%n]
            mx=((((z>>5)^((y<<2)&mask))+((y>>3)^((z<<4)&mask))) ^
                ((total^y)+(k[(p&3)^e]^z)))
            words[p]=(words[p]+mx)&mask
            z=words[p]
    return struct.pack("<%dI"%n,*words)


def flex_fixture(version:int,lock:int=0,flag:bool=False):
    props={
        "tunnelType":"2","proxyPayload":"CONNECT / HTTP/1.1","customSni":"flex.example",
        "sshServer":"srv.example","sshPort":"443","sshUser":"user","sshPass":"pass",
        "sshPortaLocal":"1080","udpResolver":"1.1.1.1","udpForward":"1",
        "file.proteger":"1","file.msg":"source fixture"
    }
    xml='<properties><comment>Test comment</comment>'+''.join(
        f'<entry key="{k}">{v.replace("&","&amp;").replace("<","&lt;")}</entry>'
        for k,v in props.items())+'</properties>'
    clear=zlib.compress(xml.encode("utf-8"))
    iv=bytes(range(12))
    mat=flex.flex_get_material(version,lock)
    password=mat.decode("latin-1").encode("utf-8")
    iterations=10000
    key=hashlib.pbkdf2_hmac("sha512",password,SALT,iterations,32)
    aad=flex.FLEX_MAGIC+bytes([version])+struct.pack(">I",lock) if version>=3 else None
    payload=gcm(key,clear,iv,aad=aad)
    header=flex.FLEX_MAGIC+bytes([version])
    if version>=3:header+=struct.pack(">I",lock)
    header+=struct.pack(">I",iterations)
    if version==4 and flag:header+=b"\x01\x04key1"
    header+=bytes([len(SALT)])+SALT+bytes([len(iv)])+iv
    header+=struct.pack(">I",len(payload))+payload
    return header


def izph_encrypt256_block(key:bytes,tweak:tuple[int,int],plain:bytes)->bytes:
    """Inverse of the production decryptor: MIX then permute per round."""
    mask=(1<<64)-1
    words=list(struct.unpack("<4Q",plain))
    k=list(struct.unpack("<4Q",key))
    sub=izph.izph_threefish256_subkeys(k,tweak)
    for j in range(4):words[j]=(words[j]+sub[0][j])&mask
    for group in range(18):
        for step in range(4):
            r0,r1=izph.IZPH_THREEFISH256_ROTATIONS[(group*4+step)%8]
            def mix(a,b,r):
                x=(a+b)&mask
                y=(((b<<r)|(b>>(64-r)))&mask)^x
                return x,y
            words[0],words[1]=mix(words[0],words[1],r0)
            words[2],words[3]=mix(words[2],words[3],r1)
            words=[words[i] for i in izph.IZPH_THREEFISH256_PERMUTE]
        for j in range(4):words[j]=(words[j]+sub[group+1][j])&mask
    result=struct.pack("<4Q",*words)
    assert izph.izph_threefish256_decrypt_block(
        list(struct.unpack("<4Q",result)),k,tweak)==list(struct.unpack("<4Q",plain))
    return result


def izph_fixture(kind:int,content=None):
    clear=js(content or TEXT)
    if kind==0:
        shifted=bytes((x+2)&255 for x in clear)
        stage=legacy_encrypt(shifted,izph.IZPH_SHA256_KEY_16)
        return b64(cbc(izph.IZPH_SHA256_KEY_16,izph.IZPH_FIXED_IV,stage))
    if kind==1:
        key16=izph.izph_get_hkdf_key_16()
        key32=izph.izph_get_hkdf_key()
        encrypted=cbc(key16,izph.IZPH_FIXED_IV,clear)
        encrypted+=bytes(-len(encrypted)%32)
        stage=b"".join(
            izph_encrypt256_block(key32,(i//32,(i//32)*64),encrypted[i:i+32])
            for i in range(0,len(encrypted),32))
        return b64(b64(stage))
    if kind==2:
        key=izph.izph_get_pbkdf2_key()
        stage=IV+cbc(key,IV,clear)
        encrypted=legacy_encrypt(stage,key[:16])
        return b64(b64(encrypted))
    if kind==3:
        key=izph.izph_get_hkdf_key()
        return b64(IV+cbc(key,IV,clear))
    raise ValueError(kind)


def n4_encode(value:str,table:str)->str:
    key=hashlib.sha256(n4.n4_hex_upper("modmkk").encode()).digest()
    base=b64(cbc(key,n4.N4_IV,value.encode("utf-8")))
    assert len(table)>=16  # Source TABLE2 intentionally has an unused 17th symbol
    return "".join(table[x>>4]+table[x&15] for x in base)
def n4_fixture():
    doc={"N4User":n4_encode("ssh-user",n4.TABLE2),
         "N4Pass":n4_encode("pass-secret",n4.TABLE2),
         "ServerIP":n4_encode("test.invalid",n4.TABLE3),
         "Payload":n4_encode("GET / HTTP/1.1",n4.TABLE4),
         "ServerPort":"n4vpn n4","isSSL":False,
         "Extra":{"N4Pass":n4_encode("nested-pass",n4.TABLE2)}}
    key=hashlib.sha256(b"jdk").digest()
    return b64(AES.new(key,AES.MODE_ECB).encrypt(pad(js(doc),16)))


def ktr_fixture(long_string=False):
    fieldkey="SERVER_HOST";plain1="test.invalid"
    field2="SERVER_PORT";plain2="443"
    def enc(s):return b64(cbc(ktr.KTR_KEY,ktr.KTR_IV,s.encode())).decode("ascii")
    def token(s):
        raw=s.encode("utf-8")
        return (b"\x7c"+struct.pack(">Q",len(raw)) if long_string
            else b"\x74"+struct.pack(">H",len(raw)))+raw
    return ktr.KTR_JAVA_MAGIC+b"".join(token(s)for s in(
        fieldkey,enc(plain1),field2,enc(plain2),"SSL_ENABLED","yes"))


def dev_fixture():
    key=hashlib.sha256(dev.DEV_AES_KEY.encode("utf-8").hex().upper().encode()).digest()
    doc={"Server":b64(cbc(key,bytes(16),b"dev.example")).decode("ascii"),
         "Port":443,"Enabled":False,
         "Payload":b64(cbc(key,bytes(16),b"CONNECT / HTTP/1.1")).decode("ascii")}
    raw=xxtea_encrypt(js(doc),dev.DEV_SKY_KEY.encode(),0x9a7393b4)
    return b64(raw)

def ltm_fixture():
    xml=b'<properties><comment>fixture</comment><entry key="Server">lt.example</entry><entry key="Port">443</entry><entry key="Empty"></entry></properties>'
    key=PBKDF2(ltm.LTM_PASSWORD,SALT,dkLen=16,count=1000,hmac_hash_module=SHA256)
    return b".".join((b64(SALT),b64(NONCE),b64(gcm(key,xml))))

def vn7_fixture(second=False):
    password=vn7.VN7_KEYS[1 if second else 0]
    key=PBKDF2(password,SALT,dkLen=16,count=1000,hmac_hash_module=SHA256)
    return b".".join((b64(SALT),b64(NONCE),b64(gcm(key,js(TEXT)))))

def fixtures():
    inputs={
        "flex.py":flex_fixture(1),
        "izph.py":izph_fixture(0),
        "n4.py":n4_fixture(),
        "crev.py":b64(xxtea_encrypt(js({"Tweaks":[{"ServerHost":b64(
            xxtea_encrypt(b"crev.example",b"DEV_CREEB",-1703701580)).decode()}],
            "Enabled":False}),b"DEV_CREEB",-1703701580)),
        "ktr.py":ktr_fixture(),
        "zoba.py":b64(xxtea_encrypt(js(TEXT),zoba.KEY,zoba.DELTA)),
        "dev.py":dev_fixture(),
        "ltm.py":ltm_fixture(),
        "vn7.py":vn7_fixture()
    }
    cat=audited_android_catalog()
    rows=sorted((x for x in cat["entries"] if x["migrationPhase"]=="F"),
                key=lambda x:x["suffix"])
    assert len(rows)==13
    vectors=[]
    def add(suffix,moduleName,mode,raw):
        source=SOURCES[moduleName]
        result=source.run(raw)
        if not result:
            raise AssertionError("Python %s .%s (%s) cannot decode source fixture"%(
                moduleName,suffix,mode))
        vectors.append({
            "suffix":suffix,"module":moduleName,"mode":mode,
            "encodedInput":b64(raw).decode("ascii"),"expected":result
        })
    for row in rows:
        name=row["script"].rsplit("/",1)[-1]
        add(row["suffix"],name,"outer",inputs[name])
    for suffix,moduleName,mode,raw in [
        ("flex","flex.py","version2",flex_fixture(2)),
        ("flex","flex.py","version3",flex_fixture(3,30)),
        ("flexnet","flex.py","version4",flex_fixture(4,30)),
        ("flexnet","flex.py","version4_optional_header",flex_fixture(4,30,True)),
        ("izph","izph.py","type1_threefish",izph_fixture(1)),
        ("izph","izph.py","type2_pbkdf2",izph_fixture(2)),
        ("izph","izph.py","type3_hkdf",izph_fixture(3)),
        ("izph","izph.py","type3_nested_base64",izph_fixture(3,{
            "Username":b64(b"GET / HTTP/1.1").decode(),
            "Servers":[{"ServerIPHost":b64(b"CONNECT edge.example").decode(),
                        "Port":443}],
            "Networks":[{"Payload":b64(b"GET / HTTP/1.1").decode(),"Enabled":False}]
        })),
        ("vn7","vn7.py","secondary_key",vn7_fixture(True)),
        ("ktr","ktr.py","long_string",ktr_fixture(True)),
        ("zoba","zoba.py","raw_binary",xxtea_encrypt(js(TEXT),zoba.KEY,zoba.DELTA)),
        ("crev","crev.py","alternative_key",b64(xxtea_encrypt(js(TEXT),b"DEV_CREV",-1703701580)))
    ]:
        add(suffix,moduleName,mode,raw)
    return {"schemaVersion":1,"suffixCount":13,"moduleCount":9,
            "caseCount":len(vectors),"modules":sorted(SOURCES),"vectors":vectors}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--fixtures",required=True,type=Path)
    args=parser.parse_args()
    doc=fixtures()
    args.fixtures.parent.mkdir(parents=True,exist_ok=True)
    args.fixtures.write_text(json.dumps(doc,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("[F] %s source-verified native reference cases for 13 suffixes" %doc["caseCount"])

if __name__=="__main__":main()
