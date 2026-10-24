#!/usr/bin/env python3
"""Synthetic NPVS v5 password fixtures and v5/v6 recipient-only framing.

No real export/password or device private key is used. Recipient fixtures test
recognition/diagnostics only; v6 document decryption is intentionally unverified.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import struct
from Crypto.Cipher import ChaCha20_Poly1305, AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


def url(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def canonical(obj):
    s=json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(",",":"))
    for a,b in (("<","\\u003c"),(">","\\u003e"),("&","\\u0026"),("\u2028","\\u2028"),("\u2029","\\u2029")):
        s=s.replace(a,b)
    return s.encode()


def seal(key,nonce,plain,aad):
    c=ChaCha20_Poly1305.new(key=key,nonce=nonce);c.update(aad)
    ciphertext,tag=c.encrypt_and_digest(plain)
    return ciphertext+tag


def make(*,password="synthetic-password",version=5,recipient=False):
    creator=ECC.construct(curve="P-256",d=0x123456789abcdef)
    pub=creator.public_key().export_key(format="SEC1",compress=True)
    cid,salt,nonce=bytes(range(16)),bytes(range(16,32)),bytes(range(32,44))
    dek=bytes(range(32));wrapped_nonce=bytes(range(48,60))
    policy={"onlyMobileNetwork":False,"attestationLevel":"","expiresAt":None,
            "displayMessage":"Sintético <>& 日本語", "customServerMessage":"", "configVersion":2}
    metadata={"issuedAt":"2026-10-22","policy":policy}
    public_key=None
    if recipient:
        key=ECC.construct(curve="P-256",d=0x987654321abcdef)
        public=key.public_key().export_key(format="SEC1",compress=True);public_key=url(public)
        fp=hashlib.sha256(public).digest();ephemeral=ECC.construct(curve="P-256",d=0x123abc)
        shared=int((key.pointQ*ephemeral.d).x).to_bytes(32,"big")
        wrapping=HKDF(shared,32,cid,SHA256,context=b"NPVS-v1-wrap"+fp)
        aes=AES.new(wrapping,AES.MODE_GCM,nonce=wrapped_nonce);aes.update(cid)
        cipher,tag=aes.encrypt_and_digest(dek)
        record=fp+ephemeral.public_key().export_key(format="SEC1",compress=True)+wrapped_nonce+cipher+tag
        prefix=b"\x01"+cid+pub+b"\x00\x00\x01"+record+(salt if version==6 else b"")
    else:
        key=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,600000,32)
        wrapped=wrapped_nonce+seal(key,wrapped_nonce,dek,salt)
        prefix=b"\x01"+cid+pub+b"\x01\x00\x00"+struct.pack(">I",600000)+salt+wrapped
    mkey=HKDF(dek,32,nonce,SHA256,context=b"NPVS-v5/metadata")
    mc=seal(mkey,nonce,canonical(metadata),prefix);header=prefix+struct.pack(">I",len(mc))+mc
    source={"v":5,"configId":url(cid),"issuedAt":metadata["issuedAt"],
            "creator":{"fp":url(hashlib.sha256(pub).digest()),"pk":url(pub)},"policy":policy,"recipients":None}
    context=hashlib.sha256(b"NPVS-v5/source-fields-v1/"+canonical(source)+nonce).digest()
    document={"configs":[{"name":"Sintético 😀", "sshConfig":{"host":"example.invalid",
        "port":443,"username":"npvs1:"+url("usuario 日本語".encode()),"password":"opaque-secret",
        "enabled":True,"extra":None,"empty":"","payload":"GET / HTTP/1.1\r\n\r\n"}}]}
    records={}
    def flatten(obj):
        if isinstance(obj,dict):return {k:flatten(v) for k,v in obj.items()}
        if isinstance(obj,list):return [flatten(v) for v in obj]
        i=len(records)+1;records[i]=obj;return i
    layout=flatten(document);records[65535]=layout
    body=b"NPF\x01"+context+struct.pack(">H",len(records))
    for i,value in records.items():
        raw=canonical(value);field_key=HKDF(dek,32,context,SHA256,context=b"NPV-fields-v1/field/"+struct.pack(">H",i))
        aad=b"NPV-fields-v1/record/"+context+struct.pack(">HI",i,len(raw))
        ciphertext=seal(field_key,bytes(12),raw,aad);body+=struct.pack(">HI",i,len(ciphertext))+ciphertext
    ikey=HKDF(dek,32,context,SHA256,context=b"NPV-fields-v1/inventory/\0\0")
    body+=hmac.digest(ikey,body,"sha256")
    unsigned=b"NPVS"+bytes([version])+struct.pack(">I",len(header))+header+nonce+struct.pack(">I",len(body))+body
    data=unsigned+DSS.new(creator,"deterministic-rfc6979",encoding="binary").sign(SHA256.new(unsigned))
    expected={"metadata":metadata,"document":document}
    return {"data":data,"expectedRaw":expected,"creator":creator,"publicKey":public_key,
            "password":password,"dek":dek}


if __name__=="__main__":
    # Output contains only explicitly synthetic, reproducible fixtures.
    out=[]
    for args in ({},{"password":"contraseña-日本語-😀"},{"recipient":True},{"recipient":True,"version":6}):
        v=make(**args);out.append({"dataBase64":base64.b64encode(v["data"]).decode(),
            "expectedRaw":v["expectedRaw"],"password":v["password"] if not args.get("recipient") else None,
            "publicKey":v["publicKey"]})
    print(json.dumps(out,ensure_ascii=False,indent=2))
