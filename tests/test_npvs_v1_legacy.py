"""Isolated signed NPVS v1 route and historical credential behavior.

All fixtures generated in memory. No real user export, key, decoded JSON, or
Telegram bot token may be checked in. v5 and v6 retain their own source codec.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import unittest
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from decoders.Python import npvs_v1

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"cloud/workers/python"))
from engine import decode_file, DecodeFailure

def _b64(value:bytes)->str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

def _seal(key,nonce,data,aad):
    c=ChaCha20_Poly1305.new(key=key,nonce=nonce)
    c.update(aad)
    ct,tag=c.encrypt_and_digest(data)
    return ct+tag

def make_v1(*,passphrase=False,recipients=False):
    signer=ECC.construct(curve="P-256",d=0x123456789abcedf)
    pub=signer.public_key().export_key(format="SEC1",compress=True)
    salt=bytes(range(16))
    dek=bytes(range(17,49))
    wrap_nonce=bytes(range(49,61))
    header={"v":1,"creator":{"pk":_b64(pub),"fp":_b64(hashlib.sha256(pub).digest())},
            "configId":_b64(bytes(range(1,17))),"recipients":[],
            "policy":{"configVersion":1}}
    if recipients:
        header["recipients"]=[{"fp":_b64(hashlib.sha256(pub).digest())}]
        credential=None
    elif passphrase:
        password="fixture-only-password"
        kdk=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,600000,32)
        header["passphrase"]={"kdf":"pbkdf2-hmac-sha256","iters":600000,
                "salt":_b64(salt),"wrap":_b64(wrap_nonce+_seal(kdk,wrap_nonce,dek,salt))}
        credential={"password":password}
    else:
        kdk=npvs_v1._npvs_custodian_kdks(salt)[0]
        header["appKey"]={"kdf":"wbaes-ctr-sha256","keyId":1,
                "salt":_b64(salt),"wrap":_b64(wrap_nonce+_seal(kdk,wrap_nonce,dek,salt))}
        credential=None
    h=json.dumps(header,separators=(",",":"),ensure_ascii=False).encode()
    plain={"configs":[{"name":"synthetic","host":"example.invalid",
                       "port":443,"enabled":True,"optional":None}],
           "metadata":{"complete":True}}
    nonce=bytes(range(60,72))
    body=_seal(dek,nonce,json.dumps(plain).encode(),h)
    unsigned=b"NPVS"+b"\x01"+struct.pack(">I",len(h))+h+nonce+struct.pack(">I",len(body))+body
    signed=unsigned+DSS.new(signer,"deterministic-rfc6979",encoding="binary").sign(SHA256.new(unsigned))
    return signed,credential,plain

class NpvsV1Tests(unittest.TestCase):
    def test_signed_v1_appkey_complete_json_without_password(self):
        raw,_,expected=make_v1()
        self.assertEqual(npvs_v1.decode_npvs_v1(raw),expected)
        out=decode_file("npvs",raw)
        self.assertEqual(out["structuredJson"],expected)
        self.assertFalse(out["isPartial"])
        self.assertEqual(json.loads(out["rawText"]),expected)

    def test_v1_password_contract_and_wrong_password(self):
        raw,credential,expected=make_v1(passphrase=True)
        for options,code in ((None,"PASSWORD_REQUIRED"),({"password":"wrong"},"AUTH_FAILED")):
            with self.assertRaises(DecodeFailure) as ctx:
                decode_file("npvs",raw,credentials=options)
            self.assertEqual(ctx.exception.code,code)
        result=decode_file("npvs",raw,credentials=credential)
        self.assertEqual(result["structuredJson"],expected)

    def test_v1_signed_recipient_never_requests_password(self):
        raw,_,_=make_v1(recipients=True)
        with self.assertRaises(DecodeFailure) as ctx: decode_file("npvs",raw)
        self.assertEqual(ctx.exception.code,"PRIVATE_KEY_REQUIRED")

    def test_v1_tampering_does_not_fallback_or_succeed(self):
        raw,_,_=make_v1()
        for position in (0,4,9,88,-1):
            changed=bytearray(raw)
            changed[position]^=1
            with self.assertRaises(DecodeFailure):decode_file("npvs",bytes(changed))
        with self.assertRaises(DecodeFailure):decode_file("npvs",raw[:-1])
        with self.assertRaises(DecodeFailure):decode_file("npvs",raw+b"x")
        with self.assertRaises(DecodeFailure) as ctx:
            decode_file("npvs",raw,credentials={"password":"wrong"})
        self.assertEqual(ctx.exception.code,"INVALID_CREDENTIALS")

    def test_unknown_version_fails_explicitly_without_v5_fallback(self):
        raw,_,_=make_v1()
        unknown=raw[:4]+b"\x03"+raw[5:]
        with self.assertRaises(DecodeFailure) as ctx:decode_file("npvs",unknown)
        self.assertEqual(ctx.exception.code,"NPVS_PROTECTION_UNSUPPORTED")

if __name__=="__main__": unittest.main()
