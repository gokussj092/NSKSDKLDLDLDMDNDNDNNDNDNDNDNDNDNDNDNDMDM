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

def make_v1(*,passphrase=False,recipients=False,embedded=False):
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
    if embedded:
        # Non-secret synthetic values imitate the real NPVS v1 prefixed
        # fields. Exact prefixed Base64 is deliberately not coerced to
        # integer/bool: the surrounding JSON schema remains authoritative.
        b64=lambda value: "npvs1:"+_b64(value.encode("utf-8"))
        plain["configs"][0].update({
            "name":"synthetic",
            "remarks":b64("Rjo"),
            "server":b64("example.invalid"),
            "serverPort":b64("8081"),
            "password":b64("synthetic-only-not-a-real-credential"),
            "method":b64("none"),
            "network":b64("xhttp"),
            "headerType":b64("none"),
            "mode":b64("gun"),
            "xhttpMode":b64("auto"),
            "nested":{
                "items":[b64("日本語"),b64('{"host":"example.invalid","ports":[443,8443]}')],
                "double":b64(b64("twice")),
                "flag":False,
                "number":8443,
                "nullable":None,
                "untaggedBase64":"dGVzdA==",
            },
        })
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

    def test_v1_authenticated_embedded_fields_are_fully_decoded(self):
        raw,_,original=make_v1(embedded=True)
        # The unprocessed cryptographic result is deliberately unchanged.
        self.assertEqual(npvs_v1.decode_npvs_v1(raw),original)
        output=decode_file("npvs",raw)
        got=output["structuredJson"]
        self.assertEqual(json.loads(output["rawText"]),got)
        self.assertFalse(output["isPartial"])
        profile=got["configs"][0]
        for name,value in (
            ("remarks","Rjo"),("server","example.invalid"),
            ("serverPort","8081"),("password","synthetic-only-not-a-real-credential"),
            ("method","none"),("network","xhttp"),("headerType","none"),
            ("mode","gun"),("xhttpMode","auto"),
        ):
            self.assertEqual(profile[name],value)
            self.assertFalse(profile[name].startswith("npvs1:"))
        self.assertEqual(profile["nested"]["items"],[
            "日本語",{"host":"example.invalid","ports":[443,8443]}])
        self.assertEqual(profile["nested"]["double"],"twice")
        self.assertEqual(profile["nested"]["number"],8443)
        self.assertIs(profile["nested"]["flag"],False)
        self.assertIsNone(profile["nested"]["nullable"])
        self.assertEqual(profile["nested"]["untaggedBase64"],"dGVzdA==")
        self.assertEqual(profile["enabled"],True)
        self.assertEqual(profile["port"],443)

    def test_v1_password_embedded_values_after_authentication(self):
        raw,credential,_=make_v1(passphrase=True,embedded=True)
        with self.assertRaises(DecodeFailure) as err:
            decode_file("npvs",raw,credentials={"password":"wrong"})
        self.assertEqual(err.exception.code,"AUTH_FAILED")
        output=decode_file("npvs",raw,credentials=credential)
        self.assertEqual(output["structuredJson"]["configs"][0]["remarks"],"Rjo")

    def test_v1_malformed_embedded_data_rejects_without_partial_result(self):
        from decoders.Python.npvs import _decode_embedded_npvs1, DecodeError as FieldError
        for bad in ("npvs1:!!!!","npvs1:","npvs1:////"):
            with self.assertRaises(FieldError):
                _decode_embedded_npvs1({"configs":[{"host":bad}]})

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
        self.assertEqual(ctx.exception.code,"UNSUPPORTED_VERSION")

if __name__=="__main__": unittest.main()
