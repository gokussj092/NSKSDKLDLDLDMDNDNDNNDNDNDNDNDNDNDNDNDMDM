#!/usr/bin/env python3
"""Offline DTunnel Mod 4.2.5 catalog and vpn:// decoder.

Protocol compatibility from supplied dtunnelmod.py. This module never downloads
remote data and never fabricates the required dtunnel-token identifier.
"""
from __future__ import annotations
import base64
import binascii
import hashlib
import json
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

SEED=b"DTunnelModSecret-API-9c69a0b72b442ccac3e6aaaa7630d12f2b351fe395e9fe667efa0907cde90da5"
KEY=hashlib.sha256(SEED).digest()
MAX_BYTES=8*1024*1024

def b64(text):
    if not isinstance(text,str):
        raise ValueError("INVALID_INPUT")
    text=re.sub(r"[ \t\r\n]","",text)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}",text) or len(text)%4==1:
        raise ValueError("INVALID_BASE64")
    try:
        return base64.b64decode(text+"="*(-len(text)%4),validate=True)
    except (ValueError,binascii.Error) as error:
        raise ValueError("INVALID_BASE64") from error

def loads(text):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:
                raise ValueError("DUPLICATE_KEY")
            result[key]=value
        return result
    return json.loads(text,object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("INVALID_NUMBER")))

def decode(data):
    if not isinstance(data,bytes) or not 0<len(data)<=MAX_BYTES:
        raise ValueError("INVALID_INPUT")
    value=data.decode("utf-8-sig").strip()
    if value.startswith("vpn://"):
        result=loads(b64(value[6:]).decode("utf-8"))
        if not isinstance(result,dict):
            raise ValueError("WRONG_DOCUMENT")
        return result
    encrypted=b64(value)
    if not encrypted or len(encrypted)%16:
        raise ValueError("INVALID_ENVELOPE")
    clear=unpad(AES.new(KEY,AES.MODE_CBC,iv=bytes(16)).decrypt(encrypted),16)
    result=loads(clear.decode("utf-8"))
    if not isinstance(result,list):
        raise ValueError("WRONG_DOCUMENT")
    items=[loads(x) if isinstance(x,str) else x for x in result]
    if any(not isinstance(item,dict) for item in items):
        raise ValueError("WRONG_DOCUMENT")
    return items

def run(data):
    try:
        return json.dumps(decode(data),ensure_ascii=False,indent=2,allow_nan=False)+"\n"
    except (ValueError,UnicodeError,RecursionError,TypeError):
        return None
