#!/usr/bin/env python3
"""Offline KSH VPN 1.3.2 catalog adapter. No network or endpoint in the worker.

Matches the owner's ksh_vpn.py contract: strict AES-256-GCM, JSON 'enc' or
raw Base64, preserved entire servers list; rejects unauthenticated data.
"""
from __future__ import annotations

import base64
import binascii
import json
import re

from Crypto.Cipher import AES

KEY = base64.b64decode("zh+01419+zsCmfiYy1L2hbdMLBoA/2mWeYHuq212xSk=")
MAX_BYTES = 8 * 1024 * 1024

def decode(data: bytes):
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_BYTES:
        raise ValueError("INVALID_INPUT")
    text = data.decode("utf-8-sig").strip()
    if text.startswith("{"):
        envelope = json.loads(text)
        if not isinstance(envelope, dict):
            raise ValueError("INVALID_ENVELOPE")
        text = envelope.get("enc")
    if not isinstance(text, str):
        raise ValueError("INVALID_ENVELOPE")
    text = re.sub(r"[ \t\r\n]", "", text)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text):
        raise ValueError("INVALID_BASE64")
    try:
        binary = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("INVALID_BASE64") from error
    if len(binary) < 29:
        raise ValueError("INVALID_ENVELOPE")
    plaintext = AES.new(KEY, AES.MODE_GCM, nonce=binary[:12], mac_len=16).decrypt_and_verify(binary[12:-16], binary[-16:])
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("DUPLICATE_KEY")
            value[key] = item
        return value
    def no_constant(_):
        raise ValueError("NONFINITE_NUMBER")
    value = json.loads(plaintext.decode("utf-8"), object_pairs_hook=unique, parse_constant=no_constant)
    if not isinstance(value, dict) or not isinstance(value.get("servers"), list) or any(
        not isinstance(item, dict) for item in value["servers"]
    ):
        raise ValueError("WRONG_DOCUMENT")
    return value

def run(data):
    try:
        return json.dumps(decode(data), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except (ValueError, UnicodeError, RecursionError, TypeError):
        return None
