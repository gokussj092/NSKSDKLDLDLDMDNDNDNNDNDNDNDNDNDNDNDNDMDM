#!/usr/bin/env python3
"""Siam VPN 4.9 (siam.pro.net): catalog decoder, live download or saved blob.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
For profile.json files use Siam_VPN_archivos.py. See README.md here.

Method (verified against this APK, versionCode 49, versionName 4.9, and
against a live download on 2026-11-13):
  GET http://unifi.thai-vpn.com/app-patch/patch-siam-3   (plain GET, no
  custom headers, no auth; the app reads the URL from the "key_url"
  preference whose default is this endpoint; the server answers HTTP
  200 with one Base64 line, ~143576 chars)
  -> Base64 decode -> streaming AEAD decrypt (the app's vendored,
     slightly modified Google Tink AesGcmHkdfStreaming):
       IKM = PBKDF2-HmacSHA256(password = prefs["key_secured"],
             salt = b"MY_APP_FIXED_SALT_V1", 100000 iterations, 32 bytes)
       header = 40 bytes: [0x28][salt: 32 bytes][nonce prefix: 7 bytes]
       key = HKDF-SHA256(IKM, salt = header salt,
             info = b"MY_SECURE_JSON_STREAM_V1", 32 bytes)
       the blob is a sequence of 4096-byte blocks counted from the
       start of the file: block 0 holds the 40-byte header plus the
       first segment (4056 bytes = 4040 plaintext + 16 tag); every
       following block is one segment (4096 bytes = 4080 + 16 tag),
       the last block is the final segment (shorter).  Segment number
       is the block index (0, 1, 2, ...); the last segment carries the
       last-segment flag.  Each segment is AES-256-GCM, nonce =
       nonce_prefix (7) + segment number (4 bytes, big endian) +
       last flag (1 byte), no additional authenticated data.
  -> JSON with Version, Message, Servers, Networks and setOpenVPN.
  -> every field that carries an "ED:" value is Base32 (Lo41.a):
     "ED:" + Base32(UTF-8 plaintext).  Fields that are not "ED:" are
     left as-is; the app's Lo41.a also accepts a plain Base64 value
     there, and decode_ed() reproduces that fallback.
Live test (2026-11-13, --url): Version 8.70, Message "update",
26 servers (all flag "th"; 6 Direct Connection OpenVPN, 1 UDP, 19
Default), 23 networks/payloads (10 item-gated, PayloadFlag "true";
13 carrier: AIS 7, DTAC 5, MY 1).  The catalog has no explicit
free/premium marker on servers; the 10 item-gated payloads say so in
their PayloadInfo ("ต้องมีไอเท็ม ...").  Full decryption takes ~5 s
in pure Python (AES-GCM over ~107 KB of plaintext).
Secondary endpoint (ping/latency list, not the catalog):
  GET https://www.thai-vpn.com/ayothaya/ping.json -> plain JSON with
  58 entries (8 Thai ISP hosts + TH-01..TH-50, port 82).  Use --ping
  to fetch it.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from http.client import HTTPException
import hashlib
import hmac
import json
import math
from pathlib import Path
import re
import struct
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
MASK = 0xFFFFFFFF
CATALOG_URL = "http://unifi.thai-vpn.com/app-patch/patch-siam-3"
PING_URL = "https://www.thai-vpn.com/ayothaya/ping.json"
# PBKDF2 password: the default of the "key_secured" preference, written
# by the app itself on every start (Lmx2).  A format constant, not a
# user password.
KEY_SECURED = "f_40#LKAZeK64iTeS7*$It1Ip0uWUk&Sus?eY-27M!5WIgUjitIWit7l!RLcivu0"
PBKDF2_SALT = b"MY_APP_FIXED_SALT_V1"
PBKDF2_ITERATIONS = 100000
STREAM_AD = b"MY_SECURE_JSON_STREAM_V1"
HEADER_LEN = 40
SEGMENT_LEN = 4096
# Fields whose values the app passes through Lo41.a ("ED:" Base32, or a
# plain Base64 value as a fallback) before using them.
ED_FIELDS_SERVERS = (
    "ServerIP", "Username", "Password", "setOpenVPN", "V2Ray",
    "UDPConfig", "Cloudfront", "NameServer", "PublicKey", "ServerDNS",
)
ED_FIELDS_NETWORKS = ("Payload", "SquidProxy", "ServerDNS", "Sni")


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- AES (pure python, stdlib only)

_SBOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
)
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)


def _xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff


def _mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _key_expansion(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = [_SBOX[t[1]] ^ _RCON[i // nk - 1], _SBOX[t[2]],
                 _SBOX[t[3]], _SBOX[t[0]]]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w, nr


def _add_rk(s, w, rnd):
    for c in range(4):
        for r in range(4):
            s[4 * c + r] ^= w[4 * rnd + c][r]


def _sub(s):
    for i in range(16):
        s[i] = _SBOX[s[i]]


def _shift(s):
    for r in range(1, 4):
        row = [s[4 * c + r] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            s[4 * c + r] = row[c]


def _mix(s):
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        s[4 * c + 0] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
        s[4 * c + 1] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
        s[4 * c + 2] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
        s[4 * c + 3] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)


def _aes_encrypt_block(key, block):
    w, nr = _key_expansion(key)
    s = list(block)
    _add_rk(s, w, 0)
    for rnd in range(1, nr):
        _sub(s)
        _shift(s)
        _mix(s)
        _add_rk(s, w, rnd)
    _sub(s)
    _shift(s)
    _add_rk(s, w, nr)
    return bytes(s)


# ---------------------------------------------------------------- AES-GCM (pure python)

_GF_POLY = 0xE1000000000000000000000000000000


def _gf_mul(x, y):
    r = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            r ^= v
        if v & 1:
            v = (v >> 1) ^ _GF_POLY
        else:
            v >>= 1
    return r


def _ghash(h, aad, ct):
    def _pad(b):
        return b + bytes((-len(b)) % 16)
    data = (_pad(aad) + _pad(ct)
            + (len(aad) * 8).to_bytes(8, "big")
            + (len(ct) * 8).to_bytes(8, "big"))
    hb = int.from_bytes(h, "big")
    y = 0
    for i in range(0, len(data), 16):
        y = _gf_mul(y ^ int.from_bytes(data[i:i + 16], "big"), hb)
    return y.to_bytes(16, "big")


def _gcm_crypt(key, nonce12, data, aad=b"", encrypt=True):
    """AES-GCM with a 12-byte nonce; for decrypt, data ends with the tag."""
    h = _aes_encrypt_block(key, bytes(16))
    j0 = nonce12 + b"\x00\x00\x00\x01"
    if encrypt:
        ct, tag_data = data, None
    else:
        if len(data) < 16:
            raise DecodeError("GCM_TAG", "El segmento GCM es demasiado corto.")
        ct, tag_data = data[:-16], data[-16:]
    out = bytearray()
    # GCM counter: J0+1, low 32 bits increment (incr32).
    ctr = int.from_bytes(j0, "big") + 1
    for i in range(0, len(ct), 16):
        blk = ct[i:i + 16]
        ks = _aes_encrypt_block(key, ctr.to_bytes(16, "big"))
        out += bytes(a ^ b for a, b in zip(blk, ks[:len(blk)]))
        ctr = (ctr & ~0xFFFFFFFF) | ((ctr + 1) & 0xFFFFFFFF)
    if encrypt:
        tag = bytes(a ^ b for a, b in zip(
            _ghash(h, aad, bytes(out)),
            _aes_encrypt_block(key, j0)))
        return bytes(out) + tag
    tag = bytes(a ^ b for a, b in zip(
        _ghash(h, aad, ct), _aes_encrypt_block(key, j0)))
    if tag != tag_data:
        raise DecodeError("GCM_TAG", "La etiqueta GCM del segmento no coincide.")
    return bytes(out)


def _hkdf(ikm, salt, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def _derive_key(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt,
        PBKDF2_ITERATIONS, 32)


# ---------------------------------------------------------------- streaming AEAD (Tink-like)

def stream_decrypt(blob, password=KEY_SECURED):
    """Decrypt a Siam update blob (Base64-decoded bytes) -> plaintext JSON bytes."""
    if len(blob) < HEADER_LEN:
        raise DecodeError("TOO_SHORT", "El blob es más corto que la cabecera de 40 bytes.")
    if blob[0] != HEADER_LEN:
        raise DecodeError("BAD_HEADER", "El primer byte del blob no es 40 (longitud de cabecera).")
    salt = blob[1:33]
    nonce_prefix = blob[33:40]
    ikm = _derive_key(password, PBKDF2_SALT)
    key = _hkdf(ikm, salt, STREAM_AD, 32)
    body = blob[HEADER_LEN:]
    if not body:
        raise DecodeError("EMPTY", "El blob no tiene segmentos después de la cabecera.")
    # Block 0 holds the header + the first segment; the first segment is
    # therefore 4096 - 40 = 4056 bytes.  Later segments are 4096 bytes.
    segments = [body[:SEGMENT_LEN - HEADER_LEN]]
    off = SEGMENT_LEN - HEADER_LEN
    while off < len(body):
        segments.append(body[off:off + SEGMENT_LEN])
        off += SEGMENT_LEN
    out = bytearray()
    for nr, seg in enumerate(segments):
        last = 1 if nr == len(segments) - 1 else 0
        nonce = nonce_prefix + nr.to_bytes(4, "big") + bytes([last])
        try:
            out += _gcm_crypt(key, nonce, seg, b"", encrypt=False)
        except DecodeError as exc:
            raise DecodeError("GCM_TAG",
                              "La etiqueta GCM del segmento %d no coincide." % nr) from exc
    return bytes(out)


def stream_encrypt(plaintext, password=KEY_SECURED, salt=None, nonce_prefix=None):
    """Encrypt plaintext JSON bytes into a Siam update blob (self-test)."""
    import os
    salt = salt if salt is not None else os.urandom(32)
    nonce_prefix = nonce_prefix if nonce_prefix is not None else os.urandom(7)
    ikm = _derive_key(password, PBKDF2_SALT)
    key = _hkdf(ikm, salt, STREAM_AD, 32)
    header = bytes([HEADER_LEN]) + salt + nonce_prefix
    # First segment carries 4040 plaintext bytes (4056 - 16 tag), the
    # rest 4080 bytes each, mirroring the 4096-byte block layout.
    chunks = [plaintext[:4040]]
    rest = plaintext[4040:]
    while rest:
        chunks.append(rest[:4080])
        rest = rest[4080:]
    blob = bytearray(header)
    for nr, chunk in enumerate(chunks):
        last = 1 if nr == len(chunks) - 1 else 0
        nonce = nonce_prefix + nr.to_bytes(4, "big") + bytes([last])
        blob += _gcm_crypt(key, nonce, chunk, b"", encrypt=True)
    return bytes(blob)


# ---------------------------------------------------------------- "ED:" fields (Lo41.a)

def _b32decode_padded(text):
    return base64.b32decode(text + "=" * (-len(text) % 8))


def decode_ed(value):
    """Decode one field value the way the app's Lo41.a does.

    "ED:" + Base32(UTF-8) -> plaintext; otherwise a plain Base64 value
    is decoded as a fallback; anything else is returned unchanged.
    """
    if not isinstance(value, str) or not value:
        return value
    if value.startswith("ED:"):
        try:
            return _b32decode_padded(value[3:]).decode("utf-8")
        except (ValueError, binascii.Error, UnicodeError):
            return value
    compact = re.sub(r"\s", "", value)
    if (len(compact) >= 8 and len(compact) % 4 == 0
            and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact)):
        try:
            raw = base64.b64decode(compact, validate=True)
            text = raw.decode("utf-8")
            if text and text.isprintable():
                return text
        except (ValueError, binascii.Error, UnicodeError):
            pass
    return value


def encode_ed(value):
    """Encode one field value the way the app's Lo41.b does."""
    if not isinstance(value, str) or not value:
        return value
    return "ED:" + base64.b32encode(value.encode("utf-8")).decode("ascii")


def _decode_ed_fields(doc, keep_ed=False):
    if keep_ed or not isinstance(doc, dict):
        return doc
    for server in doc.get("Servers", []) or []:
        if isinstance(server, dict):
            for field in ED_FIELDS_SERVERS:
                if field in server:
                    server[field] = decode_ed(server[field])
    for network in doc.get("Networks", []) or []:
        if isinstance(network, dict):
            for field in ED_FIELDS_NETWORKS:
                if field in network:
                    network[field] = decode_ed(network[field])
    return doc


# ---------------------------------------------------------------- helpers

def _text(data):
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "Se esperaba texto o bytes UTF-8.")
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    try:
        value = data.decode("utf-8-sig") if isinstance(data, bytes) else data.removeprefix("\ufeff")
        if len(value.encode("utf-8")) > MAX_BYTES:
            raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    except UnicodeError as exc:
        raise DecodeError("FORMAT_ERROR", "La entrada no es UTF-8 válido.") from exc
    return value.strip()


def _base64_blob(text):
    compact = re.sub(r"\s", "", text)
    if not compact or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        raise DecodeError("FORMAT_ERROR", "Se esperaba una línea Base64.")
    try:
        return base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR", "Base64 inválido.") from exc


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _nonfinite(_value):
    raise ValueError("nonfinite number")


def _validate(doc):
    pending, count = [(doc, 0)], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            raise DecodeError("SIZE_LIMIT", "El JSON supera el límite de complejidad.")
        if isinstance(value, dict):
            pending.extend((v, depth + 1) for v in value.values())
            pending.extend((k, depth + 1) for k in value)
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise DecodeError("INVALID_JSON", "Número JSON no finito.")
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError as exc:
                raise DecodeError("INVALID_JSON", "Unicode JSON inválido.") from exc
    return doc


def _json(data):
    try:
        doc = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON", "JSON inválido o con claves duplicadas.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El documento debe contener un objeto JSON.")
    return _validate(doc)


def decode(data, keep_ed=False):
    """Decode a Siam update blob: Base64 text or raw bytes -> catalog dict.

    Accepts the response body of the update URL (one Base64 line), the
    Base64-decoded blob bytes, or a file path's contents read by run().
    """
    if isinstance(data, (bytes, str)):
        raw = data
    else:
        raise DecodeError("FORMAT_ERROR", "Se esperaban bytes o texto.")
    if isinstance(raw, str):
        blob = _base64_blob(raw)
    else:
        blob = raw if raw[:1] == b"\x28" else _base64_blob(_text(raw))
    plain = stream_decrypt(blob)
    doc = _json(plain)
    return _decode_ed_fields(doc, keep_ed=keep_ed)


def fetch_bytes(url, timeout=60):
    req = Request(url, method="GET")
    opener = build_opener()
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read()
    except HTTPError as exc:
        raise DecodeError("HTTP_%d" % exc.code, "HTTP %d al descargar %s." % (exc.code, url)) from exc
    except (URLError, HTTPException, TimeoutError, OSError) as exc:
        raise DecodeError("NETWORK", "No se pudo descargar %s: %s" % (url, exc)) from exc
    if len(body) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La descarga supera el límite de tamaño.")
    return body


def fetch_catalog(url=CATALOG_URL, keep_ed=False):
    return decode(fetch_bytes(url), keep_ed=keep_ed)


def fetch_ping(url=PING_URL):
    body = fetch_bytes(url)
    try:
        doc = json.loads(body, object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON", "JSON inválido o con claves duplicadas.") from exc
    if not isinstance(doc, list):
        raise DecodeError("WRONG_DOCUMENT", "La lista de ping debe ser un arreglo JSON.")
    return _validate(doc)


def _summary(doc):
    servers = doc.get("Servers", []) or []
    networks = doc.get("Networks", []) or []
    gated = sum(1 for n in networks
                if isinstance(n, dict) and n.get("PayloadFlag") == "true")
    return {
        "Version": doc.get("Version"),
        "Message": doc.get("Message"),
        "servers": len(servers),
        "networks": len(networks),
        "item_gated_networks": gated,
    }


# ---------------------------------------------------------------- self-test

def _self_test():
    checks = []

    def check(name, ok):
        checks.append((name, bool(ok)))
        return ok

    # AES-128 FIPS-197 vector.
    check("aes-128", _aes_encrypt_block(
        bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        bytes.fromhex("00112233445566778899aabbccddeeff")
    ).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a")
    # AES-256-GCM round-trip (tag verified on decrypt).
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308"
                        "feffe9928665731c6d6a8f9467308308")
    nonce = bytes.fromhex("cafebabefacedbaddecaf888")
    pt = b"hello world, gcm test 1234567890"
    ct = _gcm_crypt(key, nonce, pt, b"", encrypt=True)
    check("gcm-roundtrip", _gcm_crypt(key, nonce, ct, b"", encrypt=False) == pt)
    # Streaming AEAD round-trip with the real keys (multi-segment).
    doc = {
        "Version": "9.99", "Message": "update", "setOpenVPN": "",
        "Servers": [{
            "ServerName": "Test 1", "ServerFlag": "th",
            "ServerIP": encode_ed("test.example.com"),
            "Username": encode_ed("Openvpn-User"),
            "Password": encode_ed("s3cret"),
            "SelectType": "OpenVPN",
        }],
        "Networks": [{
            "PayloadName": "Test payload", "PayloadFlag": "ais",
            "Payload": encode_ed("GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]"),
            "SelectedProtocal": "HTTP Proxy", "Protocal": "OVPN",
        }],
    }
    plain = json.dumps(doc, ensure_ascii=False).encode("utf-8")
    # Pad past one segment so the multi-segment path is exercised.
    plain = plain + b" " * (5000 - len(plain) if len(plain) < 5000 else 0)
    blob = stream_encrypt(plain)
    out = decode(base64.b64encode(blob).decode("ascii"))
    check("stream-roundtrip",
          out.get("Version") == "9.99"
          and out["Servers"][0]["ServerIP"] == "test.example.com"
          and out["Servers"][0]["Password"] == "s3cret"
          and out["Networks"][0]["Payload"].startswith("GET / HTTP/1.1"))
    # "ED:" helpers.
    check("ed-roundtrip", decode_ed(encode_ed("readyidc-o-1.opensignal.uk"))
          == "readyidc-o-1.opensignal.uk")
    check("ed-plain", decode_ed("plain.example.com") == "plain.example.com")
    check("ed-empty", decode_ed("") == "")
    # Wrong key must fail the GCM tag, never silently return garbage.
    try:
        stream_decrypt(blob, password="wrong-password")
        check("wrong-key-fails", False)
    except DecodeError as exc:
        check("wrong-key-fails", exc.code in ("GCM_TAG", "BAD_HEADER"))
    return checks


# ---------------------------------------------------------------- CLI

def run(argv=None):
    parser = argparse.ArgumentParser(
        description="Decodificador del catálogo de Siam VPN (siam.pro.net).")
    parser.add_argument("--url", nargs="?", const=CATALOG_URL, default=None,
                        help="Descargar el catálogo de URL (por defecto, la del "
                             "servidor de Siam VPN).")
    parser.add_argument("--file", dest="path", default=None,
                        help="Leer el blob guardado (texto Base64 o bytes).")
    parser.add_argument("--ping", action="store_true",
                        help="Descargar la lista de ping (ayothaya/ping.json).")
    parser.add_argument("--keep-ed", action="store_true",
                        help="No descifrar los valores \"ED:\" (dejarlos tal cual).")
    parser.add_argument("-o", "--output", default=None,
                        help="Escribir el JSON del catálogo en este archivo.")
    parser.add_argument("--self-test", action="store_true",
                        help="Ejecutar las comprobaciones internas y salir.")
    args = parser.parse_args(argv)
    if args.self_test:
        checks = _self_test()
        failed = [name for name, ok in checks if not ok]
        for name, ok in checks:
            print("%-18s %s" % (name, "OK" if ok else "FAIL"))
        print("%d/%d OK" % (len(checks) - len(failed), len(checks)))
        return 0 if not failed else 1
    t0 = time.time()
    if args.ping:
        doc = fetch_ping()
        servers = doc if isinstance(doc, list) else doc.get("servers", doc)
        summary = {"ping_entries": len(servers) if isinstance(servers, list) else "?"}
    elif args.path:
        data = Path(args.path).read_bytes()
        doc = decode(data, keep_ed=args.keep_ed)
        summary = _summary(doc)
    elif args.url:
        doc = fetch_catalog(args.url, keep_ed=args.keep_ed)
        summary = _summary(doc)
    else:
        parser.error("usa --url, --file o --ping")
    if args.output:
        Path(args.output).write_text(
            json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("Escrito: %s" % args.output)
    else:
        print(json.dumps(doc, ensure_ascii=False, indent=2))
    print("Resumen: %s (%.1f s)" % (summary, time.time() - t0), file=sys.stderr)
    return 0


def main():
    try:
        raise SystemExit(run())
    except DecodeError as exc:
        print("ERROR [%s]: %s" % (exc.code, exc), file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
