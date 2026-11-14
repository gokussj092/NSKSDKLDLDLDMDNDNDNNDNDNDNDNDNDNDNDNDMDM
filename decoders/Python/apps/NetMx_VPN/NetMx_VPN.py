#!/usr/bin/env python3
"""NetMx VPN 2.0.7: catalog decoder, local file or explicit HTTPS.

Python 3.10+, solo biblioteca estandar: AES-256-CBC esta implementado
en Python puro en este archivo (verificado contra PyCryptodome con el
asset incluido en el APK y con el catalogo en vivo).
Package com.imxfree.vpn, versionCode 207, versionName 2.0.7.

Catalog source recovered from the decompiled app (jadx):
  imx.free.vpn.util.Utils.getSystemSyncStatus()
  imx.free.vpn.util.ConfigUpdate.doInBackground()
  imx.free.vpn.util.AESCrypt.decrypt()
  imx.free.vpn.util.ConfigUtil.getJSONConfig()

The app downloads the catalog with a plain GET, no headers, no auth
(HttpURLConnection, default Dalvik User-Agent):

    GET https://raw.githubusercontent.com/MarVarGueZ/Mio/refs/heads/main/vpsvip.json

The body is one long line of block characters (the app's Jacodes
encoding). Decoding, exactly as AESCrypt does:

    text -> genString: each PAIR of block chars is one byte of a Base64
            string (first char = high nibble, second = low nibble,
            alphabet below, 16 chars)
         -> Base64 decode -> AES-256-CBC/PKCS7 ciphertext
         -> AES/CBC/PKCS7Padding, key = SHA-256(uppercase hex of the
            password string "NetMxVpn2025"), IV = 16 zero bytes
         -> UTF-8 JSON: {"version", "releaseNotes", "servers": [...]}

The same format is used for the bundled asset (assets/config/config.json)
and for the offline import: ServersActivity writes any imported file
verbatim to filesDir/Config.json and ConfigUtil reads it back with the
same AESCrypt.decrypt call (see NetMx_VPN_archivos.py).

Server entries: serverName, serverInfo ("Mexico" / "Estados Unidos"),
serverFlag (2-letter flag code, assets/flags/<code>.png), serverHost,
serverPort (443), sni, tunnelType (2 = SSH), serverType (0 = SSH,
2 = UDP), username/password/payload/proxyHost/proxyPort (empty in the
live catalog), plus udpHost/udpPort/udpObf/udpAuth/udpDown/udpUp on the
UDP servers. There is no payload/tweak section in this catalog and no
free/premium flag: every server listed is a free server.

LIVE STATUS (2026-11-13): the endpoint answers HTTP 200, 179857 bytes,
and decrypts with the app key: version "157", 88 servers (86 SSH on
port 443 + 2 "UDP Internacional"), 44 Mexico / 44 Estados Unidos,
0 payload entries (the catalog has no payload section). The bundled
asset opens with the same key: version "100", 1 placeholder server
("Actualiza los servidores...").

The checkUser endpoints found in the DEX
(http://mx.teammx.xyz:6888/checkUser, http://us.teammx.xyz:6888/checkUser)
are a separate user/premium check (DialogHelper.CheckUser), not part of
the catalog download, so they are not used here.

No .sks files in this app, and no own URI scheme: the manifest has no
ACTION_VIEW intent filter for the app's activities and no custom scheme,
so there is no text-link decoder to add. Standard vmess/vless/ss/trojan
links are already covered by SP-DECODE core.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import re
import sys
import urllib.request
from urllib.error import HTTPError, URLError

MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000

CATALOG_URL = "https://raw.githubusercontent.com/MarVarGueZ/Mio/refs/heads/main/vpsvip.json"
# Exact request the app makes: plain GET, no headers, no auth
# (HttpURLConnection default Dalvik User-Agent).
USER_AGENT = "Dalvik/2.1.0"
# AESCrypt key material: Utils.getDisplayDensity() returns this constant.
PASSWORD = "NetMxVpn2025"
# AESCrypt alphabet: Base64-decode of
# "4paZ4paa4pab4pac4pad4pae4paf4paD4paE4paF4paG4paH4paI4paJ4paK4paQ".
ALPHABET = "▙▚▛▜▝▞▟▃▄▅▆▇█▉▊▐"
ZERO_IV = bytes(16)


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
_INV_SBOX = (
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d,
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


def _sub(s, inv=False):
    box = _INV_SBOX if inv else _SBOX
    for i in range(16):
        s[i] = box[s[i]]


def _shift(s, inv=False):
    for r in range(1, 4):
        row = [s[4 * c + r] for c in range(4)]
        sh = (4 - r) if inv else r
        row = row[sh:] + row[:sh]
        for c in range(4):
            s[4 * c + r] = row[c]


def _mix(s, inv=False):
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        if inv:
            s[4 * c + 0] = _mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9)
            s[4 * c + 1] = _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13)
            s[4 * c + 2] = _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11)
            s[4 * c + 3] = _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)
        else:
            s[4 * c + 0] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
            s[4 * c + 1] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
            s[4 * c + 2] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
            s[4 * c + 3] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)


def _aes_decrypt_block(key, block):
    w, nr = _key_expansion(key)
    s = list(block)
    _add_rk(s, w, nr)
    for rnd in range(nr - 1, 0, -1):
        _sub(s, True)
        _shift(s, True)
        _add_rk(s, w, rnd)
        _mix(s, True)
    _sub(s, True)
    _shift(s, True)
    _add_rk(s, w, 0)
    return bytes(s)


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


def _aes_cbc_decrypt(key, iv, data):
    if len(data) % 16:
        raise DecodeError("DECRYPT_FAILED", "La longitud del cifrado no es multiplo de 16.")
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        dec = _aes_decrypt_block(key, blk)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    return bytes(out)


def _aes_cbc_encrypt(key, iv, data):
    if len(data) % 16:
        raise ValueError("plaintext length must be a multiple of 16")
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        enc = _aes_encrypt_block(key, blk)
        out += enc
        prev = enc
    return bytes(out)


def _pkcs7_unpad(data):
    if not data:
        raise DecodeError("DECRYPT_FAILED", "Datos vacios.")
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise DecodeError("DECRYPT_FAILED", "Relleno PKCS#7 invalido.")
    return data[:-pad]


def _pkcs7_pad(data):
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


# ---------------------------------------------------------------- helpers

def _text(data):
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "Se esperaba texto o bytes UTF-8.")
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el limite de tamano.")
    try:
        value = data.decode("utf-8-sig") if isinstance(data, bytes) else data.removeprefix("\ufeff")
        if len(value.encode("utf-8")) > MAX_BYTES:
            raise DecodeError("SIZE_LIMIT", "La entrada supera el limite de tamano.")
    except UnicodeError as exc:
        raise DecodeError("FORMAT_ERROR", "La entrada no es UTF-8 valido.") from exc
    return value


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
            raise DecodeError("SIZE_LIMIT", "El JSON supera el limite de complejidad.")
        if isinstance(value, dict):
            pending.extend((v, depth + 1) for v in value.values())
            pending.extend((k, depth + 1) for k in value)
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise DecodeError("INVALID_JSON", "Numero JSON no finito.")
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError as exc:
                raise DecodeError("INVALID_JSON", "Unicode JSON invalido.") from exc
    return doc


def _json(data):
    try:
        doc = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON", "JSON invalido o con claves duplicadas.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El documento debe contener un objeto JSON.")
    return _validate(doc)


# ---------------------------------------------------------------- AESCrypt (app)

def _jakey(password):
    """AESCrypt.Jakey: hex en mayusculas de los bytes UTF-8 del password."""
    return "".join("{:02X}".format(b) for b in password.encode("utf-8"))


def _aes_key(password=PASSWORD):
    """AESCrypt.a: SHA-256 del hex del password."""
    return hashlib.sha256(_jakey(password).encode("utf-8")).digest()


def _genstring(text):
    """AESCrypt.genString: pares de caracteres del alfabeto -> bytes Base64."""
    idx = {c: i for i, c in enumerate(ALPHABET)}
    compact = re.sub(r"\s+", "", text)
    if len(compact) % 2:
        raise DecodeError("FORMAT_ERROR", "El texto cifrado tiene un numero impar de caracteres.")
    out = bytearray()
    for i in range(0, len(compact), 2):
        hi, lo = compact[i], compact[i + 1]
        if hi not in idx or lo not in idx:
            raise DecodeError("FORMAT_ERROR", "Caracter fuera del alfabeto del formato.")
        out.append((idx[hi] * 16 + idx[lo]) & 0xFF)
    return bytes(out)


def _jacodes(data):
    """AESCrypt.Jacodes: bytes -> pares de caracteres del alfabeto."""
    return "".join(ALPHABET[b >> 4] + ALPHABET[b & 0x0F] for b in data)


def encrypt(plaintext, password=PASSWORD):
    """AESCrypt.encrypt: texto plano -> texto de caracteres de bloque."""
    raw = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext
    ct = _aes_cbc_encrypt(_aes_key(password), ZERO_IV, _pkcs7_pad(raw))
    return _jacodes(base64.b64encode(ct))


def decrypt(data, password=PASSWORD):
    """AESCrypt.decrypt: texto de caracteres de bloque -> texto plano UTF-8."""
    text = _text(data)
    b64 = _genstring(text)
    try:
        ct = base64.b64decode(b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR", "El Base64 interno es invalido.") from exc
    pt = _pkcs7_unpad(_aes_cbc_decrypt(_aes_key(password), ZERO_IV, ct))
    try:
        return pt.decode("utf-8")
    except UnicodeError as exc:
        raise DecodeError("DECRYPT_FAILED", "El texto descifrado no es UTF-8 valido.") from exc


def decode(data):
    """Decodifica un catalogo NetMx (texto cifrado) y devuelve el dict JSON."""
    return _json(decrypt(data))


def run(file_bytes):
    """Devuelve el catalogo como texto JSON (para el formato del repo)."""
    return json.dumps(decode(file_bytes), ensure_ascii=False)


# ---------------------------------------------------------------- download

def fetch_catalog(url=CATALOG_URL, retries=3):
    """GET exactamente como la app (ConfigUpdate): sin cabeceras propias,
    sin auth. Reintenta el GET completo si el cuerpo llega truncado."""
    last = None
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", USER_AGENT)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                if resp.status != 200:
                    raise DecodeError("HTTP_ERROR", "El servidor respondio HTTP %d." % resp.status)
                body = resp.read()
        except (HTTPError, URLError, OSError) as exc:
            last = DecodeError("NETWORK_ERROR", "No se pudo descargar el catalogo: %s" % exc)
            continue
        try:
            decode(body)
        except DecodeError as exc:
            last = exc
            continue
        return body
    raise last


def _summary(doc):
    servers = doc.get("servers", []) if isinstance(doc.get("servers"), list) else []
    info = {}
    for s in servers:
        if isinstance(s, dict):
            info[s.get("serverInfo", "?")] = info.get(s.get("serverInfo", "?"), 0) + 1
    udp = sum(1 for s in servers if isinstance(s, dict) and s.get("serverType") == 2)
    ssh = sum(1 for s in servers if isinstance(s, dict) and s.get("serverType") == 0)
    payloads = sum(1 for s in servers if isinstance(s, dict) and s.get("payload"))
    return {
        "version": doc.get("version"),
        "servers": len(servers),
        "ssh": ssh,
        "udp": udp,
        "by_region": info,
        "payloads": payloads,
    }


def _self_test():
    # 1) Round-trip sintetico con el mismo esquema de la app.
    sample = {"version": "999", "releaseNotes": "prueba ñandú",
              "servers": [{"serverName": "Prueba", "serverInfo": "México",
                           "serverHost": "example.com", "serverPort": "443",
                           "sni": "example.com", "tunnelType": 2, "serverType": 0}]}
    text = json.dumps(sample, ensure_ascii=False)
    back = decode(encrypt(text))
    assert back == sample, "round-trip no coincide"
    # 2) El asset incluido en el APK (copia en work/) si esta presente.
    bundled = None
    for cand in ("assets/config/config.json", "work/assets/config/config.json"):
        try:
            bundled = open(cand, encoding="utf-8").read()
            break
        except OSError:
            continue
    checks = {"self_test": "OK", "round_trip": True}
    if bundled is not None:
        doc = decode(bundled)
        checks["bundled_version"] = doc.get("version")
        checks["bundled_servers"] = len(doc.get("servers", []))
    return checks


def main(argv=None):
    parser = argparse.ArgumentParser(description="Decodificador del catalogo de NetMx VPN.")
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("file", nargs="?", help="Archivo cifrado (Config.json) a decodificar")
    source.add_argument("--url", nargs="?", const=CATALOG_URL,
                        help="Descarga explicita; por defecto usa el endpoint original")
    source.add_argument("--stdin", action="store_true", help="Lee el texto cifrado de stdin")
    parser.add_argument("-o", "--output", help="Escribe el JSON descifrado en este archivo")
    parser.add_argument("--self-test", action="store_true", help="Pruebas internas sin red")
    args = parser.parse_args(argv)

    if args.self_test:
        print(json.dumps(_self_test(), ensure_ascii=False))
        return 0

    if args.url:
        raw = fetch_catalog(args.url)
        doc = decode(raw)
    elif args.stdin:
        doc = decode(sys.stdin.buffer.read())
    elif args.file:
        with open(args.file, "rb") as fh:
            doc = decode(fh.read())
    else:
        parser.error("se requiere un archivo, --url o --stdin (o --self-test)")

    out = json.dumps(doc, ensure_ascii=False, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
    else:
        print(out)
    print(json.dumps({"summary": _summary(doc)}, ensure_ascii=False), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
