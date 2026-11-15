#!/usr/bin/env python3
"""LinkLayer VPN - decodificador del catalogo gratuito (free.php).

App: LinkLayer VPN, com.newtoolsworks.linklayer, version 3.11.2 (versionCode 93),
minSdk 21. Version de Google Play (actualizada 31 ago 2026), verificada en el
APK de APKPure (SHA-256 00ee9552d2de9e53d87ca9fa2a702b6bf754503c61cf108dc5af9fe894169642).

Metodo (verificado en vivo 2026-11-14, cuerpo determinista):
    GET https://linklayer.newtoolsworks.com/free.php
    (la app usa net/http.(*Client).Get sin cabeceras propias; el servidor
    responde igual con cualquier User-Agent)
  -> cuerpo: una linea Base64 estandar
  -> Base64 -> blob OpenSSL "Salted__" (8 B magic + 16 B salt + ciphertext)
  -> EVP_BytesToKey con MD5 (1 iteracion) -> AES-256-CBC, PKCS#7
  -> JSON: {"FreeLocationIndex", "username", "password", "expiration",
            "version", "cfs": [{location, hostHTTPTLS, hostip4, hostip6,
            sslPorts, httpPorts, wsDomain, pubkey, domain, serverUDP,
            obfsUDP, httpdualSelect, httpdual: [{name, host}]}]}

La contrasena del formato se construye en tiempo de ejecucion en
configuration.init (libgojni.so, Go): FormatInt(98548) + FormatInt(63245)
+ "8oMkh2bs3pZcJL1XAb" + FormatInt(84277). Es una constante del formato del
catalogo (como las claves de otros proveedores), no una credencial de usuario.

Resultado en vivo (2026-11-14): version "v3.1- IPV6", 3 ubicaciones gratuitas
(USA 1, USA 2, Amsterdam 1), usuario/contrasena "free"/"free", expiration 0.
No hay seccion de payloads: el catalogo es una lista de servidores con sus
puertos SSL/HTTP y opciones httpdual (CDN 1 / Direct / Direct6). El cuerpo
en vivo es determinista (SHA-256 cf2d8172f0d377e547251369dc672f72b8e283abfadff7f3beb7409d13bd669b).

El catalogo incluido en el APK (assets/flayer.dat) usa el MISMO metodo y
contrasena; solo cambian los hosts (ntwtunnel.com en vez de q-turbo.com).

Solo Python estandar. Sin dependencias.

Uso:
    python3 LinkLayer.py --url            # descarga y descifra el catalogo
    python3 LinkLayer.py --url <URL>      # otra URL con el mismo formato
    python3 LinkLayer.py --file <f>       # descifra un cuerpo guardado
    python3 LinkLayer.py --asset          # descifra flayer.dat incluido
    python3 LinkLayer.py --self-test      # pruebas (round-trip + asset)
    python3 LinkLayer.py --url -o out.json
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

CATALOG_URL = "https://linklayer.newtoolsworks.com/free.php"
# Constante del formato del catalogo (ver docstring): se construye en
# configuration.init como FormatInt(98548) + FormatInt(63245) +
# "8oMkh2bs3pZcJL1XAb" + FormatInt(84277).
FORMAT_PASSWORD = "98548632458oMkh2bs3pZcJL1XAb84277"
MAX_BYTES = 8 * 1024 * 1024


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- AES (pure python, stdlib only)
# Nucleo verificado contra PyCryptodome (mismo nucleo usado en AR PRO / Fat).

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
        raise ValueError("ciphertext length must be a multiple of 16")
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
        raise ValueError("empty data")
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad PKCS#7 padding")
    return data[:-pad]


def _pkcs7_pad(data):
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


# ---------------------------------------------------------------- EVP_BytesToKey (OpenSSL, MD5)

def _evp_bytes_to_key(password: str, salt: bytes, key_len=32, iv_len=16):
    """OpenSSL EVP_BytesToKey, 1 iteracion, MD5 (lo que usa aes256.Decrypt)."""
    out = b""
    prev = b""
    pw = password.encode("utf-8")
    while len(out) < key_len + iv_len:
        prev = hashlib.md5(prev + pw + salt).digest()
        out += prev
    return out[:key_len], out[key_len:key_len + iv_len]


def decrypt_salted(blob: bytes, password: str = FORMAT_PASSWORD) -> bytes:
    """Descifra un blob OpenSSL Salted__ (AES-256-CBC, PKCS#7)."""
    if len(blob) < 32 or blob[:8] != b"Salted__":
        raise DecodeError("FORMAT_ERROR", "Se esperaba un blob OpenSSL Salted__.")
    salt, ct = blob[8:16], blob[16:]
    if len(ct) % 16:
        raise DecodeError("FORMAT_ERROR", "El ciphertext no es multiplo de 16.")
    key, iv = _evp_bytes_to_key(password, salt)
    try:
        return _pkcs7_unpad(_aes_cbc_decrypt(key, iv, ct))
    except ValueError as exc:
        raise DecodeError("DECRYPT_FAILED", "No descifra con la clave del formato.") from exc


def encrypt_salted(plaintext: bytes, password: str = FORMAT_PASSWORD,
                   salt: bytes = b"\x00" * 16) -> bytes:
    """Cifra al formato Salted__ (solo para --self-test)."""
    key, iv = _evp_bytes_to_key(password, salt)
    return b"Salted__" + salt + _aes_cbc_encrypt(key, iv, _pkcs7_pad(plaintext))


# ---------------------------------------------------------------- catalogo

def decode(data) -> dict:
    """Descifra un cuerpo de catalogo (Base64 o bytes crudos) y devuelve el JSON."""
    if isinstance(data, str):
        text = data.strip()
    elif isinstance(data, (bytes, bytearray)):
        text = bytes(data).decode("utf-8-sig", errors="strict").strip()
    else:
        raise DecodeError("FORMAT_ERROR", "Se esperaba texto Base64 o bytes.")
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el limite de tamano.")
    compact = re.sub(r"[ \t\r\n]", "", text)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        raise DecodeError("FORMAT_ERROR", "Se esperaba Base64 estandar.")
    try:
        raw = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR", "Base64 invalido.") from exc
    plain = decrypt_salted(raw)
    try:
        doc = json.loads(plain.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise DecodeError("FORMAT_ERROR", "El descifrado no produjo JSON valido.") from exc
    if not isinstance(doc, dict) or "cfs" not in doc:
        raise DecodeError("FORMAT_ERROR", "El JSON no es un catalogo LinkLayer (falta 'cfs').")
    return doc


def fetch_catalog(url: str = CATALOG_URL, timeout: int = 30) -> bytes:
    """Descarga el catalogo exactamente como la app: GET simple, sin auth.

    La app usa net/http.(*Client).Get con el cliente por defecto de Go
    (User-Agent: Go-http-client/1.1). El servidor responde igual con
    cualquier UA; se envia la de Go para replicar la peticion.
    """
    req = urllib.request.Request(url, method="GET", headers={
        "User-Agent": "Go-http-client/1.1",
        "Accept-Encoding": "identity",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                raise DecodeError("HTTP_ERROR", f"HTTP {resp.status} en {url}")
            return resp.read()
    except DecodeError:
        raise
    except Exception as exc:
        raise DecodeError("HTTP_ERROR", f"No se pudo descargar {url}: {exc}") from exc


def summary(doc: dict) -> str:
    cfs = doc.get("cfs") or []
    lines = [
        f"version: {doc.get('version')}",
        f"usuario: {doc.get('username')} / contrasena: {doc.get('password')}",
        f"expiration: {doc.get('expiration')}  FreeLocationIndex: {doc.get('FreeLocationIndex')}",
        f"ubicaciones gratuitas: {len(cfs)}",
    ]
    for loc in cfs:
        dual = loc.get("httpdual") or []
        lines.append(
            f"  - {loc.get('location')}: {loc.get('hostHTTPTLS')} "
            f"({loc.get('hostip4')} / {loc.get('hostip6')}) "
            f"sslPorts={loc.get('sslPorts')} wsDomain={loc.get('wsDomain')} "
            f"httpdual={len(dual)}"
        )
    lines.append("payloads: 0 (el catalogo no trae seccion de payloads; "
                 "las opciones de conexion son httpdual: CDN 1 / Direct / Direct6)")
    return "\n".join(lines)


def run(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", nargs="?", const=CATALOG_URL, default=None,
                        help="descarga el catalogo (URL opcional, por defecto free.php)")
    parser.add_argument("--file", type=Path, default=None,
                        help="descifra un cuerpo guardado (Base64)")
    parser.add_argument("--asset", action="store_true",
                        help="descifra el flayer.dat incluido en el APK")
    parser.add_argument("--self-test", action="store_true",
                        help="pruebas: round-trip sintetico + asset incluido")
    parser.add_argument("-o", "--output", type=Path, default=None,
                        help="guarda el JSON descifrado")
    parser.add_argument("--summary", action="store_true",
                        help="imprime solo el resumen")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        if args.file is not None:
            doc = decode(args.file.read_bytes())
            source = f"archivo {args.file}"
        elif args.asset:
            asset = Path(__file__).resolve().parent / "flayer.dat"
            doc = decode(asset.read_bytes())
            source = f"asset {asset.name}"
        elif args.url is not None:
            body = fetch_catalog(args.url)
            doc = decode(body)
            source = f"URL {args.url}"
        else:
            parser.error("usa --url, --file, --asset o --self-test")
    except DecodeError as exc:
        print(f"LinkLayer [{exc.code}]: {exc}", file=sys.stderr)
        return 2

    if args.output is not None:
        args.output.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"guardado en {args.output} ({source})")
    if args.summary:
        print(summary(doc))
    else:
        print(json.dumps(doc, ensure_ascii=False, indent=2))
        print("--- resumen ---")
        print(summary(doc))
    return 0


def self_test() -> int:
    checks = []
    # 1. Round-trip sintetico con el mismo formato Salted__.
    sample = {"version": "v3.1- TEST", "username": "free", "password": "free",
              "expiration": 0, "FreeLocationIndex": 0,
              "cfs": [{"location": "Test 1", "hostHTTPTLS": "t.example.com",
                       "hostip4": "1.2.3.4", "hostip6": "::1",
                       "sslPorts": "443,80", "httpPorts": "443,80",
                       "wsDomain": "ws.example.com", "pubkey": "00",
                       "domain": "ns.example.com", "serverUDP": "t.example.com",
                       "obfsUDP": "xxxx", "httpdualSelect": 0,
                       "httpdual": [{"name": "CDN 1", "host": "cdn.example.com:80"}]}]}
    plain = json.dumps(sample, ensure_ascii=False).encode("utf-8")
    blob = encrypt_salted(plain, salt=b"\x01\x02\x03\x04\x05\x06\x07\x08")
    got = decode(base64.b64encode(blob).decode("ascii"))
    checks.append(("round-trip sintetico Salted__", got == sample))
    # 2. El asset incluido (flayer.dat del APK) abre con la misma clave.
    asset = Path(__file__).resolve().parent / "flayer.dat"
    doc = decode(asset.read_bytes())
    checks.append(("asset flayer.dat abre", doc.get("version") == "v3.1- IPV6"
                  and len(doc.get("cfs", [])) == 3))
    checks.append(("asset: 3 ubicaciones", [c.get("location") for c in doc["cfs"]]
                  == ["USA 1", "USA 2", "Amsterdam 1"]))
    # 3. La muestra viva guardada (catalog_sample.b64) abre igual.
    sample_path = Path(__file__).resolve().parent / "catalog_sample.b64"
    if sample_path.exists():
        live = decode(sample_path.read_bytes())
        checks.append(("muestra viva abre", live.get("version") == "v3.1- IPV6"
                      and len(live.get("cfs", [])) == 3))
        checks.append(("muestra viva: hosts q-turbo",
                      all("q-turbo.com" in (c.get("hostHTTPTLS") or "")
                          for c in live["cfs"])))
    # 4. Un blob con otra clave NO abre (padding invalido).
    try:
        decrypt_salted(blob, password="clave-incorrecta")
        checks.append(("clave incorrecta rechazada", False))
    except DecodeError:
        checks.append(("clave incorrecta rechazada", True))

    ok = True
    for name, passed in checks:
        print(f"[{'OK' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    print(f"self-test: {sum(1 for _, p in checks if p)}/{len(checks)} OK")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(run())
