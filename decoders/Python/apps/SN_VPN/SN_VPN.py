#!/usr/bin/env python3
"""Decodificador del catalogo de SN VPN (com.snnombre.snvpn) para SP-DECODE.

Metodo verificado en el APK SN VPN 5.0.7 (versionCode 507), sin cobertura
previa en el repo SP-DECODE:

    GET https://raw.githubusercontent.com/SINNOMBRE22/Fallas/main/online.json
    (HttpURLConnection, metodo GET, sin cabeceras, timeouts 10 s)

    cuerpo = texto de caracteres invisibles U+2000..U+200F (portador nibble)
    texto Base64 = nibble(carrier)                       (v.b / I0/a)
    JSON = AES-256-CBC(Base64, key, IV = 16 ceros, PKCS#7)
    key  = SHA-256(hexadecimal en mayusculas de "ARABIR")
         = SHA-256(b"415241424952")

El mismo metodo abre el segundo archivo del mismo repositorio, que la app
5.0.7 NO descarga (no hay ninguna referencia a el en el DEX; puede ser de
otra version de la app o de otra app del mismo autor):

    GET https://raw.githubusercontent.com/SINNOMBRE22/Fallas/main/online_v2.json

online.json es el formato v1 (ServerConfig: Version/Servers/SSH/Networks/
SSLNetworks/UDPCustom/DNSTT/V2RAYCustom/BHTTP/Notes). online_v2.json es el
formato v2 (Version/FormatVersion/Configs[]). Este script detecta ambos.

ESTADO EN VIVO (verificado 2026-11-14 con descarga real):
  * online.json (el endpoint de la app): Version "4.0" con TODAS las listas
    vacias. El vendedor vacio el catalogo; el script lo reporta como
    catalogo vacio, no inventa servidores.
  * online_v2.json: Version "2.0.27", 25 configs, todas FREE (21 SSH, 1
    HYSTERIA, 1 ZIVPN, 1 SLOWDNS, 1 BHTTP; 21 con Payload, 21 con SNIHost).

Los otros dos archivos del repositorio (cfg_b69n7avsse8xg0_v2.dat y
supra_vpn.dat) NO abren con esta clave (padding invalido); no pertenecen al
catalogo de SN VPN 5.0.7 y no se incluyen.

Sin esquema URI propio: el manifest solo registra VIEW/SEND con scheme
content/file y mimeType */* para importar archivos .sn. La app si atiende
enlaces estandar vmess://, vless://, trojan://, ss://, hysteria2://, hy2://
e hysteria:// por pegado de texto, ya cubiertos por SP-DECODE.

Solo stdlib de Python. Sin contrasenas de usuario ni claves de dispositivo.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import struct
import sys
import urllib.request
from pathlib import Path

CATALOG_URL = "https://raw.githubusercontent.com/SINNOMBRE22/Fallas/main/online.json"
CATALOG_V2_URL = "https://raw.githubusercontent.com/SINNOMBRE22/Fallas/main/online_v2.json"
USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 14)"
MAX_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 200000

# Clave del catalogo: SHA-256 del hexadecimal en mayusculas de "ARABIR".
CATALOG_KEY = hashlib.sha256(b"415241424952").digest()
CATALOG_IV = bytes(16)

# Alfabeto del portador invisible: U+2000..U+200F, en orden (I0/a::b).
_CARRIER = [chr(0x2000 + i) for i in range(16)]
_CARRIER_INDEX = {c: i for i, c in enumerate(_CARRIER)}


class DecodeError(ValueError):
    """El catalogo no se pudo decodificar. `code` clasifica el fallo."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------------ AES puro
def _make_sbox():
    sbox = []
    for i in range(256):
        if i == 0:
            inv = 0
        else:
            inv = None
            for y in range(1, 256):
                p = 0
                aa, bb = i, y
                while bb:
                    if bb & 1:
                        p ^= aa
                    aa = ((aa << 1) ^ (0x1b if aa & 0x80 else 0)) & 0xFF
                    bb >>= 1
                if p == 1:
                    inv = y
                    break
        s = inv ^ ((inv << 1) | (inv >> 7)) ^ ((inv << 2) | (inv >> 6)) \
            ^ ((inv << 3) | (inv >> 5)) ^ ((inv << 4) | (inv >> 4)) ^ 0x63
        sbox.append(s & 0xFF)
    return sbox


_SBOX = _make_sbox()
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF


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


# ------------------------------------------------------------- decodificacion
def carrier_decode(text):
    """Portador invisible U+2000..U+200F -> bytes del texto Base64 (I0/a)."""
    nibs = [_CARRIER_INDEX[c] for c in text if c in _CARRIER_INDEX]
    if len(nibs) < 2 or len(nibs) % 2:
        raise DecodeError("FORMAT_ERROR",
                          "El portador invisible no tiene un numero par de caracteres.")
    return bytes((nibs[i] << 4) | nibs[i + 1] for i in range(0, len(nibs), 2))


def carrier_encode(data: bytes) -> str:
    """Inverso de carrier_decode: bytes -> texto invisible U+2000..U+200F."""
    out = []
    for b in data:
        out.append(_CARRIER[b >> 4])
        out.append(_CARRIER[b & 0x0F])
    return "".join(out)


def _base64(data: bytes) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR", "Base64 invalido.") from exc


def _text(data):
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "Se esperaba texto o bytes UTF-8.")
    if isinstance(data, bytes):
        if len(data) > MAX_BYTES:
            raise DecodeError("SIZE_LIMIT", "La entrada supera el limite de tamano.")
        try:
            value = data.decode("utf-8-sig")
        except UnicodeError as exc:
            raise DecodeError("FORMAT_ERROR", "La entrada no es UTF-8 valido.") from exc
    else:
        value = data.removeprefix("\ufeff")
    if len(value.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el limite de tamano.")
    return value


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
    return doc


def decrypt_catalog_bytes(data) -> dict:
    """Portador invisible -> Base64 -> AES-256-CBC -> JSON del catalogo."""
    text = _text(data)
    # La app quita espacios y saltos de linea antes de decodificar.
    text = text.replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "")
    try:
        b64 = carrier_decode(text)
    except DecodeError:
        # Sin portador: aceptar el cuerpo ya en Base64 directo.
        if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text):
            b64 = text.encode("ascii")
        else:
            raise
    raw = _base64(b64)
    if len(raw) < 16 or len(raw) % 16:
        raise DecodeError("FORMAT_ERROR",
                          "El cuerpo cifrado no es multiplo de 16 bytes.")
    try:
        plain = _pkcs7_unpad(_aes_cbc_decrypt(CATALOG_KEY, CATALOG_IV, raw))
    except ValueError as exc:
        raise DecodeError("DECRYPT_FAILED",
                          "AES-CBC no abre el catalogo (clave o cuerpo distintos).") from exc
    try:
        doc = json.loads(plain.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DecodeError("FORMAT_ERROR", "El catalogo descifrado no es JSON.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("FORMAT_ERROR", "El catalogo descifrado no es un objeto JSON.")
    return _validate(doc)


def encrypt_catalog_bytes(doc: dict) -> str:
    """Inverso de decrypt_catalog_bytes (para pruebas de round-trip)."""
    plain = _pkcs7_pad(json.dumps(doc, ensure_ascii=False).encode("utf-8"))
    raw = _aes_cbc_encrypt(CATALOG_KEY, CATALOG_IV, plain)
    return carrier_encode(base64.b64encode(raw))


def summarize(doc: dict) -> dict:
    """Resumen del catalogo: version, servidores y redes/payloads."""
    out = {"version": doc.get("Version"), "format": None, "servers": 0,
           "networks": 0, "with_payload": 0, "with_sni": 0, "free": 0,
           "notes": doc.get("Notes", "")}
    if isinstance(doc.get("Configs"), list):
        out["format"] = "v2"
        cfgs = doc["Configs"]
        out["servers"] = len(cfgs)
        out["networks"] = len(cfgs)
        out["with_payload"] = sum(1 for c in cfgs if isinstance(c, dict) and c.get("Payload"))
        out["with_sni"] = sum(1 for c in cfgs if isinstance(c, dict) and c.get("SNIHost"))
        out["free"] = sum(1 for c in cfgs if isinstance(c, dict) and c.get("Category") == "FREE")
        from collections import Counter
        out["protocols"] = dict(Counter(c.get("Protocol") for c in cfgs if isinstance(c, dict)))
        return out
    out["format"] = "v1"
    servers = doc.get("Servers") or []
    networks = doc.get("Networks") or []
    out["servers"] = len(servers) if isinstance(servers, list) else 0
    out["networks"] = len(networks) if isinstance(networks, list) else 0
    out["lists"] = {k: len(v) for k, v in doc.items() if isinstance(v, list)}
    return out


def decode(data) -> dict:
    """Decodifica un catalogo y devuelve el JSON como dict."""
    return decrypt_catalog_bytes(data)


def fetch(url: str, timeout: int = 60) -> bytes:
    """GET exacto como la app: sin cabeceras propias, solo el User-Agent."""
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise DecodeError("HTTP_ERROR", "HTTP %d al descargar %s" % (resp.status, url))
        return resp.read()


def run(args=None):
    parser = argparse.ArgumentParser(
        prog="SN_VPN.py",
        description="Decodificador del catalogo de SN VPN (online.json / online_v2.json).")
    parser.add_argument("--url", nargs="?", const=CATALOG_URL, default=None,
                        help="Descargar el catalogo de una URL (por defecto, online.json).")
    parser.add_argument("--file", help="Leer el catalogo de un archivo local.")
    parser.add_argument("--stdin", action="store_true", help="Leer el catalogo de stdin.")
    parser.add_argument("--self-test", action="store_true", help="Pruebas internas.")
    parser.add_argument("-o", "--out", help="Guardar el JSON descifrado en un archivo.")
    parser.add_argument("--json", action="store_true",
                        help="Imprimir el resumen como JSON de una linea.")
    ns = parser.parse_args(args)

    if ns.self_test:
        return 0 if _self_test() else 1

    if ns.url:
        raw = fetch(ns.url)
        source = ns.url
    elif ns.file:
        raw = Path(ns.file).read_bytes()
        source = ns.file
    elif ns.stdin:
        raw = sys.stdin.buffer.read()
        source = "stdin"
    else:
        parser.error("Falta --url, --file o --stdin.")

    try:
        doc = decrypt_catalog_bytes(raw)
    except DecodeError as exc:
        print("ERROR [%s]: %s" % (exc.code, exc), file=sys.stderr)
        return 2
    info = summarize(doc)
    info["source"] = source
    if ns.out:
        Path(ns.out).write_text(json.dumps(doc, ensure_ascii=False, indent=2),
                                encoding="utf-8")
    if ns.json:
        print(json.dumps(info, ensure_ascii=False))
        return 0
    print("SN VPN - catalogo de %s" % source)
    print("Version: %s (formato %s)" % (info["version"], info["format"]))
    if info.get("notes"):
        print("Notas: %s" % info["notes"])
    if info["format"] == "v2":
        print("Configs: %d (FREE: %d)" % (info["servers"], info["free"]))
        print("Protocolos: %s" % (info["protocols"],))
        print("Con Payload: %d | Con SNIHost: %d" % (info["with_payload"], info["with_sni"]))
    else:
        if not any(info.get("lists", {}).values()):
            print("Catalogo VACIO: todas las listas estan vacias.")
        else:
            print("Listas: %s" % (info["lists"],))
    return 0


def _self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("OK  " if cond else "FAIL") + " " + name)
        ok = ok and bool(cond)

    # AES-256 KAT (FIPS-197, ECB): key 000102...1f,
    # plaintext 00112233...ff -> ciphertext 8ea2b7ca516745bfeafc49904b496089.
    key = bytes(range(32))
    iv = bytes(range(16))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    check("AES-256 KAT",
          _aes_encrypt_block(key, pt).hex() == "8ea2b7ca516745bfeafc49904b496089")
    check("AES-256 decrypt KAT",
          _aes_decrypt_block(key, bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")) == pt)
    ct = _aes_cbc_encrypt(key, iv, _pkcs7_pad(pt))
    check("AES-256-CBC round-trip", _pkcs7_unpad(_aes_cbc_decrypt(key, iv, ct)) == pt)
    # Clave del catalogo: SHA-256 del hex de "ARABIR".
    check("clave ARABIR",
          CATALOG_KEY.hex() == "20ffeeb0f381a71025943a057eee79bbc51823d13c560d5c8e81a604ce042439")
    # Round-trip del portador invisible.
    sample = base64.b64encode(b"hola SN VPN")
    check("portador round-trip", carrier_decode(carrier_encode(sample)) == sample)
    # Round-trip completo del catalogo (formato v1 y v2).
    doc1 = {"Version": "9.9", "Servers": [], "SSH": [], "Networks": [],
            "SSLNetworks": [], "UDPCustom": [], "DNSTT": [], "V2RAYCustom": [],
            "BHTTP": [], "Notes": "prueba"}
    check("catalogo v1 round-trip", decrypt_catalog_bytes(encrypt_catalog_bytes(doc1)) == doc1)
    doc2 = {"Version": "2.0.99", "FormatVersion": 2, "Notes": "prueba",
            "Configs": [{"Name": "Test", "Category": "FREE", "Protocol": "SSH",
                         "Host": "1.2.3.4", "Port": "443", "Payload": "GET /",
                         "SNIHost": "example.com"}]}
    check("catalogo v2 round-trip", decrypt_catalog_bytes(encrypt_catalog_bytes(doc2)) == doc2)
    check("resumen v2", summarize(doc2)["servers"] == 1
          and summarize(doc2)["with_payload"] == 1)
    print("SELF-TEST: " + ("TODO OK" if ok else "FALLO"))
    return ok


if __name__ == "__main__":
    sys.exit(run())
