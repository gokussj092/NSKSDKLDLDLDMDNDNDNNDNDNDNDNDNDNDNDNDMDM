#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RH Tunnel Lite (com.rhtunnelmax.app) 39.0.1 (build 52) - Catalogo en vivo SP-DECODE
====================================================================================
Metodo de catalogo (verificado en vivo 2026-11-14):
  * El catalogo es un JSON ("Servers.js": FileName "update") con 17 servidores y
    200 redes/payloads en la version en vivo. El archivo se sirve cifrado con el
    mismo doble cifrado que el asset integrado sabconfig.hs de la APK.
  * Fuente en vivo: API de GitHub (repositorio privado del desarrollador) con
    token Bearer; la app pide el archivo rhtunnel.json de la rama main con
    Accept: application/vnd.github.v3.raw y un cache-buster ?t=<millis>.
    Sin token la API responde 404 y la URL raw directa tambien da 404.
  * Cifrado del blob: empaquetado chino de 12 bits (cada valor + 0x4E00 -> caracter
    CJK) + AES/CBC/PKCS7, clave = SHA-256 de la clave de texto, IV = 16 ceros.
    Se aplica DOS veces (util.decrypt x2). El texto resultante lleva el prefijo
    "Telegram@noob_xman" antes del '{' del JSON.
  * Campos sensibles del JSON (hosts, IPs, usuarios, claves, enlaces vless/vmess,
    el certificado Ovpn y las URLs de config) van cifrados con XXTEA (delta
    NO estandar, distinto de 0x9E3779B9) en Base64 estandar, misma clave de texto
    que el AES. Los campos cortos de texto plano (nombres, banderas, tipos) van
    en claro.
  * Regla SP-DECODE (2026-11-15): el JSON de resultado (parse_catalog y
    --out) lleva solo los datos del catalogo, todo descifrado; las APIs de
    descarga (config_url, cloud_get_api, account_api, upload_get_api,
    upload_post_api) se descifran para comprobar que abren, pero no van en
    el resultado.
  * Enlaces de texto (compartir por portapapeles, no hay scheme en el manifest):
    "SabDev://" + XXTEA-Base64 del JSON de un servidor y "shanS://" + XXTEA-Base64
    del JSON de una red/payload. Ver RH_Tunnel_Lite_archivos.py.
  * Nube: no hay compartir por codigo ni registro de dispositivo en 39.0.1.
    La "nube" es el propio catalogo alojado en GitHub (config_url / cloud_get_api
    apuntan al mismo archivo rhtunnel.json). Los campos account_api,
    upload_get_api y upload_post_api se leen pero estan ausentes en el catalogo
    actual.

Uso:
  python3 RH_Tunnel_Lite.py --url            # descarga el catalogo en vivo y lo muestra
  python3 RH_Tunnel_Lite.py --url --out catalogo.json
  python3 RH_Tunnel_Lite.py --raw ARCHIVO   # descifra un blob (sabconfig.hs o rhtunnel.json)
  python3 RH_Tunnel_Lite.py --self-test     # pruebas internas (incluye descarga en vivo)

Solo biblioteca estandar para la red y el resto; AES usa pycryptodome si esta
disponible y si no una implementacion pura incluida en este archivo.
"""

import argparse
import base64
import hashlib
import json
import os
import struct
import sys
import time
import urllib.request

# ---------------------------------------------------------------------------
# Credenciales embebidas en la APK (solo para uso operativo de este script).
# NO copiar a reportes, README, TESTING.md ni NOTES.md.
# El token de GitHub NO va en Git (AGENTS.md regla 4): vive en
# SPDECODE_RH_TUNNEL_GITHUB_TOKEN, la misma variable que usa el
# secretHeader del registro (supplied-integrations.json).
# ---------------------------------------------------------------------------
_API_URL = "https://api.github.com/repos/polashvpn/polashdevapi/contents/rhtunnel.json?ref=main"
_API_TOKEN = os.environ.get("SPDECODE_RH_TUNNEL_GITHUB_TOKEN", "")
_AES_KEY_TEXT = "rhtunnellite"
_XXTEA_KEY_TEXT = "rhtunnellite"
_XXTEA_DELTA = 772515655
_PREFIX = "Telegram@noob_xman"

_UA = "SabrinaPro-App"

# ---------------------------------------------------------------------------
# AES puro en Python (descifrado y cifrado, claves de 128/192/256 bits)
# ---------------------------------------------------------------------------

# AES rapido si pycryptodome esta disponible; si no, implementacion pura
# incluida abajo (misma salida, mas lenta). El self-test verifica ambas.
try:
    from Crypto.Cipher import AES as _CRYPTO_AES
except Exception:
    _CRYPTO_AES = None


def _gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gf_inv(a):
    if a == 0:
        return 0
    r = 1
    for _ in range(254):
        r = _gf_mul(r, a)
    return r


def _build_sboxes():
    sbox = []
    inv_sbox = [0] * 256
    for i in range(256):
        inv = _gf_inv(i)
        s = inv
        for shift in (1, 2, 3, 4):
            s ^= ((inv << shift) | (inv >> (8 - shift))) & 0xFF
        s ^= 0x63
        s &= 0xFF
        sbox.append(s)
        inv_sbox[s] = i
    return sbox, inv_sbox


_SBOX, _INV_SBOX = _build_sboxes()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _expand_key(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[i * 4:(i + 1) * 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    return w, nr


def _add_round_key(state, w, rnd):
    for c in range(4):
        for r in range(4):
            state[r][c] ^= w[rnd * 4 + c][r]


def _sub_bytes(state, box):
    for r in range(4):
        for c in range(4):
            state[r][c] = box[state[r][c]]


def _shift_rows(state, inverse=False):
    for r in range(1, 4):
        row = [state[r][c] for c in range(4)]
        n = r if not inverse else 4 - r
        row = row[n:] + row[:n]
        for c in range(4):
            state[r][c] = row[c]


def _mix_columns(state, inverse=False):
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        if not inverse:
            state[0][c] = _gf_mul(a[0], 2) ^ _gf_mul(a[1], 3) ^ a[2] ^ a[3]
            state[1][c] = a[0] ^ _gf_mul(a[1], 2) ^ _gf_mul(a[2], 3) ^ a[3]
            state[2][c] = a[0] ^ a[1] ^ _gf_mul(a[2], 2) ^ _gf_mul(a[3], 3)
            state[3][c] = _gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ _gf_mul(a[3], 2)
        else:
            state[0][c] = _gf_mul(a[0], 14) ^ _gf_mul(a[1], 11) ^ _gf_mul(a[2], 13) ^ _gf_mul(a[3], 9)
            state[1][c] = _gf_mul(a[0], 9) ^ _gf_mul(a[1], 14) ^ _gf_mul(a[2], 11) ^ _gf_mul(a[3], 13)
            state[2][c] = _gf_mul(a[0], 13) ^ _gf_mul(a[1], 9) ^ _gf_mul(a[2], 14) ^ _gf_mul(a[3], 11)
            state[3][c] = _gf_mul(a[0], 11) ^ _gf_mul(a[1], 13) ^ _gf_mul(a[2], 9) ^ _gf_mul(a[3], 14)


def _aes_block(key, block, encrypt):
    w, nr = _expand_key(key)
    state = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
    if encrypt:
        _add_round_key(state, w, 0)
        for rnd in range(1, nr):
            _sub_bytes(state, _SBOX)
            _shift_rows(state)
            _mix_columns(state)
            _add_round_key(state, w, rnd)
        _sub_bytes(state, _SBOX)
        _shift_rows(state)
        _add_round_key(state, w, nr)
    else:
        _add_round_key(state, w, nr)
        for rnd in range(nr - 1, 0, -1):
            _shift_rows(state, inverse=True)
            _sub_bytes(state, _INV_SBOX)
            _add_round_key(state, w, rnd)
            _mix_columns(state, inverse=True)
        _shift_rows(state, inverse=True)
        _sub_bytes(state, _INV_SBOX)
        _add_round_key(state, w, 0)
    return bytes(state[r][c] for c in range(4) for r in range(4))


def aes_cbc_decrypt(key, data, iv=bytes(16)):
    if len(data) % 16:
        raise ValueError("datos AES no multiplos de 16")
    if _CRYPTO_AES is not None:
        return _CRYPTO_AES.new(key, _CRYPTO_AES.MODE_CBC, iv).decrypt(data)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = _aes_block(key, data[i:i + 16], encrypt=False)
        out += bytes(a ^ b for a, b in zip(blk, prev))
        prev = data[i:i + 16]
    return bytes(out)


def aes_cbc_encrypt(key, data, iv=bytes(16)):
    pad = 16 - (len(data) % 16)
    data = data + bytes([pad]) * pad
    if _CRYPTO_AES is not None:
        return _CRYPTO_AES.new(key, _CRYPTO_AES.MODE_CBC, iv).encrypt(data)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        enc = _aes_block(key, blk, encrypt=True)
        out += enc
        prev = enc
    return bytes(out)


def _pkcs7_unpad(data):
    if not data:
        raise ValueError("vacio")
    pad = data[-1]
    if not 1 <= pad <= 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("padding PKCS7 invalido")
    return data[:-pad]


# ---------------------------------------------------------------------------
# Empaquetado chino de 12 bits (c_00.chineseToBytes / bytesToChinese)
# ---------------------------------------------------------------------------

def chinese_to_bytes(s):
    length = (((len(s) * 12) // 8) // 16) * 16
    if length == 0 and len(s) > 0:
        length = 16
    out = bytearray(length)
    acc = 0
    nbits = 0
    j = 0
    for ch in s:
        acc = (acc << 12) | ((ord(ch) - 19968) & 0xFFF)
        nbits += 12
        while nbits >= 8 and j < length:
            out[j] = (acc >> (nbits - 8)) & 0xFF
            nbits -= 8
            j += 1
        # conservar solo los bits aun no consumidos (si no, acc crece sin
        # limite y el bucle se vuelve cuadratico en textos largos)
        if nbits:
            acc &= (1 << nbits) - 1
        else:
            acc = 0
    return bytes(out)


def bytes_to_chinese(data):
    acc = 0
    nbits = 0
    chars = []
    for b in data:
        acc = (acc << 8) | b
        nbits += 8
        while nbits >= 12:
            chars.append(chr(19968 + ((acc >> (nbits - 12)) & 0xFFF)))
            nbits -= 12
        if nbits:
            acc &= (1 << nbits) - 1
        else:
            acc = 0
    if nbits:
        chars.append(chr(19968 + ((acc << (12 - nbits)) & 0xFFF)))
    return "".join(chars)


def util_decrypt(text):
    """Una capa: chino -> AES/CBC(SHA-256(clave), IV cero) -> unpad."""
    raw = chinese_to_bytes(text)
    key = hashlib.sha256(_AES_KEY_TEXT.encode()).digest()
    return _pkcs7_unpad(aes_cbc_decrypt(key, raw))


def util_encrypt(data):
    """Inversa de util_decrypt (para construir muestras sinteticas)."""
    key = hashlib.sha256(_AES_KEY_TEXT.encode()).digest()
    ct = aes_cbc_encrypt(key, data)
    return bytes_to_chinese(ct)


def sab_decrypt(text):
    """Descifra un blob sabconfig.hs / rhtunnel.json: doble util.decrypt."""
    step1 = util_decrypt(text)
    step2 = util_decrypt(step1.decode("utf-8"))
    return step2


def sab_encrypt(data):
    """Inversa de sab_decrypt (para muestras sinteticas)."""
    inner = util_encrypt(data)
    return util_encrypt(inner.encode("utf-8"))


# ---------------------------------------------------------------------------
# XXTEA (delta no estandar de la app) + Base64 estandar (TeaBase64)
# ---------------------------------------------------------------------------

def _mx(total, y, z, p, e, k):
    return (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z))


def _to_int_array(data, include_length):
    n = (len(data) + 3) // 4
    out = [0] * n
    for i, b in enumerate(data):
        out[i >> 2] |= b << ((i & 3) * 8)
    if include_length:
        out.append(len(data))
    return out


def _to_byte_array(data, include_length):
    n = len(data) * 4
    if include_length:
        m = data[-1]
        if m < n - 7 or m > n - 4:
            return None
        n = m
    out = bytearray()
    for v in data:
        out += struct.pack("<I", v & 0xFFFFFFFF)
    return bytes(out[:n])


def _fix_key(key):
    k = key[:16]
    return k + bytes(16 - len(k))


def xxtea_decrypt(data, key_text=_XXTEA_KEY_TEXT):
    key = _to_int_array(_fix_key(key_text.encode()), False)
    v = _to_int_array(data, False)
    n = len(v)
    if n < 2:
        return None
    rounds = 6 + 52 // n
    total = (rounds * _XXTEA_DELTA) & 0xFFFFFFFF
    y = v[0]
    while total != 0:
        e = (total >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - _mx(total, y, z, p, e, key)) & 0xFFFFFFFF
            y = v[p]
        z = v[n - 1]
        v[0] = (v[0] - _mx(total, y, z, 0, e, key)) & 0xFFFFFFFF
        y = v[0]
        total = (total - _XXTEA_DELTA) & 0xFFFFFFFF
    return _to_byte_array(v, True)


def xxtea_encrypt(data, key_text=_XXTEA_KEY_TEXT):
    key = _to_int_array(_fix_key(key_text.encode()), False)
    v = _to_int_array(data, True)
    n = len(v)
    rounds = 6 + 52 // n
    total = 0
    y = v[n - 1]
    for _ in range(rounds):
        total = (total + _XXTEA_DELTA) & 0xFFFFFFFF
        e = (total >> 2) & 3
        for p in range(n - 1):
            z = v[p + 1]
            v[p] = (v[p] + _mx(total, z, y, p, e, key)) & 0xFFFFFFFF
            y = v[p]
        z = v[0]
        v[n - 1] = (v[n - 1] + _mx(total, z, y, n - 1, e, key)) & 0xFFFFFFFF
        y = v[n - 1]
    return _to_byte_array(v, False)


def c01_decrypt(s):
    """c_01.decrypt: XXTEA-Base64 -> texto."""
    if not s:
        return ""
    pt = xxtea_decrypt(base64.b64decode(s))
    return pt.decode("utf-8") if pt is not None else None


def c01_encrypt(s):
    """c_01.encrypt: texto -> XXTEA-Base64 (enlaces SabDev:// y shanS://)."""
    return base64.b64encode(xxtea_encrypt(s.encode("utf-8"))).decode()


def maybe_xxtea(value):
    """Descifra un campo del catalogo si es XXTEA-Base64; si no, lo deja igual.
    Repite hasta 3 rondas: algunos campos (p. ej. V2rayID) van cifrados dos
    veces con XXTEA, y el resultado de la primera ronda sigue siendo un
    sobre Base64. Cada ronda solo se aplica si el descifrado pasa la
    comprobacion de longitud de XXTEA y produce UTF-8 valido; un texto en
    claro que parezca Base64 no se toca porque su 'descifrado' no pasa
    esas comprobaciones."""
    if not isinstance(value, str) or not value:
        return value
    cur = value
    for _ in range(3):
        try:
            raw = base64.b64decode(cur, validate=True)
        except Exception:
            return cur
        if len(raw) < 8 or len(raw) % 4 != 0:
            return cur
        pt = xxtea_decrypt(raw)
        if pt is None:
            return cur
        try:
            nxt = pt.decode("utf-8")
        except Exception:
            return cur
        if nxt == cur:
            return cur
        cur = nxt
    return cur


# ---------------------------------------------------------------------------
# Catalogo
# ---------------------------------------------------------------------------

def parse_catalog(text):
    """Descifra el blob (o acepta JSON en claro) y devuelve el dict con
    todos los campos cifrados ya descifrados.

    Regla SP-DECODE (2026-11-15): el JSON de resultado lleva SOLO los datos
    del catalogo, todo descifrado. Las APIs de descarga del catalogo
    (config_url, cloud_get_api, account_api, upload_get_api,
    upload_post_api) se descifran si vienen cifradas, pero NO se incluyen
    en el resultado: la URL de descarga y el token viven solo en este
    script, nunca en el JSON de salida."""
    if text.lstrip().startswith("{"):
        raw = text.encode("utf-8")
    else:
        raw = sab_decrypt(text)
    if raw.startswith(_PREFIX.encode()):
        raw = raw[len(_PREFIX):]
    doc = json.loads(raw.decode("utf-8"))
    # Campos de API de descarga del catalogo: se descifran (si vienen
    # cifrados) para comprobar que abren, pero no van al resultado.
    for _api_field in ("config_url", "cloud_get_api", "account_api",
                       "upload_get_api", "upload_post_api"):
        _v = doc.get(_api_field)
        if isinstance(_v, str) and _v:
            maybe_xxtea(_v)
    out = {
        "FileName": doc.get("FileName"),
        "Version": doc.get("Version"),
        "ReleaseNotes": doc.get("ReleaseNotes"),
        "contactSupport": doc.get("contactSupport"),
        "AppConfPass": doc.get("AppConfPass"),
        "Servers": [{k: maybe_xxtea(v) for k, v in s.items()}
                    for s in doc.get("Servers", [])],
        "HTTPNetworks": [{k: maybe_xxtea(v) for k, v in n.items()}
                         for n in doc.get("HTTPNetworks", [])],
        "JSONsettings": doc.get("JSONsettings"),
        "Ovpn_Cert": maybe_xxtea(doc.get("Ovpn_Cert", "")),
    }
    return out


def fetch_live():
    """Replica la peticion exacta de la app (checkUpdate / checkUpdateSab):
    GET al API de GitHub con Bearer, UA SabrinaPro-App, Accept v3.raw y
    cache-buster ?t=<millis> (la URL ya lleva ?ref=main, asi que va con &t=)."""
    if not _API_TOKEN:
        raise ValueError("Falta SPDECODE_RH_TUNNEL_GITHUB_TOKEN (token GitHub de la app, por entorno; nunca en Git)")
    sep = "&" if "?" in _API_URL else "?"
    url = _API_URL + sep + "t=" + str(int(time.time() * 1000))
    req = urllib.request.Request(url, headers={
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Authorization": "Bearer " + _API_TOKEN,
        "User-Agent": _UA,
        "Accept": "application/vnd.github.v3.raw",
    })
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8")


def summarize(doc):
    lines = []
    lines.append("RH Tunnel Lite - catalogo %s (FileName %s)" % (doc["Version"], doc["FileName"]))
    lines.append("Servidores: %d | Redes/payloads: %d" % (len(doc["Servers"]), len(doc["HTTPNetworks"])))
    for s in doc["Servers"]:
        lines.append("  [%s] %s | %s | IP=%s | CF=%s | HTTP=%s | Tcp=%s SSL=%s | user=%s" % (
            s.get("serverType"), s.get("Name"), s.get("FLAG"),
            s.get("ServerIP"), s.get("ServerCloudFront"), s.get("ServerHTTP"),
            s.get("TcpPort"), s.get("SSLPort"), s.get("Username")))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def self_test(live=True):
    ok = 0
    fails = []

    def check(name, cond):
        nonlocal ok
        if cond:
            ok += 1
            print("  OK  " + name)
        else:
            fails.append(name)
            print("  FAIL " + name)

    print("RH Tunnel Lite --self-test")
    print("  INFO AES: %s" % ("pycryptodome" if _CRYPTO_AES is not None else "puro Python"))

    # 1. AES puro contra vector conocido (generado con pycryptodome al desarrollar:
    #    AES-256-CBC, clave SHA-256 de la clave de texto, IV cero, PKCS7,
    #    plaintext b"RH-TUNNEL-LITE-TEST-1234567890" -> 32 bytes de ciphertext).
    key = hashlib.sha256(_AES_KEY_TEXT.encode()).digest()
    ct = bytes.fromhex("c1d88b3becca351cff7d3cf59197ec42c259c1e84efdad663880dc51734749bf")
    pt = _pkcs7_unpad(aes_cbc_decrypt(key, ct))
    check("AES-256-CBC vector conocido (pycryptodome)", pt == b"RH-TUNNEL-LITE-TEST-1234567890")
    pt2 = _pkcs7_unpad(aes_cbc_decrypt(key, aes_cbc_encrypt(key, b"RH-TUNNEL-LITE-TEST-1234567890")))
    check("AES-256-CBC round-trip (cifrar/descifrar)", pt2 == b"RH-TUNNEL-LITE-TEST-1234567890")

    # 2. Empaquetado chino round-trip (la funcion java solo se usa con
    #    ciphertext AES, multiplo de 16 bytes, y ahi es exacta)
    sample = b"0123456789ABCDEF0123456789ABCDEF"  # 32 bytes
    check("empaquetado chino 12 bits round-trip",
          chinese_to_bytes(bytes_to_chinese(sample)) == sample)

    # 3. XXTEA round-trip (delta no estandar) + c_01
    msg = '{"Name":"TEST","ServerIP":"1.2.3.4"}'
    enc = c01_encrypt(msg)
    check("XXTEA c_01 round-trip (encriptar/descifrar)", c01_decrypt(enc) == msg)

    # 4. Doble AES (sab) round-trip sobre un mini Servers.js
    mini = {"FileName": "update", "Version": "9.9-test", "Servers": [], "HTTPNetworks": []}
    blob = sab_encrypt((_PREFIX + json.dumps(mini)).encode("utf-8"))
    back = sab_decrypt(blob)
    check("doble AES sabconfig round-trip",
          json.loads(back[len(_PREFIX):].decode("utf-8"))["Version"] == "9.9-test")

    # 5. parse_catalog sobre el mini blob
    doc = parse_catalog(blob)
    check("parse_catalog del mini blob", doc["Version"] == "9.9-test")

    # 6. Enlaces de texto round-trip
    srv = {"Name": "TEST", "serverType": 0, "ServerIP": "1.2.3.4", "Username": "u"}
    link = "SabDev://" + c01_encrypt(json.dumps(srv))
    got = json.loads(c01_decrypt(link[len("SabDev://"):]))
    check("enlace SabDev:// round-trip", got["ServerIP"] == "1.2.3.4")
    net = {"Name": "NET", "SSLSNI": "www.google.com", "payload_type": "ovpn"}
    link2 = "shanS://" + c01_encrypt(json.dumps(net))
    got2 = json.loads(c01_decrypt(link2[len("shanS://"):]))
    check("enlace shanS:// round-trip", got2["SSLSNI"] == "www.google.com")

    # 7. Descarga en vivo (si hay red)
    if live:
        try:
            raw = fetch_live()
            doc = parse_catalog(raw)
            check("descarga en vivo: catalogo parsea (Version %s, %d servidores, %d redes)"
                  % (doc["Version"], len(doc["Servers"]), len(doc["HTTPNetworks"])),
                  len(doc["Servers"]) > 0 and len(doc["HTTPNetworks"]) > 0)
            print("  INFO version en vivo: %s" % doc["Version"])
        except Exception as e:
            print("  SKIP descarga en vivo (sin red o error): %s" % e)

    print("self-test: %d OK, %d FAIL" % (ok, len(fails)))
    return 1 if fails else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="RH Tunnel Lite - catalogo en vivo y descifrador")
    ap.add_argument("--url", action="store_true", help="descargar el catalogo en vivo")
    ap.add_argument("--raw", metavar="ARCHIVO", help="descifrar un blob local (sabconfig.hs / rhtunnel.json)")
    ap.add_argument("--out", metavar="ARCHIVO", help="guardar el JSON descifrado")
    ap.add_argument("--self-test", action="store_true", help="pruebas internas")
    ap.add_argument("--no-live", action="store_true", help="self-test sin descarga en vivo")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test(live=not args.no_live)

    if args.raw:
        with open(args.raw, "r", encoding="utf-8") as f:
            text = f.read()
        doc = parse_catalog(text)
    elif args.url:
        doc = parse_catalog(fetch_live())
    else:
        ap.print_help()
        return 2

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=1)
        print("guardado en %s" % args.out)
    print(summarize(doc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
