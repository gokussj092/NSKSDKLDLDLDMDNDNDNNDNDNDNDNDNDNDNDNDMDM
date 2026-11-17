#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
M Light (com.pausatotal.mlight) 3.1.55 - descarga y descifrado del catalogo.

Metodo exacto (verificado en vivo 2026-11-15 contra el endpoint real):
  * Descarga: GET a la URL del catalogo (GitHub raw, repo publico de
    PausaStudio), sin headers ni User-Agent propios (defecto de Java),
    connect/read timeout 15 s, exige HTTP 200. La app (clase Lwo,
    AsyncTask) lee el cuerpo linea a linea y lo concatena sin saltos.
  * Cifrado del config ("AESCrypt", clase L...):
      1. El texto descargado son caracteres baybayin; cada par codifica
         1 byte: byte = indice(alfabeto, c[2i]) * 16 + indice(alfabeto,
         c[2i+1]), con un alfabeto de 17 caracteres.
      2. Esos bytes, como UTF-8, son una cadena Base64 (NO_WRAP) ->
         bytes del ciphertext.
      3. AES/CBC/PKCS7Padding, IV = 16 bytes cero, clave = SHA-256 del
         hex (alfabeto estandar 0123456789ABCDEF, mayusculas) de la
         clave en claro. La clave en claro sale de la funcion nativa
         getAESKey() (libsec_core.so), que la construye caracter por
         caracter.
      4. El texto plano descifrado es el JSON del catalogo, ya en claro
         (sin sobres internos: 0 valores con caracteres baybayin).
  * La app guarda el config descargado en getFilesDir() con el nombre
    "ic_launcher.png" (disimulado). Si no existe el archivo local, usa
    el asset assets/flags/iusacel.png (no es un PNG: es el config
    ofuscado, version 1.0.0).
  * URL secundaria (no usada por este script salvo con --messages):
    messages-config.json, mismo cifrado, con los mensajes de la app
    (JsonVersion 1.0.26).

El JSON de resultado lleva SOLO los datos del catalogo, todo descifrado;
NUNCA incluye las URLs/endpoints de descarga ni tokens (regla de Pedro,
2026-11-15). Las URLs y la clave viven solo en este script.

Uso:
  python3 M_Light.py --download [--out catalogo.json] [--fields]
  python3 M_Light.py --raw respuesta_guardada.txt [--out catalogo.json]
  python3 M_Light.py --download --messages [--out ...]
  python3 M_Light.py --self-test
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from collections import Counter

# ------------------------------------------------------------------ URLs
CATALOG_URL = "https://raw.githubusercontent.com/PausaStudio/pausada258/refs/heads/main/config.json"
MESSAGES_URL = "https://raw.githubusercontent.com/PausaStudio/pausada258/refs/heads/main/messages-config.json"

# Clave en claro del catalogo (sale de getAESKey() en libsec_core.so).
# La clave AES real es SHA-256 del hex en mayusculas de esta cadena.
_CATALOG_PASSWORD = "dam9n"

# Alfabeto baybayin de 17 caracteres (campo estatico de AESCrypt, fijado
# en <clinit> desde un array de 50 bytes). El 17o caracter no aparece en
# los archivos descargados; es parte del alfabeto igualmente. Se define
# por codepoints para evitar confusion entre glifos parecidos.
ALPHABET = "".join(chr(c) for c in (
    0x6e6, 0x1711, 0x1710, 0x170f, 0x170e, 0x170c, 0x1708, 0x1707, 0x1706,
    0x1702, 0x1701, 0x1700, 0x170b, 0x170a, 0x1709, 0x1705, 0x1704))
_TIMEOUT_S = 15


class DecodeError(Exception):
    """Fallo al descifrar o parsear el catalogo."""


# ------------------------------------------------------------------ AES
# Se usa pycryptodome si esta disponible; si no, AES puro en Python
# (validado en el self-test contra el vector FIPS-197 AES-256 y contra
# pycryptodome cuando esta presente).
try:
    from Crypto.Cipher import AES as _PycryptAES  # type: ignore

    def _aes_cbc_decrypt(key, iv, data):
        return _PycryptAES.new(key, _PycryptAES.MODE_CBC, iv).decrypt(data)

    def _aes_cbc_encrypt(key, iv, data):
        return _PycryptAES.new(key, _PycryptAES.MODE_CBC, iv).encrypt(data)

    _AES_BACKEND = "pycryptodome"
except Exception:  # pragma: no cover - fallback puro
    _AES_BACKEND = "pure-python"

    _SBOX = (
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    )
    _INV_SBOX = (
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
    )
    _RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)

    def _xtime(a):
        return ((a << 1) ^ (0x1b if a & 0x80 else 0)) & 0xff

    def _gmul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            a = _xtime(a)
            b >>= 1
        return r

    def _key_expand(key):
        nk = len(key) // 4
        nr = nk + 6
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        for i in range(nk, 4 * (nr + 1)):
            t = list(w[i - 1])
            if i % nk == 0:
                t = [_SBOX[t[1]] ^ _RCON[i // nk - 1], _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
            elif nk > 6 and i % nk == 4:
                t = [_SBOX[x] for x in t]
            w.append([w[i - nk][j] ^ t[j] for j in range(4)])
        return w, nr

    def _add_rk(state, w, rnd):
        for c in range(4):
            for r in range(4):
                state[r][c] ^= w[4 * rnd + c][r]

    def _sub(state, box):
        for r in range(4):
            for c in range(4):
                state[r][c] = box[state[r][c]]

    def _shift(state, inv=False):
        for r in range(1, 4):
            row = [state[r][c] for c in range(4)]
            n = r if not inv else 4 - r
            for c in range(4):
                state[r][c] = row[(c + n) % 4]

    def _mix(state, inv=False):
        for c in range(4):
            col = [state[r][c] for r in range(4)]
            if not inv:
                state[0][c] = _gmul(col[0], 2) ^ _gmul(col[1], 3) ^ col[2] ^ col[3]
                state[1][c] = col[0] ^ _gmul(col[1], 2) ^ _gmul(col[2], 3) ^ col[3]
                state[2][c] = col[0] ^ col[1] ^ _gmul(col[2], 2) ^ _gmul(col[3], 3)
                state[3][c] = _gmul(col[0], 3) ^ col[1] ^ col[2] ^ _gmul(col[3], 2)
            else:
                state[0][c] = _gmul(col[0], 14) ^ _gmul(col[1], 11) ^ _gmul(col[2], 13) ^ _gmul(col[3], 9)
                state[1][c] = _gmul(col[0], 9) ^ _gmul(col[1], 14) ^ _gmul(col[2], 11) ^ _gmul(col[3], 13)
                state[2][c] = _gmul(col[0], 13) ^ _gmul(col[1], 9) ^ _gmul(col[2], 14) ^ _gmul(col[3], 11)
                state[3][c] = _gmul(col[0], 11) ^ _gmul(col[1], 13) ^ _gmul(col[2], 9) ^ _gmul(col[3], 14)

    def _block(key, block, decrypt=False):
        w, nr = _key_expand(key)
        state = [[block[4 * c + r] for c in range(4)] for r in range(4)]
        if not decrypt:
            _add_rk(state, w, 0)
            for rnd in range(1, nr):
                _sub(state, _SBOX)
                _shift(state)
                _mix(state)
                _add_rk(state, w, rnd)
            _sub(state, _SBOX)
            _shift(state)
            _add_rk(state, w, nr)
        else:
            _add_rk(state, w, nr)
            for rnd in range(nr - 1, 0, -1):
                _shift(state, inv=True)
                _sub(state, _INV_SBOX)
                _add_rk(state, w, rnd)
                _mix(state, inv=True)
            _shift(state, inv=True)
            _sub(state, _INV_SBOX)
            _add_rk(state, w, 0)
        return bytes(state[r][c] for c in range(4) for r in range(4))

    def _aes_cbc_decrypt(key, iv, data):
        if len(data) % 16:
            raise DecodeError("ciphertext no multiplo de 16")
        out = bytearray()
        prev = iv
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            dec = _block(key, chunk, decrypt=True)
            out += bytes(a ^ b for a, b in zip(dec, prev))
            prev = chunk
        return bytes(out)

    def _aes_cbc_encrypt(key, iv, data):
        if len(data) % 16:
            raise DecodeError("plaintext no multiplo de 16")
        out = bytearray()
        prev = iv
        for i in range(0, len(data), 16):
            chunk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
            enc = _block(key, chunk)
            out += enc
            prev = enc
        return bytes(out)


# ------------------------------------------------------- derivacion/clave
def derive_key(password):
    """Clave AES-256: SHA-256 del hex en mayusculas de la clave en claro."""
    hex_upper = password.encode("utf-8").hex().upper()
    return hashlib.sha256(hex_upper.encode("ascii")).digest()


def _unpad(data):
    if not data:
        raise DecodeError("descifrado vacio")
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise DecodeError("padding PKCS7 invalido")
    return data[:-pad]


def _pad(data):
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


# ------------------------------------------------- codificacion baybayin
def baybayin_decode(text):
    """Pares de caracteres baybayin -> bytes (cada par = 1 byte)."""
    text = "".join(text.split())
    if len(text) % 2:
        raise DecodeError("texto baybayin con longitud impar: %d" % len(text))
    idx = {c: i for i, c in enumerate(ALPHABET)}
    out = bytearray()
    for i in range(0, len(text), 2):
        hi = idx.get(text[i])
        lo = idx.get(text[i + 1])
        if hi is None or lo is None:
            raise DecodeError("caracter fuera del alfabeto en posicion %d" % i)
        out.append(hi * 16 + lo)
    return bytes(out)


def baybayin_encode(data):
    """Bytes -> pares de caracteres baybayin."""
    return "".join(ALPHABET[b >> 4] + ALPHABET[b & 0x0f] for b in data)


# ------------------------------------------------------- cifrado AESCrypt
def decrypt_config(text, password=_CATALOG_PASSWORD):
    """Descifra el texto del config (baybayin -> Base64 -> AES-CBC) -> str."""
    raw = baybayin_decode(text)
    try:
        b64 = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError("bytes intermedios no son UTF-8") from exc
    try:
        ciphertext = base64.b64decode(b64, validate=False)
    except Exception as exc:
        raise DecodeError("Base64 intermedia invalida") from exc
    key = derive_key(password)
    plain = _unpad(_aes_cbc_decrypt(key, b"\x00" * 16, ciphertext))
    return plain.decode("utf-8")


def encrypt_config(plaintext, password=_CATALOG_PASSWORD):
    """Cifra texto plano -> texto baybayin (inverso exacto de decrypt_config)."""
    key = derive_key(password)
    ciphertext = _aes_cbc_encrypt(key, b"\x00" * 16, _pad(plaintext.encode("utf-8")))
    b64 = base64.b64encode(ciphertext).decode("ascii")
    return baybayin_encode(b64.encode("utf-8"))


# ---------------------------------------------------------------- descarga
def fetch_live(url=CATALOG_URL):
    """GET exacto de la app: sin headers propios, timeouts 15 s, exige 200."""
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            if resp.status != 200:
                raise DecodeError("HTTP %d" % resp.status)
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise DecodeError("HTTP %d" % exc.code) from exc
    except urllib.error.URLError as exc:
        raise DecodeError("error de red: %s" % exc.reason) from exc


def decode_catalog(text):
    """Texto cifrado descargado -> dict del catalogo (todo en claro)."""
    plain = decrypt_config(text)
    try:
        data = json.loads(plain)
    except json.JSONDecodeError as exc:
        raise DecodeError("JSON invalido tras descifrar: %s" % exc) from exc
    if not isinstance(data, dict):
        raise DecodeError("el catalogo no es un objeto JSON")
    return data


# --------------------------------------------------------------- resumen
def summarize(data):
    servers = data.get("Servers") or []
    total_fields = 0
    nonempty = 0
    flags = Counter()
    myservers = Counter()
    for srv in servers:
        if not isinstance(srv, dict):
            continue
        total_fields += len(srv)
        for key, value in srv.items():
            # False (booleanos ZacDevz*) no cuenta como "no vacio": son
            # 890 valores false que inflarian el conteo sin aportar datos.
            if value not in ("", None) and value is not False:
                nonempty += 1
        flags[srv.get("Flag", "")] += 1
        myservers[srv.get("MyServer", "")] += 1
    lines = [
        "M Light - catalogo v%s" % data.get("Version", "?"),
        "servidores: %d" % len(servers),
        "MyServer distintos: %d" % len([k for k in myservers if k]),
        "campos por servidor: %d total, %d no vacios" % (total_fields, nonempty),
        "flags: %s" % dict(flags.most_common(8)),
    ]
    return "\n".join(lines)


def field_coverage(data):
    """Cobertura por campo sobre la lista Servers."""
    servers = data.get("Servers") or []
    counts = Counter()
    for srv in servers:
        if isinstance(srv, dict):
            for key, value in srv.items():
                if value not in ("", None) and value is not False:
                    counts[key] += 1
    total = len(servers)
    out = ["campo: no vacios / %d servidores" % total]
    for key, count in counts.most_common():
        out.append("  %-16s %d" % (key, count))
    return "\n".join(out)


# -------------------------------------------------------------- self-test
def _self_test():
    checks = []

    def check(name, fn):
        try:
            fn()
            checks.append((name, True, ""))
        except Exception as exc:  # noqa: BLE001
            checks.append((name, False, "%s: %s" % (type(exc).__name__, exc)))

    def _fips_vector():
        # FIPS-197 AES-256: clave 000102...1f, texto 00112233...eeff
        key = bytes(range(32))
        plain = bytes.fromhex("00112233445566778899aabbccddeeff")
        want = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
        got = _aes_cbc_encrypt(key, b"\x00" * 16, plain)
        if got != want:
            raise AssertionError("vector FIPS-197 no coincide (encrypt)")
        back = _aes_cbc_decrypt(key, b"\x00" * 16, got)
        if back != plain:
            raise AssertionError("vector FIPS-197 no coincide (decrypt)")

    def _roundtrip():
        sample = json.dumps(
            {"Version": "1.0.999", "Servers": [{"Name": "Prueba", "ServerIP": "1.2.3.4"}]},
            ensure_ascii=False,
        )
        enc = encrypt_config(sample)
        if decrypt_config(enc) != sample:
            raise AssertionError("round-trip baybayin/AES fallo")
        if any(c not in ALPHABET for c in enc):
            raise AssertionError("el cifrado no usa solo el alfabeto")

    def _derive_key_known():
        # SHA-256 del hex en mayusculas de la clave en claro.
        want = hashlib.sha256("64616D396E".encode("ascii")).digest()
        if derive_key(_CATALOG_PASSWORD) != want:
            raise AssertionError("derivacion de clave no coincide")

    def _bundled_asset():
        # El asset bundled assets/flags/iusacel.png (v1.0.0) debe abrir.
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "apk", "extract2", "assets", "flags", "iusacel.png")
        if not os.path.exists(path):
            path = os.path.join(here, "work", "extract2", "assets", "flags", "iusacel.png")
        if not os.path.exists(path):
            return  # sin el asset extraido, el check se salta
        with open(path, encoding="utf-8") as fh:
            data = decode_catalog(fh.read())
        if data.get("Version") != "1.0.0":
            raise AssertionError("asset bundled: version %r" % data.get("Version"))

    def _live_sample():
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "work", "live_config_raw.txt")
        if not os.path.exists(path):
            return
        with open(path, encoding="utf-8") as fh:
            data = decode_catalog(fh.read())
        if data.get("Version") != "1.0.115" or len(data.get("Servers") or []) != 117:
            raise AssertionError("muestra viva: version/servidores no coinciden")

    check("vector FIPS-197 AES-256 (backend %s)" % _AES_BACKEND, _fips_vector)
    check("derivacion de clave SHA-256(hex)", _derive_key_known)
    check("round-trip cifrado baybayin/AES", _roundtrip)
    check("asset bundled iusacel.png v1.0.0", _bundled_asset)
    check("muestra viva v1.0.115 / 117 servidores", _live_sample)

    failed = [c for c in checks if not c[1]]
    for name, ok, err in checks:
        print(("OK  " if ok else "FAIL") + " " + name + ((" - " + err) if err else ""))
    print("SELF-TEST: %d/%d OK" % (len(checks) - len(failed), len(checks)))
    return 0 if not failed else 1


# -------------------------------------------------------------------- CLI
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="M Light 3.1.55 - descarga y descifra el catalogo en vivo.")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--download", "--url", action="store_true",
                     help="descargar el catalogo en vivo (GET)")
    src.add_argument("--raw", metavar="ARCHIVO",
                     help="descifrar una respuesta guardada (texto baybayin)")
    ap.add_argument("--messages", action="store_true",
                    help="descargar tambien messages-config.json (mismo cifrado)")
    ap.add_argument("-o", "--out", metavar="ARCHIVO",
                    help="guardar el catalogo legible (JSON) en ARCHIVO")
    ap.add_argument("--fields", action="store_true",
                    help="mostrar cobertura de campos por servidor")
    ap.add_argument("--self-test", action="store_true",
                    help="pruebas internas (sin red)")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()

    if args.raw:
        with open(args.raw, encoding="utf-8") as fh:
            data = decode_catalog(fh.read())
    elif args.download:
        raw = fetch_live(CATALOG_URL)
        data = decode_catalog(raw)
    else:
        ap.error("usa --download para descargar en vivo o --raw ARCHIVO para una muestra")

    print(summarize(data))
    if args.fields:
        print(field_coverage(data))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        print("guardado en %s" % args.out)

    if args.messages:
        raw = fetch_live(MESSAGES_URL)
        msgs = decode_catalog(raw)
        print("messages-config: JsonVersion %s, %d mensajes, %d entradas Servers"
              % (msgs.get("JsonVersion", "?"),
                 len(msgs.get("Messages") or []),
                 len(msgs.get("Servers") or [])))
        if args.out:
            base, ext = os.path.splitext(args.out)
            mpath = base + "_messages" + ext
            with open(mpath, "w", encoding="utf-8") as fh:
                json.dump(msgs, fh, ensure_ascii=False, indent=2)
            print("guardado en %s" % mpath)
    return 0


if __name__ == "__main__":
    sys.exit(main())
