#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CHN TUNNEL LITE — catalogo para SP-DECODE
=========================================
App: CHN TUNNEL LITE (com.chntunnel.lite), version 1.4 (versionCode 14),
de ChotonNet IT Solution. Familia RENZ (misma que RA Tunnel, Zam VIP NET,
TRP Tunnel, Binke Volt, OSP Tunnel).

Catalogo en vivo (verificado 2026-11-14):
    GET https://choton.xyz/uploads/json/aa7b2249663bc6b01c68.json
    User-Agent: Dalvik/2.1.0 (Linux; U; Android 14; Redmi 14C Build/UP1A.231005.007)
    (Volley StringRequest, headers por defecto; la app NO manda UA propio,
    asi que cualquier UA Dalvik funciona. Un UA generico de Python puede
    ser bloqueado por Cloudflare en el host choton.xyz.)
    Respuesta: un cuerpo Base64 (una sola linea) = cifrado modo 0 del
    catalogo JSON completo.

Cifrado (todo en libovpn3.so, JNI RenzUtils.decrypt, 3 modos):
    Modo 0: Base64 -> AES-128-CBC (key = SHA-256(SEED)[:16], IV fijo)
            -> XXTEA (delta 0x85A92C1F, sumas negadas; ultima palabra =
            longitud del texto plano). Se usa para el cuerpo del catalogo
            y para la mayoria de los campos (Name, Subname, puertos, flag,
            CustomCert, Obfs, Info, TLSVersion, ProxySettings).
    Modo 1: Base64 -> Threefish-256 por bloques de 32 B
            (key = HKDF-SHA256(SALT, SEED, 32 B), tweak (i, 192*i))
            -> quitar NULs finales -> AES-128-CBC
            (key = HKDF-SHA256(SALT[:16], SEED, 16 B), mismo IV).
            Se usa para ServerIPHost, SNIHost y Payload.
    Modo 2: caracteres invisibles (ZWSP=0, ZWNJ=1; ZWJ se ignora)
            -> XXTEA (key = PBKDF2-HmacSHA256(SEED, SALT, 100000, 32)[:16])
            -> IV (16 B) + AES-256-CBC (key = PBKDF2 completa).
            Se usa para Username y Password.

    SEED / SALT / IV viven en .rodata de libovpn3.so (offsets 0x206430,
    0x206410 y 0x206450); los valores estan embebidos abajo porque el
    script debe funcionar sin el APK.

Formato de archivo propio: ver CHN_Tunnel_Lite_archivos.py
    (.js / .rj = mismo cifrado modo 0 del catalogo completo;
    chntunnellite://<modo 0> = una sola red en JSON).

Nube: no hay share por codigo ni registro de dispositivo. El unico
servicio en la nube es el catalogo por URL de arriba (mas Telegram
t.me/chntunnel y un canal de WhatsApp, solo contacto).

Uso:
    python3 CHN_Tunnel_Lite.py --url            # descarga y descifra en vivo
    python3 CHN_Tunnel_Lite.py --file BODY      # descifra un cuerpo local
    python3 CHN_Tunnel_Lite.py --url --output catalogo.json
    python3 CHN_Tunnel_Lite.py --self-test      # pruebas sin red

Solo biblioteca estandar de Python 3. Sin dependencias.
"""

import argparse
import base64
import hashlib
import hmac
import json
import struct
import sys
import urllib.request

# ---------------------------------------------------------------- constantes

CATALOG_URL = "https://choton.xyz/uploads/json/aa7b2249663bc6b01c68.json"
# Volley (Android) User-Agent por defecto; la app no manda uno propio.
USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 14; Redmi 14C Build/UP1A.231005.007)"

# Constantes de libovpn3.so (.rodata): SEED @0x206430 (32 B),
# SALT @0x206410 (32 B), IV @0x206450 (16 B).
SEED = bytes.fromhex(
    "dc4ca026b740c6b2d622fc3bbaae2af6d4f645cfd1be47b8e76c4f1f6034920f")
SALT = bytes.fromhex(
    "8b76b4a1fe8023d5aa9f0e567fec1f22192729f15848aac76459cfd3a48a5829")
AES_IV = bytes.fromhex("7bf969da3cdc44014a4cc779963465fd4e")

AES_KEY = hashlib.sha256(SEED).digest()[:16]          # modo 0
PBK = hashlib.pbkdf2_hmac("sha256", SEED, SALT, 100000, 32)  # modo 2


def hkdf_sha256(salt, ikm, info=b"", length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, n = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([n]), hashlib.sha256).digest()
        out += t
        n += 1
    return out[:length]


HKDF32 = hkdf_sha256(SALT, SEED, b"", 32)      # modo 1: Threefish
HKDF16 = hkdf_sha256(SALT[:16], SEED, b"", 16)  # modo 1: AES-128

_M32 = 0xFFFFFFFF
XXTEA_DELTA = 0x85A92C1F  # variante RENZ: sumas negadas

# --------------------------------------------------------------------- AES
# AES-128/192/256 puro stdlib (FIPS-197), cifrado y descifrado, modo CBC.
# La S-box se genera desde la especificacion, no se escribe a mano.


def _gf_mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ (0x1B if a & 0x80 else 0)) & 0xFF
        b >>= 1
    return r


def _gf_inv(a):
    if a == 0:
        return 0
    for x in range(1, 256):
        if _gf_mul(a, x) == 1:
            return x
    raise ValueError("sin inverso en GF(2^8)")


def _make_sbox():
    sbox = []
    for i in range(256):
        inv = _gf_inv(i)
        s = inv
        for shift in (1, 2, 3, 4):
            s ^= ((inv << shift) | (inv >> (8 - shift))) & 0xFF
        s ^= 0x63
        sbox.append(s & 0xFF)
    return sbox


_SBOX = _make_sbox()
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D]


def _key_expand(key):
    nk = len(key) // 4
    nr = nk + 6
    w = list(struct.unpack(">%dI" % nk, key))
    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            rot = ((temp << 8) | (temp >> 24)) & _M32
            sub = (_SBOX[(rot >> 24) & 0xFF] << 24) | \
                  (_SBOX[(rot >> 16) & 0xFF] << 16) | \
                  (_SBOX[(rot >> 8) & 0xFF] << 8) | _SBOX[rot & 0xFF]
            temp = sub ^ (_RCON[i // nk - 1] << 24)
        elif nk > 6 and i % nk == 4:
            temp = (_SBOX[(temp >> 24) & 0xFF] << 24) | \
                   (_SBOX[(temp >> 16) & 0xFF] << 16) | \
                   (_SBOX[(temp >> 8) & 0xFF] << 8) | _SBOX[temp & 0xFF]
        w.append((w[i - nk] ^ temp) & _M32)
    return w, nr


def _add_round_key(state, w, rnd):
    for c in range(4):
        word = w[rnd * 4 + c]
        for r in range(4):
            state[r][c] ^= (word >> (24 - 8 * r)) & 0xFF


def _sub_bytes(state, inv=False):
    box = _INV_SBOX if inv else _SBOX
    for r in range(4):
        for c in range(4):
            state[r][c] = box[state[r][c]]


def _shift_rows(state, inv=False):
    for r in range(1, 4):
        row = [state[r][c] for c in range(4)]
        shift = (4 - r) if inv else r
        row = row[shift:] + row[:shift]
        for c in range(4):
            state[r][c] = row[c]


def _mix_columns(state, inv=False):
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        if not inv:
            state[0][c] = _gf_mul(a[0], 2) ^ _gf_mul(a[1], 3) ^ a[2] ^ a[3]
            state[1][c] = a[0] ^ _gf_mul(a[1], 2) ^ _gf_mul(a[2], 3) ^ a[3]
            state[2][c] = a[0] ^ a[1] ^ _gf_mul(a[2], 2) ^ _gf_mul(a[3], 3)
            state[3][c] = _gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ _gf_mul(a[3], 2)
        else:
            state[0][c] = _gf_mul(a[0], 14) ^ _gf_mul(a[1], 11) ^ \
                          _gf_mul(a[2], 13) ^ _gf_mul(a[3], 9)
            state[1][c] = _gf_mul(a[0], 9) ^ _gf_mul(a[1], 14) ^ \
                          _gf_mul(a[2], 11) ^ _gf_mul(a[3], 13)
            state[2][c] = _gf_mul(a[0], 13) ^ _gf_mul(a[1], 9) ^ \
                          _gf_mul(a[2], 14) ^ _gf_mul(a[3], 11)
            state[3][c] = _gf_mul(a[0], 11) ^ _gf_mul(a[1], 13) ^ \
                          _gf_mul(a[2], 9) ^ _gf_mul(a[3], 14)


def _aes_block(key, block, encrypt=True):
    w, nr = _key_expand(key)
    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = block[i]
    if encrypt:
        _add_round_key(state, w, 0)
        for rnd in range(1, nr):
            _sub_bytes(state)
            _shift_rows(state)
            _mix_columns(state)
            _add_round_key(state, w, rnd)
        _sub_bytes(state)
        _shift_rows(state)
        _add_round_key(state, w, nr)
    else:
        _add_round_key(state, w, nr)
        for rnd in range(nr - 1, 0, -1):
            _shift_rows(state, inv=True)
            _sub_bytes(state, inv=True)
            _add_round_key(state, w, rnd)
            _mix_columns(state, inv=True)
        _shift_rows(state, inv=True)
        _sub_bytes(state, inv=True)
        _add_round_key(state, w, 0)
    out = bytearray(16)
    for i in range(16):
        out[i] = state[i % 4][i // 4]
    return bytes(out)


def _aes_cbc_decrypt(data, key, iv):
    """AES-CBC con unpadding PKCS#7. Devuelve b"" si la entrada es mala."""
    if not data or len(data) % 16 != 0:
        return b""
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 16):
        block = data[off:off + 16]
        out.extend(bytes(a ^ b for a, b in
                         zip(_aes_block(key, block, encrypt=False), prev)))
        prev = block
    if not out:
        return b""
    pad = out[-1]
    if pad < 1 or pad > 16 or out[-pad:] != bytes([pad]) * pad:
        return b""
    return bytes(out[:-pad])


def _aes_cbc_encrypt(data, key, iv):
    pad = 16 - (len(data) % 16)
    data = data + bytes([pad]) * pad
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[off:off + 16], prev))
        enc = _aes_block(key, block, encrypt=True)
        out.extend(enc)
        prev = enc
    return bytes(out)


# ------------------------------------------------------------------- XXTEA

def _prepare_xxtea_key(key16):
    """El codigo nativo trunca la clave en el primer byte NUL."""
    k = bytearray(key16[:16].ljust(16, b"\x00"))
    for i in range(15):
        if k[i] == 0:
            for j in range(i + 1, 16):
                k[j] = 0
            break
    return list(struct.unpack("<4I", bytes(k)))


def xxtea_decrypt_native(data, key16):
    """XXTEA variante RENZ: delta 0x85A92C1F con sumas negadas
    (el cifrado usa delta = -0x85A92C1F mod 2^32). Ultima palabra =
    longitud del texto plano. Devuelve (plaintext, longitud)."""
    n = (len(data) + 3) // 4
    if n < 2 or not data:
        return b"", 0
    buf = bytearray(n * 4)
    buf[:len(data)] = data
    v = list(struct.unpack("<%dI" % n, buf))
    k = _prepare_xxtea_key(key16)
    rounds = 6 + 52 // n
    total = (-(rounds * XXTEA_DELTA)) & _M32
    for _ in range(rounds):
        e = (total >> 2) & 3
        y = v[0]
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            mx = ((((z >> 5) ^ ((y << 2) & _M32)) +
                   ((y >> 3) ^ ((z << 4) & _M32))) ^
                  ((total ^ y) + (k[(p & 3) ^ e] ^ z))) & _M32
            v[p] = (v[p] - mx) & _M32
            y = v[p]
        z = v[n - 1]
        mx = ((((z >> 5) ^ ((y << 2) & _M32)) +
               ((y >> 3) ^ ((z << 4) & _M32))) ^
              ((total ^ y) + (k[e] ^ z))) & _M32
        v[0] = (v[0] - mx) & _M32
        total = (total + XXTEA_DELTA) & _M32
    total_bytes = n * 4
    last = v[-1]
    if total_bytes - 7 <= last <= total_bytes - 4:
        return struct.pack("<%dI" % n, *v)[:last], last
    return b"", 0


def xxtea_encrypt_native(data, key16):
    """Inversa de xxtea_decrypt_native (para generar .js/.rj y links)."""
    n = (len(data) + 3) // 4 + 1  # +1: la ultima palabra guarda la longitud
    if n < 2:
        return data
    buf = bytearray(n * 4)
    buf[:len(data)] = data
    v = list(struct.unpack("<%dI" % n, buf))
    v[-1] = len(data)
    k = _prepare_xxtea_key(key16)
    rounds = 6 + 52 // n
    denc = (-XXTEA_DELTA) & _M32
    total = 0
    for _ in range(rounds):
        total = (total + denc) & _M32
        e = (total >> 2) & 3
        z = v[n - 1]
        for p in range(n):
            y = v[(p + 1) % n]
            mx = ((((z >> 5) ^ ((y << 2) & _M32)) +
                   ((y >> 3) ^ ((z << 4) & _M32))) ^
                  ((total ^ y) + (k[(p & 3) ^ e] ^ z))) & _M32
            v[p] = (v[p] + mx) & _M32
            z = v[p]
    return struct.pack("<%dI" % n, *v)


# --------------------------------------------------------------- Threefish

_M64 = (1 << 64) - 1
_TF_C240 = 0x1BD11BDAA9FC1A22
_TF_ROT = [[14, 16], [52, 57], [23, 40], [5, 37],
           [25, 33], [46, 12], [58, 22], [32, 32]]
_TF_PERM = [0, 3, 2, 1]


def _rotl64(x, r):
    return ((x << r) | (x >> (64 - r))) & _M64


def _rotr64(x, r):
    return ((x >> r) | (x << (64 - r))) & _M64


def _threefish_subkeys(key32, tweak):
    k = list(struct.unpack("<4Q", key32))
    k.append(_TF_C240 ^ k[0] ^ k[1] ^ k[2] ^ k[3])
    t = [tweak[0], tweak[1], tweak[0] ^ tweak[1]]
    sk = []
    for s in range(19):
        sk.append([
            k[s % 5],
            (k[(s + 1) % 5] + t[s % 3]) & _M64,
            (k[(s + 2) % 5] + t[(s + 1) % 3]) & _M64,
            (k[(s + 3) % 5] + s) & _M64,
        ])
    return sk


def threefish256_decrypt_block(key32, tweak, block32):
    sk = _threefish_subkeys(key32, tweak)
    v = list(struct.unpack("<4Q", block32))
    for r in range(71, -1, -1):
        if (r + 1) % 4 == 0:
            s = (r + 1) // 4
            v = [(v[i] - sk[s][i]) & _M64 for i in range(4)]
        v = [v[_TF_PERM[i]] for i in range(4)]
        r0, r1 = _TF_ROT[r % 8]
        x1 = _rotr64((v[1] ^ v[0]) & _M64, r0)
        x0 = (v[0] - x1) & _M64
        x3 = _rotr64((v[3] ^ v[2]) & _M64, r1)
        x2 = (v[2] - x3) & _M64
        v = [x0, x1, x2, x3]
    v = [(v[i] - sk[0][i]) & _M64 for i in range(4)]
    return struct.pack("<4Q", *v)


def threefish256_encrypt_block(key32, tweak, block32):
    sk = _threefish_subkeys(key32, tweak)
    v = list(struct.unpack("<4Q", block32))
    v = [(v[i] + sk[0][i]) & _M64 for i in range(4)]
    for r in range(72):
        r0, r1 = _TF_ROT[r % 8]
        y0 = (v[0] + v[1]) & _M64
        y1 = _rotl64(v[1], r0) ^ y0
        y2 = (v[2] + v[3]) & _M64
        y3 = _rotl64(v[3], r1) ^ y2
        v = [y0, y1, y2, y3]
        v = [v[_TF_PERM[i]] for i in range(4)]
        if (r + 1) % 4 == 0:
            s = (r + 1) // 4
            v = [(v[i] + sk[s][i]) & _M64 for i in range(4)]
    return struct.pack("<4Q", *v)


# ------------------------------------------------------------ modos 0/1/2

def _b64_clean(text):
    if isinstance(text, bytes):
        text = text.decode("utf-8", "ignore")
    text = "".join(text.split())
    text += "=" * (-len(text) % 4)
    return text


def decrypt_mode0(value):
    """Modo 0: Base64 -> AES-128-CBC -> XXTEA. Devuelve bytes o None."""
    if not value or not isinstance(value, str):
        return None
    try:
        raw = base64.b64decode(_b64_clean(value), validate=False)
    except Exception:
        return None
    if len(raw) < 16 or len(raw) % 16 != 0:
        return None
    aes_plain = _aes_cbc_decrypt(raw, AES_KEY, AES_IV)
    if not aes_plain:
        return None
    plain, _ = xxtea_decrypt_native(aes_plain, AES_KEY)
    return plain if plain else None


def encrypt_mode0(plain_bytes):
    """Inversa de decrypt_mode0. Devuelve el texto Base64."""
    x = xxtea_encrypt_native(plain_bytes, AES_KEY)
    ct = _aes_cbc_encrypt(x, AES_KEY, AES_IV)
    return base64.b64encode(ct).decode("ascii")


def decrypt_mode1(value):
    """Modo 1: Base64 -> Threefish-256 (tweak (i, 192*i))
    -> quitar NULs -> AES-128-CBC. Devuelve bytes o None."""
    if not value or not isinstance(value, str):
        return None
    try:
        raw = base64.b64decode(_b64_clean(value), validate=False)
    except Exception:
        return None
    if len(raw) % 8 != 0:
        return None
    out = bytearray(raw)
    nblocks = (len(raw) + 31) // 32
    for i in range(nblocks):
        chunk = bytes(out[i * 32:(i + 1) * 32])
        if len(chunk) < 32:
            chunk = chunk + b"\x00" * (32 - len(chunk))
        dec = threefish256_decrypt_block(HKDF32, (i, 192 * i), chunk)
        out[i * 32:(i + 1) * 32] = dec[:len(out[i * 32:(i + 1) * 32])]
    stripped = bytes(out).rstrip(b"\x00")
    if not stripped or len(stripped) % 16 != 0:
        return None
    return _aes_cbc_decrypt(stripped, HKDF16, AES_IV)


def invisible_decode(s):
    """Caracteres invisibles -> bytes: ZWSP=0, ZWNJ=1, ZWJ se ignora;
    8 tokens -> 1 byte, intercambio de bits adyacentes, XOR 0x5A."""
    bits = []
    for ch in s:
        if ch == "\u200b":
            bits.append(0)
        elif ch == "\u200c":
            bits.append(1)
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        w = 0
        for b in bits[i:i + 8]:
            w = (w << 1) | b
        w = ((w << 1) & 0xAA) | ((w >> 1) & 0x55)
        out.append(w ^ 0x5A)
    return bytes(out)


def decrypt_mode2(value):
    """Modo 2: invisibles -> XXTEA (PBK[:16]) -> IV + AES-256-CBC (PBK).
    Devuelve bytes o None."""
    if not value or not isinstance(value, str):
        return None
    inv = invisible_decode(value)
    if not inv:
        return None
    x, _ = xxtea_decrypt_native(inv, PBK[:16])
    if not x or len(x) < 32:
        return None
    iv, ct = x[:16], x[16:]
    if len(ct) % 16 != 0:
        return None
    return _aes_cbc_decrypt(ct, PBK, iv)


def invisible_encode(data):
    """Inversa de invisible_decode: bytes -> caracteres invisibles
    (ZWSP=0, ZWNJ=1)."""
    out = []
    for byte in data:
        w = byte ^ 0x5A
        w = ((w << 1) & 0xAA) | ((w >> 1) & 0x55)
        for i in range(7, -1, -1):
            out.append("\u200b" if ((w >> i) & 1) == 0 else "\u200c")
    return "".join(out)


def encrypt_mode2(plain_bytes, iv=None):
    """Inversa de decrypt_mode2 (para generar enlaces y archivos).
    IV aleatorio si no se da uno."""
    import os
    if iv is None:
        iv = os.urandom(16)
    ct = _aes_cbc_encrypt(plain_bytes, PBK, iv)
    x = xxtea_encrypt_native(iv + ct, PBK[:16])
    return invisible_encode(x)


# Campos que usan modo 1 y modo 2 (el resto de campos de texto usan modo 0).
_MODE1_FIELDS = {"ServerIPHost", "SNIHost", "Payload"}
_MODE2_FIELDS = {"Username", "Password"}


def _looks_encrypted(value):
    """Un campo de texto plano (p. ej. "Version": "1.49") no es un
    cifrado: el cifrado mas corto posible (modo 0, 1 byte de texto)
    tiene 24 caracteres Base64. Los invisibles del modo 2 son mucho
    mas largos. Si no parece cifrado, se deja tal cual."""
    if len(value) < 20:
        return False
    if any(c in value for c in "\u200b\u200c\u200d"):
        return True
    return all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                  "0123456789+/=_-" for c in value)


def decrypt_field(field_name, value):
    """Descifra un campo del catalogo segun su nombre.
    Devuelve (texto_plano, modo) o (valor_original, None) si no cifra."""
    if value == "" or value is None:
        return value, None
    if not _looks_encrypted(value):
        return value, None
    if field_name in _MODE2_FIELDS:
        r = decrypt_mode2(value)
        return (r.decode("utf-8", "replace"), 2) if r is not None else (value, "FAIL")
    if field_name in _MODE1_FIELDS:
        r = decrypt_mode1(value)
        return (r.decode("utf-8", "replace"), 1) if r is not None else (value, "FAIL")
    r = decrypt_mode0(value)
    return (r.decode("utf-8", "replace"), 0) if r is not None else (value, "FAIL")


def decrypt_catalog_body(body_text):
    """Descifra el cuerpo del catalogo (modo 0) y devuelve el dict JSON."""
    plain = decrypt_mode0(body_text)
    if plain is None:
        raise ValueError("DECRYPT_FAILED: el cuerpo no abre con modo 0")
    return json.loads(plain.decode("utf-8"))


def readable_catalog(raw):
    """Devuelve una copia del catalogo con todos los campos descifrados.
    Los campos que no abren quedan con el valor cifrado y se cuentan."""
    import copy
    out = copy.deepcopy(raw)
    fails = []

    def walk(obj, path=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str):
                    plain, mode = decrypt_field(k, v)
                    if mode == "FAIL":
                        fails.append(path + k)
                    else:
                        obj[k] = plain
                else:
                    walk(v, path + k + ".")
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, path + "[%d]." % i)

    walk(out)
    return out, fails


# ------------------------------------------------------------------- fetch

def fetch_catalog(url=CATALOG_URL):
    """Descarga el cuerpo del catalogo exactamente como la app
    (GET, UA Dalvik, sin headers extra). Devuelve el texto crudo."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as resp:
        if resp.status != 200:
            raise RuntimeError("HTTP %d al descargar el catalogo" % resp.status)
        return resp.read().decode("utf-8", "ignore")


def summarize(raw, readable):
    servers = raw.get("Servers", [])
    networks = raw.get("Networks", [])
    with_payload = sum(1 for n in readable.get("Networks", [])
                       if n.get("Payload"))
    with_sni = sum(1 for n in readable.get("Networks", [])
                   if n.get("SNIHost"))
    return {
        "version": raw.get("Version"),
        "servers": len(servers),
        "networks": len(networks),
        "networks_with_payload": with_payload,
        "networks_with_sni": with_sni,
    }


# --------------------------------------------------------------------- CLI

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="CHN TUNNEL LITE: descarga y descifra el catalogo "
                    "(com.chntunnel.lite 1.4).")
    ap.add_argument("--url", nargs="?", const=CATALOG_URL, default=None,
                    help="descargar el catalogo en vivo "
                         "(URL opcional, por defecto la de la app)")
    ap.add_argument("--file", help="descifrar un cuerpo local (.js/.rj o "
                                   "texto Base64 del catalogo)")
    ap.add_argument("--output", help="guardar el catalogo legible (JSON)")
    ap.add_argument("--raw-output", help="guardar el catalogo crudo (JSON)")
    ap.add_argument("--summary", action="store_true",
                    help="mostrar solo el resumen")
    ap.add_argument("--self-test", action="store_true",
                    help="pruebas sin red y salir")
    args = ap.parse_args(argv)

    if args.self_test:
        return 0 if self_test() else 1

    if args.url:
        body = fetch_catalog(args.url)
    elif args.file:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            body = f.read()
    else:
        ap.error("usa --url, --file o --self-test")

    raw = decrypt_catalog_body(body)
    readable, fails = readable_catalog(raw)
    info = summarize(raw, readable)

    if args.summary:
        print("Version: %s" % info["version"])
        print("Servidores: %d" % info["servers"])
        print("Redes: %d (%d con Payload, %d con SNI)"
              % (info["networks"], info["networks_with_payload"],
                 info["networks_with_sni"]))
        if fails:
            print("Campos sin descifrar: %d (%s)"
                  % (len(fails), ", ".join(fails[:5])))
        return 0

    if args.raw_output:
        with open(args.raw_output, "w", encoding="utf-8") as f:
            json.dump(raw, f, ensure_ascii=False, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(readable, f, ensure_ascii=False, indent=2)
        print("Catalogo legible guardado en %s" % args.output)
    else:
        print(json.dumps(readable, ensure_ascii=False, indent=2))
    if fails:
        print("ADVERTENCIA: %d campos no se descifraron: %s"
              % (len(fails), ", ".join(fails[:10])), file=sys.stderr)
        return 2
    return 0


# --------------------------------------------------------------- self-test

def self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("OK   " if cond else "FAIL ") + name)
        if not cond:
            ok = False

    # 1. Vectores FIPS-197 del AES.
    check("AES-128 FIPS-197",
          _aes_block(bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
                     bytes.fromhex("00112233445566778899aabbccddeeff"),
                     encrypt=True).hex() ==
          "69c4e0d86a7b0430d8cdb78070b4c55a")
    check("AES-256 FIPS-197",
          _aes_block(bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                                   "101112131415161718191a1b1c1d1e1f"),
                     bytes.fromhex("00112233445566778899aabbccddeeff"),
                     encrypt=True).hex() ==
          "8ea2b7ca516745bfeafc49904b496089")
    check("AES-128 CBC round-trip",
          _aes_cbc_decrypt(_aes_cbc_encrypt(b"hola mundo 12345", AES_KEY,
                                            AES_IV), AES_KEY, AES_IV)
          == b"hola mundo 12345")

    # 2. XXTEA (variante RENZ) round-trip.
    import os
    blob = os.urandom(100)
    pt, _ = xxtea_decrypt_native(xxtea_encrypt_native(blob, AES_KEY), AES_KEY)
    check("XXTEA round-trip", pt == blob)

    # 3. Threefish-256 round-trip.
    key = os.urandom(32)
    blk = os.urandom(32)
    check("Threefish-256 round-trip",
          threefish256_decrypt_block(
              key, (3, 576),
              threefish256_encrypt_block(key, (3, 576), blk)) == blk)

    # 4. Vectores reales del catalogo en vivo 1.49 (2026-11-14).
    check("modo 0: Name -> SERVER-01",
          decrypt_mode0("TPu9XILJWfCU3zxm+FD+zrU/KGqXn8csY503fRUXMko=")
          == b"SERVER-01")
    check("modo 0: Subname -> OVPN",
          decrypt_mode0("KyBNPq0aE67Mud4shmljvQ==") == b"OVPN")
    check("modo 0: flag -> gb",
          decrypt_mode0("9XfsaseCQIpcZ4wCzjd90A==") == b"gb")
    check("modo 1: ServerIPHost -> choton1.choton.ggff.net",
          decrypt_mode1("3d47yLj+MkrDSedU097l8OxOAQjAHc6Um5EyYeNSDN8=")
          == b"choton1.choton.ggff.net")
    check("modo 1: SNIHost -> www.goggle.com",
          decrypt_mode1("r9Fy3jwd11usLeZzZ+VkHx0jN/lB8WCmbr0VzjUkB0M=")
          == b"www.goggle.com")
    check("modo 1: Payload multi-bloque",
          decrypt_mode1("o0H5wfOS+JTiR581iYViFkXmk+ml9yKM9ReLajd/UeOLFVPGFN"
                        "lIdtLxmq0b5q5UYPzQiNwwucDbqCBETqxirDA5TiX+vDwqztkz"
                        "B/Jz7roj/6ogugxgZDDK9l35Gr9w") ==
          b"GET wss://[rlb] HTTP/1.1[crlf]Host: [rlb] [crlf]Upgrade: "
          b"WebServer(Cloudflare)[crlf][crlf]")

    # 5. Modo 2 round-trip (cifrado invisible -> descifrado).
    check("modo 2 round-trip", decrypt_mode2(encrypt_mode2(b"chntunnel"))
          == b"chntunnel")

    # 6. Re-cifrado del cuerpo en vivo (si la muestra esta al lado).
    import os.path
    sample = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "catalog_sample.b64")
    if os.path.exists(sample):
        with open(sample, "r", encoding="utf-8") as f:
            body = f.read().strip()
        raw = decrypt_catalog_body(body)
        # el texto plano descifrado, re-cifrado, debe ser byte-identico
        # al cuerpo original (verificado contra el cuerpo en vivo):
        plain = decrypt_mode0(body)
        check("re-cifrado del cuerpo en vivo == original",
              encrypt_mode0(plain) == body)
        check("catalogo de muestra: Version 1.49, 5 servidores, 44 redes",
              raw.get("Version") == "1.49" and
              len(raw.get("Servers", [])) == 5 and
              len(raw.get("Networks", [])) == 44)
        readable, fails = readable_catalog(raw)
        check("catalogo de muestra: 0 campos sin descifrar", not fails)
    else:
        print("SKIP re-cifrado del cuerpo (no esta catalog_sample.b64)")

    print("SELF-TEST: %s" % ("TODO OK" if ok else "FALLOS"))
    return ok


if __name__ == "__main__":
    sys.exit(main())
