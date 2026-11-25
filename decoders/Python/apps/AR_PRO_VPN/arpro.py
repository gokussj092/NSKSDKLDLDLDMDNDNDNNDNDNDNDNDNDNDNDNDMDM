#!/usr/bin/env python3
"""Decodificador AR PRO VPN 2.0 para SP-DECODE (solo biblioteca estandar).

App: AR PRO VPN, paquete ``noob.arpro.vpn``, versionName 2.0, versionCode 2
(minSdk 24, targetSdk 36). Fork de v2rayNG ("NoobDev Build").

METODO 2.0 (verificado contra el APK 2.0 y en vivo 2026-11-25)
------------------------------------------------------------
La criptografia nativa ya NO vive en libwg-pro.so (eliminada en 2.0);
vive en libovpn3.so, registrada dinamicamente en JNI_OnLoad como los
metodos nativos ``a``..``j`` de ``com.noobdev.vpn.utils.preference.NoobCrypt``.
Los modos (parametro ``int`` de NoobCrypt.a/b, via TR0.p/TR0.s/Te.m/Te.l):

    modo 0: AES-256-GCM     (nonce = primeros 12 B, tag = ultimos 16 B)
    modo 1: AES-256-CBC     (IV = primeros 16 B, PKCS#7)
    modo 2: ChaCha20        (IV = primeros 16 B: contador LE32 + nonce 12 B)
    modo 3: ChaCha20-Poly1305 (nonce = primeros 12 B, tag = ultimos 16 B)
    modo 4: AES-256-CBC con IV determinista = SHA-256(plaintext)[:16]
            (solo cambia el cifrado; al descifrar es igual que el modo 1)
    modo 5: AES-256-XTS     (tweak = primeros 16 B; resto = ciphertext,
                             con robo de texto (CTS) si no es multiplo de 16)

Las claves de 32 y 64 bytes son constantes de formato derivadas de
libovpn3.so (raw XOR mascaras, y ROL6 por byte para la de 64 B); se
incluyen como hexadecimales porque sin ellas no se puede descifrar nada.

Catalogo 2.0 (VERIFIED_REAL 2026-11-25):
    GET https://jezvpn.xyz/api/app?json=20ec37d9ba9316e8a793
    Sin cabeceras propias, sin autenticacion, sin User-Agent propio.
    Cuerpo = una linea Base64 -> AES-256-XTS (modo 5) -> JSON UTF-8.
    Version del catalogo 3.4.8, versioncode "0", 27 servidores, 394 tweaks.
    Campos: servidores y nivel superior en modo 0 (GCM); tweaks en modo 1
    (CBC). El resto de valores en texto plano se dejan como estan.
    Endpoint de comprobacion de actualizacion (NO es el catalogo):
    GET https://jezvpn.xyz/api/app?json=d154dff4627f2474cf87
    -> JSON plano con versiones de varias apps.

    UUIDs V2Ray ofuscados (``NOOB_`` + Base64): el UUID GCM-descifrado
    de 9 servidores viene como ``NOOB_`` + Base64 (URL-codificado). La
    de-ofuscacion vive en el nucleo Xray personalizado (NoobXray,
    libgojni.so, ``AndroidLibXrayLite.resolveInternalTags``):
    quitar ``NOOB_``, URL-decodificar, Base64-decodificar, restar a
    cada byte ``((i + TABLA[i % 10]) % 7)`` con TABLA = ``qgSEvZmfmb``
    y dar la vuelta a la cadena. Verificado: 5 UUID estandar validos,
    3 servidores GCP comparten el mismo user-id VLESS que aparece en
    claro en el ``v2rayjson`` de un tweak, y el valor corto coincide
    con el Path/host del propio servidor. El usuario y la contrasena
    de Servers[20] descifran con GCM (modo 0) a un token de 32 hex
    (la etiqueta GCM lo verifica); la sesion anterior los marco por
    error como sin resolver.

Archivos .ar 2.0 (VERIFIED_SYNTHETIC; falta una muestra real exportada):
    Contenido = Base64(IV aleatorio 16 B + AES-256-CBC(modo 1, key32,
    PKCS#7) de UTF-8("AR PRO VPN" + JSON_perfil)).
    La importacion (ARTunnelMain.H) hace Te.l(1, contenido) -> quita el
    prefijo "AR PRO VPN" -> JSONObject; despues valida ExpireDate,
    RootBlock, DeviceID, PSInstall y contrasena (isPassON/MyPass).
    El perfil JSON tiene los mismos 28 campos que en 1.0. Sin .sks.

Textos: sin esquema propio. La app maneja vmess://, vless://, ss://,
trojan:// y wireguard:// estandar, ya cubiertos por el nucleo de
SP-DECODE. ``AR://`` no es un enlace de importacion.

Metodo 1.0 (legacy, endpoint aun vivo): ver AR_PRO_VPN.py y
AR_PRO_VPN_archivos.py en este mismo directorio (XXTEA + Jdecrypt).
El token 1.0 (0b791e09b974f136ed62) devolvio en vivo el catalogo
version 19.2.8 con 9 servidores y 434 tweaks.

Uso:
    python arpro.py --url [-o catalogo.json]
    python arpro.py respuesta_guardada.bin [-o catalogo.json]
    python arpro.py --ar perfil.ar
    python arpro.py --self-test

Solo biblioteca estandar (Python 3.10+). El AES, GCM, XTS y
ChaCha20-Poly1305 son implementaciones puras en Python incluidas aqui.

NOTA: este script contiene las claves de formato del decodificador y
las URLs de los endpoints de la app. NO contiene credenciales de
servidores, usuarios, contrasenas ni tokens de ningun usuario.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import secrets
import sys
import urllib.request
from functools import lru_cache

__version__ = "2.0.1"

MAX_BYTES = 64 * 1024 * 1024

# Endpoints (URLs fijas de la app; el JSON resultado no las incluye).
CATALOG_URL = "https://jezvpn.xyz/api/app?json=20ec37d9ba9316e8a793"
UPDATE_CHECK_URL = "https://jezvpn.xyz/api/app?json=d154dff4627f2474cf87"
LEGACY_CATALOG_URL = "https://jezvpn.xyz/api/app?json=0b791e09b974f136ed62"

# Claves de formato (derivadas de libovpn3.so; ver ANALISIS.md).
KEY32 = bytes.fromhex(
    "98c4d1e8636cfd85e5d4d9e479704edf0563d44117efaa33c631241704e7dd60"
)
KEY64 = bytes.fromhex(
    "071823cbc90de8733ee21ffa9f563c8b0cd0d948b08b24d8ba987ad7c3f2d601d"
    "6bfc77684b8931a32df907e9b7b146752d211197ca8ee0da0d14b2b0ea82fd8"
)

AR_PREFIX = "AR PRO VPN"

# Tabla de de-ofuscacion de los UUID V2Ray (libgojni.so,
# AndroidLibXrayLite.resolveInternalTags: tabla en .rodata 0x3e52b3).
NOOB_TABLE = b"qgSEvZmfmb"
NOOB_PREFIX = "NOOB_"


def deobfuscate_noob_uuid(value):
    """De-ofusca un UUID V2Ray ``NOOB_`` + Base64 (URL-codificado).

    Esquema del nucleo NoobXray (verificado por desensamblado de
    libgojni.so, funcion resolveInternalTags, y por comprobacion
    cruzada con el catalogo vivo):
      1. quitar el prefijo ``NOOB_`` (memequal de los primeros 5 B);
      2. URL-decodificar y Base64-decodificar (encoding/base64);
      3. a cada byte ``b`` en la posicion ``i`` restar
         ``((i + TABLA[i % 10]) % 7)`` con TABLA = ``qgSEvZmfmb``;
      4. dar la vuelta a la cadena (la funcion invierte el []rune).
    Devuelve el texto plano, o None si el valor no es un NOOB_ valido.
    El resultado puede ser un UUID estandar, un user-id VLESS
    (los servidores GCP comparten uno que tambien aparece en claro
    en un tweak) o un identificador corto: se devuelve tal cual.
    """
    if not isinstance(value, str) or not value.startswith(NOOB_PREFIX):
        return None
    try:
        import urllib.parse
        raw = base64.b64decode(urllib.parse.unquote(value[len(NOOB_PREFIX):]))
        if not raw:
            return None
        plain = bytes(
            (b - ((i + NOOB_TABLE[i % 10]) % 7)) % 256
            for i, b in enumerate(raw)
        )
    except (binascii.Error, ValueError):
        return None
    try:
        return plain[::-1].decode("utf-8")
    except UnicodeDecodeError:
        return None


def obfuscate_noob_uuid(plain):
    """Inversa de deobfuscate_noob_uuid (solo para el self-test)."""
    raw = plain[::-1].encode("utf-8")
    enc = bytes(
        (b + ((i + NOOB_TABLE[i % 10]) % 7)) % 256
        for i, b in enumerate(raw)
    )
    return NOOB_PREFIX + base64.b64encode(enc).decode("ascii")


# Campos que nunca se incluyen en el catalog.json redactado.
REDACTED_SERVER_FIELDS = {
    "Username", "Password", "PrivateKey", "OpenVPNCertificate",
    "ServerIPHost", "ServerHTTPHost",
}
REDACTED_TOP_FIELDS = {
    "DefUpdateURL", "updater", "Banner_ID", "AppOpenAd",
    "Interstitial_ID", "RewardAd_ID", "RewardInter_ID", "cardLink",
}
UUID_RE = None  # se compila perezosamente (evita importar re al inicio)


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


@lru_cache(maxsize=8)
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
    return tuple(tuple(word) for word in w), nr


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


def _pkcs7_pad(data):
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data):
    if not data:
        raise ValueError("empty data")
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad PKCS#7 padding")
    return data[:-pad]


def _aes_cbc_encrypt(key, iv, data):
    data = _pkcs7_pad(data)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = _aes_encrypt_block(key, blk)
        out += prev
    return bytes(out)


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


# ---------------------------------------------------------------- GCM

def _gf128_mul(x, y):
    """Multiplicacion en GF(2^128) con el polinomio de GCM (x^128+x^7+x^2+x+1)."""
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ 0xE1000000000000000000000000000000
        else:
            v >>= 1
    return z


def _ghash(h, data):
    """GHASH sin AAD: bloques de datos y, al final, el bloque de
    longitudes [len(AAD)=0][len(C) en bits], tambien multiplicado por H."""
    y = 0
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        blk = blk + b"\x00" * (16 - len(blk))
        y = _gf128_mul(y ^ int.from_bytes(blk, "big"), h)
    y = _gf128_mul(y ^ (len(data) * 8), h)
    return y


def _gcm_crypt(key, nonce, data, tag=None, encrypt=True):
    """AES-256-GCM (modo 0). Sin AAD (la app no usa AAD).

    Layout de la app: nonce = primeros 12 B, tag = ultimos 16 B.
    """
    if len(nonce) != 12:
        raise ValueError("GCM nonce must be 12 bytes")
    h = int.from_bytes(_aes_encrypt_block(key, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    # Contador CTR: J0+1, J0+2, ...
    out = bytearray()
    counter = int.from_bytes(j0, "big")
    for i in range(0, len(data), 16):
        counter += 1
        keystream = _aes_encrypt_block(key, counter.to_bytes(16, "big"))
        blk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(blk, keystream))
    ct = bytes(out) if encrypt else data
    # Tag sobre el ciphertext (GHASH ya incluye el bloque de longitudes).
    s = _ghash(h, ct)
    tag_calc = (s ^ int.from_bytes(_aes_encrypt_block(key, j0), "big")).to_bytes(16, "big")
    if encrypt:
        return bytes(out), tag_calc
    if tag is None or tag != tag_calc:
        raise ValueError("GCM tag verification failed")
    return bytes(out)


# ---------------------------------------------------------------- XTS (con robo de texto)

def _gf128_mul_x(tweak):
    """Multiplica el tweak por x en GF(2^128) (polinomio x^128+x^7+x^2+x+1).
    En XTS el tweak es little-endian: el byte 0 es el menos significativo."""
    t = bytearray(tweak)
    carry = (t[15] >> 7) & 1
    for i in range(15, 0, -1):
        t[i] = ((t[i] << 1) & 0xff) | (t[i - 1] >> 7)
    t[0] = ((t[0] << 1) & 0xff) ^ (0x87 if carry else 0)
    return bytes(t)


def _xts_crypt(key64, tweak, data, encrypt=True):
    """AES-256-XTS (modo 5) con robo de texto (CTS) para el ultimo bloque
    parcial, como hace OpenSSL EVP (el que usa la app).

    key64 = clave1 (32 B) || clave2 (32 B); tweak = primeros 16 B.
    El tweak avanza un paso por bloque (multiplicacion por x); se lleva
    de forma incremental, no recomputado desde cero por bloque.
    """
    if len(key64) != 64:
        raise ValueError("XTS key must be 64 bytes")
    if len(data) < 16:
        raise ValueError("XTS data must be at least 16 bytes")
    k1, k2 = key64[:32], key64[32:]
    nblocks = len(data) // 16
    partial = len(data) % 16
    # Tweaks incrementales: t[i+1] = t[i] * x.
    tweaks = []
    t = _aes_encrypt_block(k2, tweak)
    for _ in range(nblocks + 1):
        tweaks.append(t)
        t = _gf128_mul_x(t)

    def crypt_block(blk, tw, enc):
        x = bytes(a ^ b for a, b in zip(blk, tw))
        y = _aes_encrypt_block(k1, x) if enc else _aes_decrypt_block(k1, x)
        return bytes(a ^ b for a, b in zip(y, tw))

    if partial == 0:
        out = bytearray()
        for i in range(nblocks):
            out += crypt_block(data[i * 16:(i + 1) * 16], tweaks[i], encrypt)
        return bytes(out)
    # CTS: todos los bloques salvo los dos ultimos, normales.
    out = bytearray()
    for i in range(nblocks - 1):
        out += crypt_block(data[i * 16:(i + 1) * 16], tweaks[i], encrypt)
    last_full = data[(nblocks - 1) * 16:nblocks * 16]
    last_part = data[nblocks * 16:]
    t_prev = tweaks[nblocks - 1]
    t_last = tweaks[nblocks]
    if encrypt:
        cc = crypt_block(last_full, t_prev, True)
        tail = last_part + cc[partial:]
        out += crypt_block(tail, t_last, True)
        out += cc[:partial]
    else:
        pp = crypt_block(last_full, t_last, False)
        cc = last_part + pp[partial:]
        out += crypt_block(cc, t_prev, False)
        out += pp[:partial]
    return bytes(out)


# ---------------------------------------------------------------- ChaCha20 / Poly1305

def _rotl32(v, n):
    return ((v << n) & 0xffffffff) | (v >> (32 - n))


def _chacha20_block(key, counter, nonce):
    """Un bloque ChaCha20 (RFC 8439): key 32 B, counter 32 bits, nonce 12 B."""
    consts = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
    kw = [int.from_bytes(key[i:i + 4], "little") for i in range(0, 32, 4)]
    nw = [int.from_bytes(nonce[i:i + 4], "little") for i in range(0, 12, 4)]
    st = list(consts) + kw + [counter] + nw

    def qr(s, a, b, c, d):
        s[a] = (s[a] + s[b]) & 0xffffffff; s[d] ^= s[a]; s[d] = _rotl32(s[d], 16)
        s[c] = (s[c] + s[d]) & 0xffffffff; s[b] ^= s[c]; s[b] = _rotl32(s[b], 12)
        s[a] = (s[a] + s[b]) & 0xffffffff; s[d] ^= s[a]; s[d] = _rotl32(s[d], 8)
        s[c] = (s[c] + s[d]) & 0xffffffff; s[b] ^= s[c]; s[b] = _rotl32(s[b], 7)

    x = list(st)
    for _ in range(10):
        qr(x, 0, 4, 8, 12); qr(x, 1, 5, 9, 13); qr(x, 2, 6, 10, 14); qr(x, 3, 7, 11, 15)
        qr(x, 0, 5, 10, 15); qr(x, 1, 6, 11, 12); qr(x, 2, 7, 8, 13); qr(x, 3, 4, 9, 14)
    return b"".join(((x[i] + st[i]) & 0xffffffff).to_bytes(4, "little") for i in range(16))


def _chacha20_xor(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = _chacha20_block(key, counter, nonce)
        counter = (counter + 1) & 0xffffffff
        blk = data[i:i + 64]
        out += bytes(a ^ b for a, b in zip(blk, ks))
    return bytes(out)


def _poly1305(msg, key):
    """Poly1305 (RFC 8439) con clave de un solo uso de 32 B."""
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        blk = msg[i:i + 16]
        n = int.from_bytes(blk, "little") + (1 << (8 * len(blk)))
        acc = ((acc + n) * r) % p
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


def _chacha20_poly1305_crypt(key, nonce, data, tag=None, encrypt=True, aad=b""):
    """ChaCha20-Poly1305 AEAD (modo 3). La app usa AAD vacio; el
    parametro ``aad`` existe para poder verificar el vector RFC 8439.

    Layout de la app: nonce = primeros 12 B, tag = ultimos 16 B.
    """
    if len(nonce) != 12:
        raise ValueError("ChaCha20-Poly1305 nonce must be 12 bytes")
    otk = _chacha20_block(key, 0, nonce)[:32]
    if encrypt:
        ct = _chacha20_xor(key, 1, nonce, data)
    else:
        ct = data
    mac_data = aad + b"\x00" * ((16 - len(aad) % 16) % 16)
    mac_data += ct + b"\x00" * ((16 - len(ct) % 16) % 16)
    mac_data += len(aad).to_bytes(8, "little") + len(ct).to_bytes(8, "little")
    tag_calc = _poly1305(mac_data, otk)
    if encrypt:
        return ct, tag_calc
    if tag is None or tag != tag_calc:
        raise ValueError("ChaCha20-Poly1305 tag verification failed")
    return _chacha20_xor(key, 1, nonce, ct)


# ---------------------------------------------------------------- Modos nativos (NoobCrypt.a/b)

def mode_decrypt(mode, blob):
    """Descifra un blob segun el modo nativo. El blob incluye el prefijo
    (nonce/IV/tweak) y, en los AEAD, el tag final. Devuelve el plaintext."""
    if mode == 0:  # AES-256-GCM
        if len(blob) < 12 + 16:
            raise ValueError("GCM blob too short")
        return _gcm_crypt(KEY32, blob[:12], blob[12:-16], tag=blob[-16:], encrypt=False)
    if mode in (1, 4):  # AES-256-CBC (modo 4 descifra igual que el 1)
        if len(blob) < 32 or len(blob) % 16:
            raise ValueError("CBC blob too short or not a multiple of 16")
        return _pkcs7_unpad(_aes_cbc_decrypt(KEY32, blob[:16], blob[16:]))
    if mode == 2:  # ChaCha20 (IV 16 B: contador LE32 + nonce 12 B)
        if len(blob) < 16:
            raise ValueError("ChaCha20 blob too short")
        counter = int.from_bytes(blob[:4], "little")
        return _chacha20_xor(KEY32, counter, blob[4:16], blob[16:])
    if mode == 3:  # ChaCha20-Poly1305
        if len(blob) < 12 + 16:
            raise ValueError("ChaCha20-Poly1305 blob too short")
        return _chacha20_poly1305_crypt(KEY32, blob[:12], blob[12:-16], tag=blob[-16:], encrypt=False)
    if mode == 5:  # AES-256-XTS
        if len(blob) < 32:
            raise ValueError("XTS blob too short")
        return _xts_crypt(KEY64, blob[:16], blob[16:], encrypt=False)
    raise ValueError("unknown mode %r" % (mode,))


def mode_encrypt(mode, plaintext, iv=None):
    """Cifra segun el modo nativo. Devuelve el blob con su prefijo (y tag
    si es AEAD). Solo se usa para el self-test y para codificar .ar."""
    if mode == 0:
        nonce = iv if iv is not None else secrets.token_bytes(12)
        ct, tag = _gcm_crypt(KEY32, nonce, plaintext, encrypt=True)
        return nonce + ct + tag
    if mode == 1:
        ivb = iv if iv is not None else secrets.token_bytes(16)
        return ivb + _aes_cbc_encrypt(KEY32, ivb, plaintext)
    if mode == 4:  # IV determinista = SHA-256(plaintext)[:16]
        ivb = hashlib.sha256(plaintext).digest()[:16]
        return ivb + _aes_cbc_encrypt(KEY32, ivb, plaintext)
    if mode == 2:
        ivb = iv if iv is not None else secrets.token_bytes(16)
        counter = int.from_bytes(ivb[:4], "little")
        return ivb + _chacha20_xor(KEY32, counter, ivb[4:16], plaintext)
    if mode == 3:
        nonce = iv if iv is not None else secrets.token_bytes(12)
        ct, tag = _chacha20_poly1305_crypt(KEY32, nonce, plaintext, encrypt=True)
        return nonce + ct + tag
    if mode == 5:
        tweak = iv if iv is not None else secrets.token_bytes(16)
        return tweak + _xts_crypt(KEY64, tweak, plaintext, encrypt=True)
    raise ValueError("unknown mode %r" % (mode,))


# ---------------------------------------------------------------- Catalogo

def _b64decode(value):
    """Base64 estandar tolerante con espacios/saltos (el cuerpo del
    catalogo es una sola linea, pero los campos pueden venir con
    espacios)."""
    if isinstance(value, bytes):
        value = value.decode("ascii", "ignore")
    cleaned = "".join(value.split())
    return base64.b64decode(cleaned, validate=False)


def _looks_like_plaintext(text):
    """True si el texto descifrado parece texto legible (incluye emoji)."""
    if not text:
        return False
    for ch in text:
        o = ord(ch)
        if o in (0x09, 0x0a, 0x0d):
            continue
        if o < 0x20 or o == 0x7f:
            return False
    return True


def try_decrypt_field(value, modes):
    """Intenta descifrar un valor de texto con los modos dados, en orden.
    Devuelve (plaintext, modo) o (None, None) si no es un cifrado valido
    (en ese caso el valor se deja en texto plano)."""
    if not isinstance(value, str) or not value:
        return None, None
    try:
        raw = _b64decode(value)
    except (binascii.Error, ValueError):
        return None, None
    if len(raw) < 28:
        return None, None
    for mode in modes:
        try:
            plain = mode_decrypt(mode, raw)
        except Exception:
            continue
        try:
            text = plain.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if _looks_like_plaintext(text):
            return text, mode
    return None, None


def decrypt_catalog_body(data):
    """Descifra el cuerpo crudo del catalogo 2.0 (Base64 -> XTS modo 5)
    y devuelve el JSON como dict. ``data`` puede ser bytes o str."""
    if isinstance(data, bytes):
        text = data.decode("ascii", "ignore")
    else:
        text = data
    text = "".join(text.split())
    if len(text) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El cuerpo supera el limite de tamano.")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise DecodeError("FORMAT_ERROR", "El cuerpo no es Base64 estandar.")
    try:
        plain = mode_decrypt(5, raw)
    except Exception as exc:
        raise DecodeError("DECRYPT_ERROR", "XTS (modo 5) fallo: %s" % exc)
    try:
        return json.loads(plain.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError("JSON_ERROR", "El cuerpo descifrado no es JSON: %s" % exc)


def decrypt_catalog_fields(doc):
    """Descifra los campos de texto del catalogo: servidores y nivel
    superior con modo 0 (GCM), tweaks con modo 1 (CBC). Devuelve
    (doc_descifrado, estadisticas). Los valores que no descifran quedan
    como estan (texto plano o cifrado sin resolver)."""
    stats = {"gcm": 0, "cbc": 0, "chacha_poly": 0, "plain": 0,
             "unresolved": 0, "noob_uuid": 0}

    def dec_value(value, modes):
        text, mode = try_decrypt_field(value, modes)
        if text is None:
            stats["plain"] += 1
            return value
        if mode == 0:
            stats["gcm"] += 1
        elif mode == 1:
            stats["cbc"] += 1
        elif mode == 3:
            stats["chacha_poly"] += 1
        return text

    def dec_obj(obj, modes):
        if isinstance(obj, dict):
            return {k: dec_obj(v, modes) for k, v in obj.items()}
        if isinstance(obj, list):
            return [dec_obj(v, modes) for v in obj]
        if isinstance(obj, str):
            return dec_value(obj, modes)
        stats["plain"] += 1
        return obj

    out = {}
    for key, value in doc.items():
        if key == "Tweaks":
            out[key] = dec_obj(value, (1, 0, 3))
        else:
            out[key] = dec_obj(value, (0, 1, 3))
    # UUIDs V2Ray ofuscados: tras el GCM quedan como NOOB_+Base64; la
    # de-ofuscacion vive en el nucleo NoobXray (ver
    # deobfuscate_noob_uuid). Si un valor no de-ofusca, se deja como
    # esta y el contador "sin resolver" lo delata.
    for server in out.get("Servers") or []:
        v2ray = server.get("V2ray") if isinstance(server, dict) else None
        if isinstance(v2ray, dict):
            uuid = v2ray.get("UUID")
            if isinstance(uuid, str) and uuid.startswith(NOOB_PREFIX):
                plain = deobfuscate_noob_uuid(uuid)
                if plain is not None:
                    v2ray["UUID"] = plain
                    stats["noob_uuid"] += 1
    # Campos que quedaron como Base64 largo sin descifrar (el conteo es
    # heuristico: tambien marca texto plano largo como payloads, SNI,
    # hosts y enlaces vless; ver ANALISIS.md para la clasificacion).
    def count_unresolved(obj):
        if isinstance(obj, dict):
            for v in obj.values():
                count_unresolved(v)
        elif isinstance(obj, list):
            for v in obj:
                count_unresolved(v)
        elif isinstance(obj, str) and len(obj) >= 28:
            try:
                raw = _b64decode(obj)
            except Exception:
                return
            if len(raw) >= 28:
                stats["unresolved"] += 1
    count_unresolved(out)
    return out, stats


def decode_catalog(data):
    """Cuerpo crudo -> catalogo completo descifrado (con credenciales).
    Para el JSON que se entrega, usar redact_catalog() encima."""
    doc = decrypt_catalog_body(data)
    return decrypt_catalog_fields(doc)


def redact_catalog(doc):
    """Catalogo descifrado -> version redactada para entregar: sin
    credenciales de servidores, sin claves, sin APIs de descarga y con
    los UUID de los enlaces v2rayjson enmascarados."""
    import re
    uuid_re = re.compile(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    )

    def redact_server(server):
        out = {}
        for key, value in server.items():
            if key in REDACTED_SERVER_FIELDS:
                continue
            if key == "SlowDNS" and isinstance(value, dict):
                out[key] = {k: v for k, v in value.items() if k != "DNSTTKey"}
                continue
            if key == "V2ray" and isinstance(value, dict):
                # El UUID es una credencial (ademas va ofuscado NOOB_+Base64).
                out[key] = {k: ("[redacted-uuid]" if k == "UUID" else v)
                            for k, v in value.items()}
                continue
            out[key] = value
        return out

    def redact_tweak(tweak):
        out = {}
        for key, value in tweak.items():
            if key == "v2rayjson" and isinstance(value, str):
                # Enmascara el userinfo de cualquier enlace (UUID u otro
                # identificador de usuario), no solo los UUID con formato.
                masked = uuid_re.sub("[redacted-uuid]", value)
                masked = re.sub(r"(://)[^/@]+@", r"\1[redacted-user]@", masked)
                out[key] = masked
                continue
            out[key] = value
        return out

    out = {}
    for key, value in doc.items():
        if key in REDACTED_TOP_FIELDS:
            continue
        if key == "Servers":
            out[key] = [redact_server(s) for s in value]
        elif key == "Tweaks":
            out[key] = [redact_tweak(t) for t in value]
        else:
            out[key] = value
    return out


# ---------------------------------------------------------------- Archivos .ar

def encode_ar(profile):
    """Codifica un perfil .ar 2.0: Base64(IV + AES-256-CBC(modo 1) de
    UTF-8("AR PRO VPN" + JSON)). El IV es aleatorio (como en la app)."""
    payload = (AR_PREFIX + json.dumps(profile, ensure_ascii=False)).encode("utf-8")
    return base64.b64encode(mode_encrypt(1, payload)).decode("ascii")


def decode_ar(data):
    """Decodifica un .ar 2.0. Acepta el contenido del archivo como str o
    bytes (con o sin saltos de linea). Devuelve el perfil como dict."""
    if isinstance(data, bytes):
        text = data.decode("utf-8", "ignore")
    else:
        text = data
    text = "".join(text.split())
    if len(text) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el limite de tamano.")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise DecodeError("FORMAT_ERROR", "El .ar no es Base64 estandar.")
    try:
        plain = mode_decrypt(1, raw)
    except Exception as exc:
        raise DecodeError("DECRYPT_ERROR", "CBC (modo 1) fallo: %s" % exc)
    try:
        text = plain.decode("utf-8")
    except UnicodeDecodeError:
        raise DecodeError("FORMAT_ERROR", "El .ar descifrado no es UTF-8.")
    if not text.startswith(AR_PREFIX):
        raise DecodeError(
            "FORMAT_ERROR",
            "El .ar no pertenece a esta app (falta el prefijo %r)." % AR_PREFIX,
        )
    try:
        return json.loads(text[len(AR_PREFIX):])
    except json.JSONDecodeError as exc:
        raise DecodeError("JSON_ERROR", "El perfil descifrado no es JSON: %s" % exc)


# ---------------------------------------------------------------- Descarga (peticion exacta de la app)

def _plain_get(url, timeout=25):
    """GET plano como lo hace la app: HttpURLConnection, sin cabeceras
    propias, sin autenticacion, sin User-Agent propio."""
    req = urllib.request.Request(url, method="GET")
    # Sin headers: urllib anade su User-Agent por defecto; la app no lo
    # hace, pero el servidor devuelve el mismo cuerpo con cualquier UA
    # (verificado en vivo con 4 User-Agents distintos).
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise DecodeError("HTTP_ERROR", "HTTP %s" % resp.status)
        return resp.read()


def fetch_catalog(url=CATALOG_URL):
    """Descarga el catalogo 2.0 en vivo y lo descifra. Devuelve
    (catalogo_descifrado, estadisticas, cuerpo_crudo)."""
    body = _plain_get(url)
    doc, stats = decode_catalog(body)
    return doc, stats, body


# ---------------------------------------------------------------- CLI

def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


def _write(path, data):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(data)


def _self_test():
    """Round-trips y vectores conocidos. No usa red ni archivos."""
    ok = []

    # AES-256, vector FIPS-197.
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    assert _aes_encrypt_block(key, pt) == ct, "AES-256 encrypt"
    assert _aes_decrypt_block(key, ct) == pt, "AES-256 decrypt"
    ok.append("AES-256 FIPS-197")

    # AES-256-GCM, vector NIST (key 0, IV 0, pt 16 ceros).
    gkey = b"\x00" * 32
    giv = b"\x00" * 12
    gpt = b"\x00" * 16
    gct, gtag = _gcm_crypt(gkey, giv, gpt, encrypt=True)
    assert gct.hex() == "cea7403d4d606b6e074ec5d3baf39d18", "GCM ct"
    assert gtag.hex() == "d0d1c8a799996bf0265b98b5d48ab919", "GCM tag"
    assert _gcm_crypt(gkey, giv, gct, tag=gtag, encrypt=False) == gpt, "GCM round-trip"
    ok.append("AES-256-GCM NIST")

    # AES-256-XTS round-trip, con y sin bloque parcial (CTS).
    xts_key = bytes(range(64))
    tweak = bytes(range(16))
    for n in (16, 32, 48, 100, 340789):
        data = bytes((i * 7 + 3) % 256 for i in range(n))
        enc = _xts_crypt(xts_key, tweak, data, encrypt=True)
        assert _xts_crypt(xts_key, tweak, enc, encrypt=False) == data, "XTS %d" % n
    ok.append("AES-256-XTS round-trip (16/32/48/100/340789 B, con CTS)")

    # Respuesta conocida del catalogo vivo: los primeros 64 bytes del blob
    # real (tweak + 3 bloques) descifran a '{"Servers":[{"Name":"NEjoBa1...'
    # (el Name va cifrado con GCM dentro del JSON del catalogo).
    live_head = base64.b64decode(
        "QDbVK5R6uBL8ZYWGjb3+yjJ9Bp1C98d8CCSsBrYqZo9eEUMl4XX+yU4mQj5a0slK"
        "I4hoUhgyO53eNxITpvY3Ag=="
    )
    assert _xts_crypt(KEY64, live_head[:16], live_head[16:], encrypt=False) == (
        b'{"Servers":[{"Name":"NEjoBa1cgCMUOKvAjAS27u6sD0U'
    ), "XTS known-answer (catalogo vivo)"
    ok.append("XTS known-answer (primeros 48 B del catalogo vivo)")

    # ChaCha20-Poly1305, vector RFC 8439 A.5 (con su AAD).
    ckey = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    cnonce = bytes.fromhex("070000004041424344454647")
    caad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    cpt = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
           b"only one tip for the future, sunscreen would be it.")
    cct, ctag = _chacha20_poly1305_crypt(ckey, cnonce, cpt, encrypt=True, aad=caad)
    assert cct.hex() == ("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62"
                         "d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692"
                         "ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4d"
                         "ef08e4b7a9de576d26586cec64b6116"), "ChaCha20-Poly1305 ct"
    assert ctag.hex() == "1ae10b594f09e26a7e902ecbd0600691", "ChaCha20-Poly1305 tag"
    assert _chacha20_poly1305_crypt(ckey, cnonce, cct, tag=ctag, encrypt=False, aad=caad) == cpt
    ok.append("ChaCha20-Poly1305 RFC 8439 A.5")

    # ChaCha20 (modo 2) round-trip.
    ch = _chacha20_xor(KEY32, 0, bytes(range(12)), b"hello chacha20 world")
    assert _chacha20_xor(KEY32, 0, bytes(range(12)), ch) == b"hello chacha20 world"
    ok.append("ChaCha20 round-trip")

    # Modos 0/1/3/4/5 round-trip a traves del dispatch nativo.
    sample = b'{"Name":"SUPER UDP 1","Flag":"ma"}'
    for mode in (0, 1, 3, 4, 5):
        blob = mode_encrypt(mode, sample)
        assert mode_decrypt(mode, blob) == sample, "modo %d" % mode
    ok.append("modos nativos 0/1/3/4/5 round-trip")

    # UUIDs NOOB_ round-trip (valores SINTETICOS, nunca credenciales
    # reales: el script viaja en el ZIP y el redactado no lleva UUID).
    # Se ofusca y de-ofusca un UUID estandar, un user-id VLESS y un
    # identificador corto inventados; debe devolver el original.
    for sample_uuid in ("11111111-2222-3333-4444-555555555555",
                        "testuser-1234567890", "test"):
        enc = obfuscate_noob_uuid(sample_uuid)
        assert enc.startswith("NOOB_"), "NOOB_ round-trip prefijo"
        assert deobfuscate_noob_uuid(enc) == sample_uuid, "NOOB_ round-trip"
    assert deobfuscate_noob_uuid("no-es-noob") is None
    assert deobfuscate_noob_uuid("NOOB_!!!") is None
    ok.append("UUID NOOB_ round-trip (UUID, user-id VLESS, id corto)")

    # .ar round-trip (perfil sintetico, sin credenciales reales).
    profile = {
        "PSInstall": True, "DeviceID": "test-device", "RootBlock": False,
        "MobileData": True, "ExpireDate": 0, "isMsg": False, "CFGMessage": "",
        "isPassON": False, "MyPass": "", "Payload": "GET / HTTP/1.1",
        "WSPayload": "", "SNIHost": "example.com", "BUGHost": "",
        "DNSHost": "8.8.8.8", "ProxySet": False, "UDPhost": "",
        "UDPobfs": "", "UDPauth": "", "V2Ejson": "", "v2Esni": "",
        "isUri": False, "isEreverse": False, "EwgConf": "",
        "TunnelType": 0, "isWSProxy": False, "isWS": False,
        "Server": "TEST SERVER", "NoobDev": "test",
    }
    ar = encode_ar(profile)
    assert decode_ar(ar) == profile, ".ar round-trip"
    ok.append(".ar round-trip (perfil sintetico)")

    print("self-test OK (%d checks):" % len(ok))
    for line in ok:
        print("  -", line)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Decodificador AR PRO VPN 2.0 (SP-DECODE)")
    ap.add_argument("file", nargs="?", help="cuerpo del catalogo guardado o archivo .ar")
    ap.add_argument("--url", action="store_true", help="descargar el catalogo 2.0 en vivo")
    ap.add_argument("--ar", action="store_true", help="decodificar un archivo .ar 2.0")
    ap.add_argument("--self-test", action="store_true", help="round-trips y vectores conocidos")
    ap.add_argument("-o", "--output", help="archivo JSON de salida (catalogo redactado por defecto)")
    ap.add_argument("--full", action="store_true",
                    help="guardar el catalogo COMPLETO (con credenciales); solo para uso local, nunca en el ZIP ni en Drive")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()

    try:
        if args.ar:
            if not args.file:
                ap.error("--ar necesita un archivo .ar")
            profile = decode_ar(_read(args.file))
            print(json.dumps(profile, ensure_ascii=False, indent=2))
            return 0
        if args.url:
            doc, stats, _body = fetch_catalog()
        elif args.file:
            doc, stats = decode_catalog(_read(args.file))
        else:
            ap.error("falta --url o un archivo de entrada")
    except DecodeError as exc:
        print("error [%s]: %s" % (exc.code, exc), file=sys.stderr)
        return 1

    version = doc.get("Version")
    servers = doc.get("Servers") or []
    tweaks = doc.get("Tweaks") or []
    print("catalogo version %s: %d servidores, %d tweaks "
          "(GCM %d, CBC %d, ChaCha-Poly %d, plano %d, sin resolver %d, "
          "UUID NOOB_ %d)"
          % (version, len(servers), len(tweaks), stats["gcm"], stats["cbc"],
             stats["chacha_poly"], stats["plain"], stats["unresolved"],
             stats["noob_uuid"]))
    if args.output:
        out_doc = doc if args.full else redact_catalog(doc)
        _write(args.output, json.dumps(out_doc, ensure_ascii=False, indent=2))
        print("guardado:", args.output,
              "(completo)" if args.full else "(redactado)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
