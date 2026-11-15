#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V2Box - V2ray Client (dev.hexasoftware.v2box) 6.2.3, build 88 — decodificador
de archivos de exportación .v2box (formatos v1 y v2), formato de proveedor
de SP-DECODE. Solo biblioteca estándar de Python 3.10+.

MÉTODO RECUPERADO DEL APK 6.2.3 (clases.dex; verificado, no reutilizado a
ciegas del repo: el repo cubría 6.1.2 y solo tenía el formato v1):

  * El archivo .v2box es SIEMPRE un JSON con magic "v2box_export".
  * v1 (version = 1, clase ug2): campos isPasswordProtected,
    expirationTimestamp, allowedDeviceIDs, ciphertext, nonce, tag — todo
    Base64 estándar sin saltos de línea. AES-256-GCM, nonce de 12 B,
    tag de 16 B (ciphertext y tag van separados; el GCM verifica
    ct || tag). Clave: si no hay contraseña, la clave fija
    b"V2BoxEncryptionKey2026_Secret!#%" (32 B), guardada en el DEX como
    bytes XOR 90 en el <clinit> de la clase xg2 (campo `a`; la función
    xg2.c() hace out[i] = a[i] ^ 90); si hay contraseña, la clave es
    SHA-256(contraseña UTF-8) (xg2.d). El texto plano es un JSON
    PackageContent (tg2) con "configs" (renombrado a "a" al cifrar) y
    "raws" (renombrado a "b").
  * v2 (version = 2, sobre zg2 "Envelope"): campos magic, version,
    header, nonce, ciphertext, tag — header/nonce/ciphertext/tag en
    Base64 estándar. header (decodificado) es un JSON (ah2):
    {v, kdf, salt, iterations, expiresAt, deviceIds, recipients,
    createdAt}. El payload va cifrado con AES-256-GCM con una clave de
    archivo aleatoria de 32 B, nonce de 12 B y AAD = los bytes exactos
    del JSON del header. El texto plano es un JSON Payload (eh2):
    {configs: [{name, profile, raw, type, value}], subscription,
    locked, lockMessage}; cada config tiene type "profile" (value =
    ProfileItem JSON), "link" (value = enlace vmess:// etc.) o "json"
    (value = config V2Ray JSON con "outbounds").
    La clave de archivo se obtiene según header.kdf:
      - "pbkdf2-sha256": PBKDF2-HMAC-SHA256(contraseña normalizada NFC
        en UTF-8, salt, iterations — 600000 por defecto —, 32 B).
      - "ecdh-p256": cada recipient es {kid, epk, key} (Base64). kid =
        Base64(SHA-256(clave pública del destinatario, punto P-256 sin
        comprimir de 65 B)[0:8]). Para abrirlo hace falta la clave
        PRIVADA P-256 del dispositivo destinatario: shared =
        ECDH(privada, epk); kek = HKDF-SHA256(salt = epk || pub,
        ikm = shared, info = b"v2box/2 recipient", L = 44); la clave
        de archivo sale de AES-256-GCM(kek[0:32], nonce = kek[32:44])
        descifrando recipient.key (48 B = 32 ct + 16 tag). Sin la
        clave privada del dispositivo NO se puede abrir offline: la
        app la guarda en Android Keystore (alias v2box_device_p256 /
        v2box_device_wrap) y no es exportable.
      - "none": la clave de archivo es la clave fija v1 (xg2.c()).
      - cualquier otro kdf: la app responde "Export file needs a
        newer version of the app".
    Límites y avisos que aplica la app (aquí se reportan, no se
    ocultan): archivo > 10 MB rechazado; expiresAt/expirationTimestamp
    vencido; allowedDeviceIDs/deviceIds sin el user_uuid del
    dispositivo ("This device is not authorized to open this file").

LO QUE NO SE PUEDE ABRIR OFFLINE:
  * .v2box v2 con kdf ecdh-p256 sin la clave privada P-256 del
    dispositivo destinatario (se reporta RECIPIENT_KEY_REQUIRED con
    los kid para identificar el dispositivo).
  * .v2box v1/v2 con contraseña sin conocerla (se reporta
    NEED_PASSWORD).

El repo SP-DECODE ya cubría V2Box 6.1.2 (decoders/Python/v2box.py y
v2box_export.py) con SOLO el formato v1 y con PyCryptodome. Esta
versión 6.2.3 mantiene el v1 intacto (misma clave, mismo sobre) y
AÑADE el formato v2 descrito arriba, que el repo no tenía. Este
script implementa ambos en stdlib puro.

Uso:
  python3 V2Box_archivos.py archivo.v2box [--password CONTRASEÑA]
      [--device-key CLAVE] [--json]
  python3 V2Box_archivos.py --self-test
  --device-key acepta: escalar P-256 de 32 B en Base64 o hexadecimal,
  o una clave PKCS#8 DER en Base64 (o un archivo .pem/.der).
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac as hmac_mod
import json
import struct
import sys
import time
import unicodedata
from pathlib import Path

# ------------------------------------------------------------------ constantes
# Bytes tal cual están en el DEX (xg2.a), ofuscados con XOR 90.
_V2BOX_RAW_KEY = bytes([
    12, 104, 24, 53, 34, 31, 52, 57, 40, 35, 42, 46, 51, 53, 52, 17,
    63, 35, 104, 106, 104, 108, 5, 9, 63, 57, 40, 63, 46, 123, 121, 127,
])
# Clave fija v1: b"V2BoxEncryptionKey2026_Secret!#%"
V2BOX_KEY = bytes(b ^ 90 for b in _V2BOX_RAW_KEY)

MAGIC = "v2box_export"
MAX_FILE_BYTES = 10 * 1024 * 1024  # xg2.d: 10 MB
PBKDF2_ITERATIONS_DEFAULT = 600000  # ah2.a: Integer.valueOf(600000)
HKDF_INFO = b"v2box/2 recipient"  # ih2.a, campo estático `a`
MAX_RECIPIENTS = 100

PROVIDER = "V2Box"
APP_VERSION = "6.2.3"
APP_BUILD = 88


class DecodeError(Exception):
    """Error de decodificación con un código estable para SP-DECODE."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


# ------------------------------------------------------- AES-256-GCM (stdlib)
# Implementación AES pura en Python, reutilizada del lote de Fat Tunnel
# (~/workspace/catalogs/fat/Fat_Tunnel_Lite_archivos.py), verificada allí
# contra vectores NIST AES-GCM.
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
                    aa = ((aa << 1) ^ (0x1b if aa & 0x80 else 0)) & 0xff
                    bb >>= 1
                if p == 1:
                    inv = y
                    break
        s = inv ^ ((inv << 1) | (inv >> 7)) ^ ((inv << 2) | (inv >> 6)) \
            ^ ((inv << 3) | (inv >> 5)) ^ ((inv << 4) | (inv >> 4)) ^ 0x63
        sbox.append(s & 0xff)
    return sbox


_SBOX = _make_sbox()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
_GCM_R = 0xe1000000000000000000000000000000


def _aes_key_expand(key):
    w = [x for grp in (struct.unpack(">4I", key[i:i + 16]) for i in range(0, 32, 16)) for x in grp]
    for i in range(8, 60):
        temp = w[i - 1]
        if i % 8 == 0:
            rot = ((temp << 8) | (temp >> 24)) & 0xffffffff
            sub = (_SBOX[(rot >> 24) & 0xff] << 24) | (_SBOX[(rot >> 16) & 0xff] << 16) \
                | (_SBOX[(rot >> 8) & 0xff] << 8) | _SBOX[rot & 0xff]
            temp = sub ^ (_RCON[i // 8 - 1] << 24)
        elif i % 8 == 4:
            temp = (_SBOX[(temp >> 24) & 0xff] << 24) | (_SBOX[(temp >> 16) & 0xff] << 16) \
                | (_SBOX[(temp >> 8) & 0xff] << 8) | _SBOX[temp & 0xff]
        w.append(w[i - 8] ^ temp)
    return w


def _aes_encrypt_block(key_words, block):
    s = list(struct.unpack(">4I", block))
    rk = key_words
    for i in range(4):
        s[i] ^= rk[i]
    for rnd in range(1, 14):
        b = bytearray(16)
        for i in range(4):
            for j in range(4):
                b[4 * j + i] = _SBOX[(s[j] >> (24 - 8 * i)) & 0xff]
        sb = bytearray(16)
        for r in range(4):
            for c in range(4):
                sb[4 * c + r] = b[4 * ((c + r) % 4) + r]

        def xtime(x):
            return ((x << 1) ^ (0x1b if x & 0x80 else 0)) & 0xff
        out = [0] * 4
        for c in range(4):
            a0, a1, a2, a3 = sb[4 * c], sb[4 * c + 1], sb[4 * c + 2], sb[4 * c + 3]
            out[c] = (xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3) << 24 \
                | (a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3) << 16 \
                | (a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)) << 8 \
                | ((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3))
        s = out
        for i in range(4):
            s[i] ^= rk[4 * rnd + i]
    b = bytearray(16)
    for i in range(4):
        for j in range(4):
            b[4 * j + i] = _SBOX[(s[j] >> (24 - 8 * i)) & 0xff]
    sb = bytearray(16)
    for r in range(4):
        for c in range(4):
            sb[4 * c + r] = b[4 * ((c + r) % 4) + r]
    s = list(struct.unpack(">4I", bytes(sb)))
    for i in range(4):
        s[i] ^= rk[56 + i]
    return struct.pack(">4I", *s)


def _gf_mul(x, y):
    z = 0
    v = y
    for _ in range(128):
        if (x >> 127) & 1:
            z ^= v
        v = (v >> 1) ^ _GCM_R if v & 1 else v >> 1
        x = (x << 1) & ((1 << 128) - 1)
    return z


def _ghash(h, data):
    y = 0
    for i in range(0, len(data), 16):
        y = _gf_mul(y ^ int.from_bytes(data[i:i + 16], "big"), h)
    return y


def _aes_gcm_decrypt(key, nonce, ciphertext, tag, aad=b""):
    """AES-256-GCM decrypt (stdlib puro). nonce: 12 bytes; tag: 16 bytes."""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    kw = _aes_key_expand(key)
    h = int.from_bytes(_aes_encrypt_block(kw, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    pt = bytearray()
    counter = 1
    for i in range(0, len(ciphertext), 16):
        chunk = ciphertext[i:i + 16]
        ctr = nonce + struct.pack(">I", counter + 1)
        ks = _aes_encrypt_block(kw, ctr)
        pt += bytes(a ^ b for a, b in zip(chunk, ks))
        counter += 1

    def pad16(d):
        return d + b"\x00" * ((-len(d)) % 16)
    s = _ghash(h, pad16(aad) + pad16(ciphertext)
               + struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8))
    ej0 = _aes_encrypt_block(kw, j0)
    calc_tag = (s ^ int.from_bytes(ej0, "big")).to_bytes(16, "big")
    if calc_tag != tag:
        raise ValueError("GCM tag mismatch")
    return bytes(pt)


def _aes_gcm_encrypt(key, nonce, plaintext, aad=b""):
    """AES-256-GCM encrypt (stdlib puro). Devuelve (ciphertext, tag)."""
    kw = _aes_key_expand(key)
    h = int.from_bytes(_aes_encrypt_block(kw, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    ct = bytearray()
    counter = 1
    for i in range(0, len(plaintext), 16):
        chunk = plaintext[i:i + 16]
        ctr = nonce + struct.pack(">I", counter + 1)
        ks = _aes_encrypt_block(kw, ctr)
        ct += bytes(a ^ b for a, b in zip(chunk, ks))
        counter += 1

    def pad16(d):
        return d + b"\x00" * ((-len(d)) % 16)
    s = _ghash(h, pad16(aad) + pad16(bytes(ct))
               + struct.pack(">QQ", len(aad) * 8, len(ct) * 8))
    ej0 = _aes_encrypt_block(kw, j0)
    tag = (s ^ int.from_bytes(ej0, "big")).to_bytes(16, "big")
    return bytes(ct), tag


# ------------------------------------------------------------ Base64 / HKDF
def _b64d(text):
    """Base64 estándar (Android Base64.NO_WRAP = 2) con padding tolerante."""
    if text is None:
        return None
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("ascii", "replace")
    s = "".join(str(text).split())
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def _b64e(raw):
    return base64.b64encode(raw).decode("ascii")


def _hkdf_sha256(salt, ikm, info, length=44):
    """HKDF-SHA256 (RFC 5869) tal como lo implementa ih2.d:
    extract(salt, ikm) -> PRK; expand(PRK, info, L) con T(i)."""
    prk = hmac_mod.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac_mod.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


# ------------------------------------------------------- ECDH P-256 (stdlib)
# Curva secp256r1 (NIST P-256), la misma que usa la app (ECGenParameterSpec
# "secp256r1"; jv1.b/c codifican el punto sin comprimir: 0x04 || X || Y).
_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
_A = _P - 3
_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5


def _ec_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p == q:
        lam = (3 * x1 * x1 + _A) * pow(2 * y1, -1, _P) % _P
    else:
        lam = (y2 - y1) * pow((x2 - x1) % _P, -1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _ec_mul(k, point=(_GX, _GY)):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _ec_add(result, addend)
        addend = _ec_add(addend, addend)
        k >>= 1
    return result


def _point_to_bytes(point):
    x, y = point
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def _point_from_bytes(raw):
    """Decodifica un punto P-256 sin comprimir (65 B, 0x04||X||Y) y lo
    valida en la curva (igual que jv1.b)."""
    if len(raw) != 65 or raw[0] != 4:
        raise DecodeError("INVALID_RECIPIENT_KEY", "Not a P-256 public key")
    x = int.from_bytes(raw[1:33], "big")
    y = int.from_bytes(raw[33:65], "big")
    if x >= _P or y >= _P:
        raise DecodeError("INVALID_RECIPIENT_KEY", "Not a P-256 public key")
    if (y * y - (x * x * x + _A * x + _B)) % _P != 0:
        raise DecodeError("INVALID_RECIPIENT_KEY", "Not a P-256 public key")
    return (x, y)


def _parse_device_key(value):
    """Acepta la clave privada P-256 del dispositivo como:
    - escalar de 32 B en Base64 o hexadecimal,
    - PKCS#8 DER en Base64 (o archivo .pem/.der con ese contenido).
    Devuelve (escalar_int, pubkey_bytes_65)."""
    if value is None:
        return None
    text = value.strip() if isinstance(value, str) else value
    raw = None
    if isinstance(text, str) and ("-----BEGIN" in text or text.startswith("-----")):
        body = "".join(
            ln.strip() for ln in text.splitlines()
            if ln.strip() and not ln.startswith("-----")
        )
        raw = _b64d(body)
    elif isinstance(text, str):
        candidate = "".join(text.split())
        try:
            raw = _b64d(candidate)
        except (binascii.Error, ValueError):
            raw = None
        if raw is None or len(raw) not in (32,):
            try:
                raw = bytes.fromhex(candidate)
            except ValueError:
                raw = None
        if raw is None:
            # ¿Es la ruta de un archivo .pem/.der?
            p = Path(text)
            if p.is_file():
                blob = p.read_bytes()
                if blob.startswith(b"-----"):
                    body = "".join(
                        ln.decode("ascii", "replace").strip()
                        for ln in blob.decode("ascii", "replace").splitlines()
                        if ln.strip() and not ln.startswith("-----")
                    )
                    raw = _b64d(body)
                else:
                    raw = blob
    if raw is None:
        raise DecodeError("INVALID_DEVICE_KEY",
                          "No se pudo interpretar --device-key")
    if len(raw) == 32:
        scalar = int.from_bytes(raw, "big")
    else:
        scalar = _extract_pkcs8_scalar(raw)
    if not (1 <= scalar < _N):
        raise DecodeError("INVALID_DEVICE_KEY",
                          "La clave privada P-256 está fuera de rango")
    pub = _point_to_bytes(_ec_mul(scalar))
    return scalar, pub


def _extract_pkcs8_scalar(der):
    """Extrae el escalar de 32 B de una clave EC PKCS#8 DER
    (SEQUENCE { INTEGER 0, SEQUENCE { OID, OID }, OCTET STRING {
    SEQUENCE { INTEGER 1, OCTET STRING escalar, ... } } })."""
    def read_tlv(buf, pos):
        if pos + 2 > len(buf):
            raise DecodeError("INVALID_DEVICE_KEY", "DER truncado")
        tag = buf[pos]
        pos += 1
        ln = buf[pos]
        pos += 1
        if ln & 0x80:
            n = ln & 0x7f
            ln = int.from_bytes(buf[pos:pos + n], "big")
            pos += n
        return tag, buf[pos:pos + ln], pos + ln

    try:
        tag, outer, _ = read_tlv(der, 0)
        if tag != 0x30:
            raise DecodeError("INVALID_DEVICE_KEY", "No es PKCS#8 DER")
        pos = 0
        _, _, pos = read_tlv(outer, pos)   # INTEGER 0
        _, _, pos = read_tlv(outer, pos)   # SEQUENCE AlgorithmIdentifier
        _, octets, _ = read_tlv(outer, pos)  # OCTET STRING privateKey
        tag, inner, _ = read_tlv(octets, 0)
        if tag != 0x30:
            raise DecodeError("INVALID_DEVICE_KEY", "ECPrivateKey inválido")
        ipos = 0
        _, _, ipos = read_tlv(inner, ipos)  # INTEGER 1
        _, scalar, _ = read_tlv(inner, ipos)  # OCTET STRING escalar
        if len(scalar) != 32:
            raise DecodeError("INVALID_DEVICE_KEY",
                              "El escalar EC no tiene 32 B")
        return int.from_bytes(scalar, "big")
    except DecodeError:
        raise
    except Exception as exc:
        raise DecodeError("INVALID_DEVICE_KEY",
                          "No se pudo extraer el escalar PKCS#8: %s" % exc)


# ------------------------------------------------------------ decodificadores
def _check_expiry(expires_unix, warnings):
    """expiresAt/expirationTimestamp en segundos Unix (la app compara con
    System.currentTimeMillis()/1000). Solo avisa; no bloquea el descifrado."""
    if expires_unix is None:
        return
    try:
        exp = float(expires_unix)
    except (TypeError, ValueError):
        return
    if time.time() > exp:
        warnings.append("expired: el archivo caducó el %s (unix %s)"
                        % (time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(exp)), exp))


def _check_device_ids(allowed, warnings):
    """allowedDeviceIDs/deviceIds: la app exige que el user_uuid del
    dispositivo esté en la lista. SP-DECODE no conoce ese UUID, así que
    lo reporta como restricción sin bloquear el descifrado."""
    if allowed:
        warnings.append(
            "device_restricted: solo estos dispositivos pueden abrirlo "
            "según la app: %s" % (", ".join(str(x) for x in allowed),))


def _normalize_v1_payload(plain):
    """Texto plano v1: JSON PackageContent con claves 'a'/'b' (o
    'configs'/'raws' si no se renombraron)."""
    configs = plain.get("a", plain.get("configs")) or []
    raws = plain.get("b", plain.get("raws")) or {}
    profiles = []
    for item in configs if isinstance(configs, list) else []:
        if isinstance(item, dict):
            profiles.append({
                "remarks": item.get("remarks"),
                "type": item.get("configType"),
                "server": item.get("server"),
                "port": item.get("serverPort"),
                "raw": item,
            })
    return {"configs": configs, "raws": raws, "profiles": profiles}


def _decode_v1(data, password, warnings):
    if data.get("magic") != MAGIC:
        raise DecodeError("INVALID_FORMAT", "Magic signature mismatch")
    nonce = _b64d(data.get("nonce", ""))
    tag = _b64d(data.get("tag", ""))
    ciphertext = _b64d(data.get("ciphertext", ""))
    if not nonce or not tag or not ciphertext:
        raise DecodeError("INVALID_FORMAT",
                          "Faltan nonce/tag/ciphertext en el sobre v1")
    _check_expiry(data.get("expirationTimestamp"), warnings)
    _check_device_ids(data.get("allowedDeviceIDs"), warnings)
    if data.get("isPasswordProtected"):
        if password is None:
            raise DecodeError(
                "NEED_PASSWORD",
                "Este archivo .v2box v1 está protegido con contraseña; "
                "pásala con --password.")
        key = hashlib.sha256(password.encode("utf-8")).digest()
    else:
        key = V2BOX_KEY
    try:
        plain = _aes_gcm_decrypt(key, nonce, ciphertext, tag)
    except ValueError:
        raise DecodeError("TAG_MISMATCH",
                          "El tag GCM no verifica: contraseña incorrecta "
                          "o archivo dañado/modificado.")
    try:
        payload = json.loads(plain.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise DecodeError("INVALID_PAYLOAD",
                          "El texto plano v1 no es JSON válido")
    norm = _normalize_v1_payload(payload if isinstance(payload, dict) else {})
    return {
        "status": "ok",
        "format": "v2box_export",
        "version": 1,
        "password_protected": bool(data.get("isPasswordProtected")),
        "expiration_timestamp": data.get("expirationTimestamp"),
        "allowed_device_ids": data.get("allowedDeviceIDs"),
        "payload": payload,
        "configs": norm["configs"],
        "raws": norm["raws"],
        "profiles": norm["profiles"],
        "warnings": warnings,
    }


def _normalize_v2_payload(payload):
    """Texto plano v2: JSON Payload (eh2). Cada config (yg2) trae
    name/profile/raw/type/value; type: profile | link | json."""
    configs = payload.get("configs") or []
    profiles = []
    for item in configs if isinstance(configs, list) else []:
        if not isinstance(item, dict):
            continue
        ctype = item.get("type")
        value = item.get("value")
        entry = {
            "name": item.get("name"),
            "type": ctype,
            "value": value,
            "raw": item.get("raw"),
            "profile": item.get("profile"),
        }
        if ctype == "profile" and isinstance(value, dict):
            entry["remarks"] = value.get("remarks")
            entry["server"] = value.get("server")
            entry["port"] = value.get("serverPort")
        elif ctype == "link" and isinstance(value, str):
            entry["link"] = value
        profiles.append(entry)
    return {"configs": configs, "profiles": profiles,
            "subscription": payload.get("subscription"),
            "locked": payload.get("locked"),
            "lock_message": payload.get("lockMessage")}


def _decode_v2(envelope, password, device_key, warnings):
    if envelope.get("magic") != MAGIC:
        raise DecodeError("INVALID_FORMAT", "Magic signature mismatch")
    version = envelope.get("version")
    if version != 2:
        if isinstance(version, int) and version > 2:
            raise DecodeError(
                "NEEDS_NEWER_APP",
                "Export file needs a newer version of the app "
                "(version %s)" % version)
        raise DecodeError("INVALID_FORMAT",
                          "Versión de sobre no soportada: %r" % (version,))
    try:
        header_bytes = _b64d(envelope.get("header", ""))
        header = json.loads(header_bytes.decode("utf-8"))
    except Exception:
        raise DecodeError("INVALID_FORMAT",
                          "El header v2 no es JSON Base64 válido")
    if not isinstance(header, dict):
        raise DecodeError("INVALID_FORMAT", "El header v2 no es un objeto")
    if header.get("v") != 2:
        raise DecodeError("INVALID_FORMAT",
                          "Versión de header v2 distinta de 2: %r"
                          % (header.get("v"),))
    nonce = _b64d(envelope.get("nonce", ""))
    tag = _b64d(envelope.get("tag", ""))
    ciphertext = _b64d(envelope.get("ciphertext", ""))
    if not nonce or not tag or not ciphertext:
        raise DecodeError("INVALID_FORMAT",
                          "Faltan nonce/tag/ciphertext en el sobre v2")
    _check_expiry(header.get("expiresAt"), warnings)
    _check_device_ids(header.get("deviceIds"), warnings)

    kdf = header.get("kdf")
    file_key = None
    if kdf == "pbkdf2-sha256":
        if password is None:
            raise DecodeError(
                "NEED_PASSWORD",
                "Este archivo .v2box v2 está protegido con contraseña; "
                "pásala con --password.")
        salt = _b64d(header.get("salt") or "")
        iterations = header.get("iterations") or PBKDF2_ITERATIONS_DEFAULT
        pw = unicodedata.normalize("NFC", password).encode("utf-8")
        file_key = hashlib.pbkdf2_hmac("sha256", pw, salt,
                                       int(iterations), dklen=32)
    elif kdf == "ecdh-p256":
        recipients = header.get("recipients") or []
        if device_key is None:
            kids = [r.get("kid") for r in recipients
                    if isinstance(r, dict) and r.get("kid")]
            raise DecodeError(
                "RECIPIENT_KEY_REQUIRED",
                "Este archivo .v2box v2 está cifrado para dispositivo(s) "
                "con kid %s. Hace falta la clave privada P-256 del "
                "dispositivo destinatario (--device-key); está en su "
                "Android Keystore y no es exportable." % (kids,))
        scalar, pub = _parse_device_key(device_key)
        my_kid = _b64e(hashlib.sha256(pub).digest()[:8])
        file_key = None
        tried = []
        for rec in recipients:
            if not isinstance(rec, dict):
                continue
            tried.append(rec.get("kid"))
            if rec.get("kid") != my_kid:
                continue
            epk = _b64d(rec.get("epk") or "")
            wrapped = _b64d(rec.get("key") or "")
            if len(wrapped) != 48:
                continue
            epk_point = _point_from_bytes(epk)
            shared_point = _ec_mul(scalar, epk_point)
            shared = shared_point[0].to_bytes(32, "big")
            kek = _hkdf_sha256(epk + pub, shared, HKDF_INFO, 44)
            try:
                file_key = _aes_gcm_decrypt(kek[:32], kek[32:44],
                                            wrapped[:32], wrapped[32:])
                break
            except ValueError:
                continue
        if file_key is None:
            raise DecodeError(
                "RECIPIENT_KEY_REQUIRED",
                "Ningún recipient coincide con esta clave de dispositivo "
                "(mi kid %s; recipients: %s). El archivo es de otro "
                "dispositivo." % (my_kid, tried))
    elif kdf == "none":
        file_key = V2BOX_KEY
    else:
        raise DecodeError(
            "NEEDS_NEWER_APP",
            "Export file needs a newer version of the app "
            "(kdf desconocido: %r)" % (kdf,))

    try:
        plain = _aes_gcm_decrypt(file_key, nonce, ciphertext, tag,
                                 aad=header_bytes)
    except ValueError:
        raise DecodeError("TAG_MISMATCH",
                          "El tag GCM no verifica: contraseña incorrecta, "
                          "clave de dispositivo incorrecta o archivo "
                          "dañado/modificado (\"This file is damaged or "
                          "was changed\").")
    try:
        payload = json.loads(plain.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise DecodeError("INVALID_PAYLOAD",
                          "El texto plano v2 no es JSON válido")
    norm = _normalize_v2_payload(payload if isinstance(payload, dict) else {})
    return {
        "status": "ok",
        "format": "v2box_export",
        "version": 2,
        "kdf": kdf,
        "header": header,
        "payload": payload,
        "configs": norm["configs"],
        "profiles": norm["profiles"],
        "subscription": norm["subscription"],
        "locked": norm["locked"],
        "lock_message": norm["lock_message"],
        "warnings": warnings,
    }


def decode_file(data, password=None, device_key=None):
    """Decodifica un archivo .v2box (bytes o str). Devuelve un dict con
    status ok y los perfiles, o lanza DecodeError con un código."""
    if isinstance(data, (bytes, bytearray)):
        raw = bytes(data)
    else:
        raw = str(data).encode("utf-8")
    if len(raw) > MAX_FILE_BYTES:
        raise DecodeError("TOO_LARGE",
                          "File is too large to import (%d B > 10 MB)"
                          % len(raw))
    text = raw.decode("utf-8", "replace").strip()
    try:
        envelope = json.loads(text)
    except ValueError:
        raise DecodeError("INVALID_FORMAT",
                          "Invalid or corrupted export file format "
                          "(no es JSON)")
    if not isinstance(envelope, dict):
        raise DecodeError("INVALID_FORMAT",
                          "Invalid or corrupted export file format")
    warnings = []
    if envelope.get("magic") != MAGIC:
        raise DecodeError("INVALID_FORMAT", "Magic signature mismatch")
    version = envelope.get("version", 1)
    if version == 1:
        return _decode_v1(envelope, password, warnings)
    if version == 2:
        return _decode_v2(envelope, password, device_key, warnings)
    if isinstance(version, int) and version > 2:
        raise DecodeError("NEEDS_NEWER_APP",
                          "Export file needs a newer version of the app "
                          "(version %s)" % version)
    raise DecodeError("INVALID_FORMAT",
                      "Versión de sobre no soportada: %r" % (version,))


def run(data, password=None, device_key=None):
    """Wrapper estilo proveedor SP-DECODE: devuelve el JSON legible o None."""
    try:
        result = decode_file(data, password=password, device_key=device_key)
    except DecodeError as exc:
        return json.dumps({"status": "error", "code": exc.code,
                           "error": exc.message}, ensure_ascii=False, indent=2)
    return json.dumps(result, ensure_ascii=False, indent=2)


# ------------------------------------------------------- self-test (sintético)
# Los cifradores de abajo replican EXACTAMENTE lo que hace la app al
# exportar (xg2.a para v1, ih2.a para v2); el self-test cifra datos
# sintéticos y verifica que decode_file() los abre. No hay archivos
# .v2box reales de usuario para probar: un archivo real es lo que
# cerraría la verificación end-to-end.
def _selftest_encrypt_v1(payload, password=None):
    nonce = bytes(range(12))
    key = (hashlib.sha256(password.encode("utf-8")).digest()
           if password is not None else V2BOX_KEY)
    ct, tag = _aes_gcm_encrypt(key, nonce, json.dumps(
        payload, ensure_ascii=False).encode("utf-8"))
    env = {"magic": MAGIC, "version": 1,
           "isPasswordProtected": password is not None,
           "expirationTimestamp": None, "allowedDeviceIDs": None,
           "ciphertext": _b64e(ct), "nonce": _b64e(nonce), "tag": _b64e(tag)}
    return json.dumps(env).encode("utf-8")


def _selftest_encrypt_v2(payload, password=None, recipients_pub=(),
                         device_scalar=None):
    header = {"v": 2, "kdf": "none", "salt": None, "iterations": None,
              "expiresAt": None, "deviceIds": None, "recipients": None,
              "createdAt": 1790000000}
    if password is not None:
        salt = bytes(range(16))
        header["kdf"] = "pbkdf2-sha256"
        header["salt"] = _b64e(salt)
        header["iterations"] = PBKDF2_ITERATIONS_DEFAULT
        file_key = hashlib.pbkdf2_hmac(
            "sha256", unicodedata.normalize("NFC", password).encode("utf-8"),
            salt, PBKDF2_ITERATIONS_DEFAULT, dklen=32)
    elif recipients_pub:
        file_key = bytes(range(32))
        header["kdf"] = "ecdh-p256"
        recs = []
        for pub in recipients_pub:
            eph_scalar = 0x123456789abcdef
            epk_point = _ec_mul(eph_scalar)
            epk = _point_to_bytes(epk_point)
            shared = _ec_mul(eph_scalar, _point_from_bytes(pub))[0].to_bytes(32, "big")
            kek = _hkdf_sha256(epk + pub, shared, HKDF_INFO, 44)
            wrapped, wtag = _aes_gcm_encrypt(kek[:32], kek[32:44], file_key)
            recs.append({"kid": _b64e(hashlib.sha256(pub).digest()[:8]),
                         "epk": _b64e(epk),
                         "key": _b64e(wrapped + wtag)})
        header["recipients"] = recs
    else:
        file_key = V2BOX_KEY
    header_bytes = json.dumps(header, ensure_ascii=False).encode("utf-8")
    nonce = bytes(range(12, 24))
    ct, tag = _aes_gcm_encrypt(file_key, nonce, json.dumps(
        payload, ensure_ascii=False).encode("utf-8"), aad=header_bytes)
    env = {"magic": MAGIC, "version": 2, "header": _b64e(header_bytes),
           "nonce": _b64e(nonce), "ciphertext": _b64e(ct), "tag": _b64e(tag)}
    return json.dumps(env).encode("utf-8")


def self_test():
    checks = []
    # 1. AES-256-GCM: verificación cruzada con la librería `cryptography`
    # (solo en el self-test; el script en sí es stdlib puro) y round-trip.
    try:
        key = bytes(range(32))
        nonce = bytes(range(12))
        pt0 = b"V2Box AES-GCM round-trip 1234567890"
        ct0, tag0 = _aes_gcm_encrypt(key, nonce, pt0, aad=b"v2box/2")
        ok = _aes_gcm_decrypt(key, nonce, ct0, tag0, aad=b"v2box/2") == pt0
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            ref = AESGCM(key).decrypt(nonce, ct0 + tag0, b"v2box/2")
            ok = ok and ref == pt0
        except ImportError:
            pass  # sin `cryptography`, el round-trip ya verifica el GCM
        checks.append(("AES-256-GCM (round-trip + ref)", ok))
    except Exception as exc:
        checks.append(("AES-256-GCM (round-trip + ref)", "ERROR: %s" % exc))
    # 2. v1 sin contraseña.
    p1 = {"a": [{"remarks": "Test v1", "configType": "Vmess",
                 "server": "1.2.3.4", "serverPort": "443"}], "b": {}}
    try:
        r = decode_file(_selftest_encrypt_v1(p1))
        checks.append(("v1 sin contraseña", r["status"] == "ok"
                       and r["profiles"][0]["server"] == "1.2.3.4"))
    except Exception as exc:
        checks.append(("v1 sin contraseña", "ERROR: %s" % exc))
    # 3. v1 con contraseña (y contraseña incorrecta -> TAG_MISMATCH).
    try:
        r = decode_file(_selftest_encrypt_v1(p1, "Ghost"), password="Ghost")
        ok = r["status"] == "ok"
        try:
            decode_file(_selftest_encrypt_v1(p1, "Ghost"), password="mal")
            ok = False
        except DecodeError as exc:
            ok = ok and exc.code == "TAG_MISMATCH"
        checks.append(("v1 con contraseña", ok))
    except Exception as exc:
        checks.append(("v1 con contraseña", "ERROR: %s" % exc))
    # 4. v2 con contraseña PBKDF2.
    p2 = {"configs": [{"name": "Test v2", "type": "link",
                       "value": "vmess://eyJ2IjoiMiJ9",
                       "profile": None, "raw": None}],
          "subscription": None, "locked": False, "lockMessage": ""}
    try:
        r = decode_file(_selftest_encrypt_v2(p2, password="Secreto123"),
                        password="Secreto123")
        checks.append(("v2 pbkdf2-sha256", r["status"] == "ok"
                       and r["kdf"] == "pbkdf2-sha256"
                       and r["profiles"][0]["type"] == "link"))
    except Exception as exc:
        checks.append(("v2 pbkdf2-sha256", "ERROR: %s" % exc))
    # 5. v2 kdf none (clave fija).
    try:
        r = decode_file(_selftest_encrypt_v2(p2))
        checks.append(("v2 kdf none", r["status"] == "ok"
                       and r["kdf"] == "none"))
    except Exception as exc:
        checks.append(("v2 kdf none", "ERROR: %s" % exc))
    # 6. v2 ecdh-p256: destinatario con escalar conocido.
    try:
        scalar = 0xabcdef123456789
        pub = _point_to_bytes(_ec_mul(scalar))
        blob = _selftest_encrypt_v2(p2, recipients_pub=[pub])
        # Sin clave -> RECIPIENT_KEY_REQUIRED.
        try:
            decode_file(blob)
            ok = False
        except DecodeError as exc:
            ok = exc.code == "RECIPIENT_KEY_REQUIRED"
        # Con la clave privada (escalar en Base64) -> abre.
        r = decode_file(blob, device_key=_b64e(scalar.to_bytes(32, "big")))
        ok = ok and r["status"] == "ok" and r["kdf"] == "ecdh-p256"
        # Con otra clave -> no coincide el kid.
        try:
            decode_file(blob, device_key=_b64e((0x9999).to_bytes(32, "big")))
            ok = False
        except DecodeError as exc:
            ok = ok and exc.code == "RECIPIENT_KEY_REQUIRED"
        checks.append(("v2 ecdh-p256", ok))
    except Exception as exc:
        checks.append(("v2 ecdh-p256", "ERROR: %s" % exc))
    # 7. Formato inválido / magic incorrecto.
    try:
        decode_file(b'{"magic": "otro"}')
        checks.append(("magic inválido", False))
    except DecodeError as exc:
        checks.append(("magic inválido", exc.code == "INVALID_FORMAT"))
    failed = [name for name, ok in checks if ok is not True]
    for name, ok in checks:
        print(("OK  " if ok is True else "FAIL") + " " + name
              + ("" if ok is True else " -> %s" % ok))
    print("self-test: %d/%d OK" % (len(checks) - len(failed), len(checks)))
    return 0 if not failed else 1


# ------------------------------------------------------------------------ CLI
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Decodificador de archivos .v2box de V2Box 6.2.3 "
                    "(formatos v1 y v2).")
    ap.add_argument("file", nargs="?", help="Archivo .v2box a decodificar")
    ap.add_argument("--password", default=None,
                    help="Contraseña del archivo (v1/v2 con contraseña)")
    ap.add_argument("--device-key", default=None,
                    help="Clave privada P-256 del dispositivo destinatario "
                         "(v2 ecdh-p256): escalar de 32 B en Base64 o hex, "
                         "o PKCS#8 DER en Base64 / archivo .pem/.der")
    ap.add_argument("--json", action="store_true",
                    help="Imprimir el resultado como JSON")
    ap.add_argument("--self-test", action="store_true",
                    help="Pruebas sintéticas de ida y vuelta (v1 y v2)")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.file:
        ap.error("falta el archivo .v2box (o usa --self-test)")
    data = Path(args.file).read_bytes()
    try:
        result = decode_file(data, password=args.password,
                             device_key=args.device_key)
    except DecodeError as exc:
        result = {"status": "error", "code": exc.code, "error": exc.message}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    print("V2Box .v2box — formato v%d, kdf %s"
          % (result["version"], result.get("kdf", "v1-fijo")))
    for w in result.get("warnings", []):
        print("AVISO: " + w)
    print("Perfiles: %d" % len(result.get("profiles", [])))
    for prof in result.get("profiles", []):
        print(" - %s | %s | %s:%s" % (
            prof.get("name") or prof.get("remarks") or "?",
            prof.get("type"), prof.get("server"), prof.get("port")))
    if result.get("subscription"):
        print("Suscripción: %s" % result["subscription"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
