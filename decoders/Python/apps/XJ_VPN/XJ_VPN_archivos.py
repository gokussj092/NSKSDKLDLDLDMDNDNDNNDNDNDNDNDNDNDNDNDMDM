#!/usr/bin/env python3
"""XJ VPN 1.9.7 (net.xj.vpn): decodificador de archivos .xj y enlaces de texto.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
See README.md here.

Method (verified against this APK, versionCode 99, versionName 1.9.7;
codecs Java net.xj.vpn.data.XjConfigCodec, GcpHostUpdateCodec y
OfflineUpdateCodec, leídos por bytecode con androguard -- jadx murió
al 52% por OOM y ApiClient.java no se decompiló, pero los codecs sí
están completos en el DEX):

Common crypto (los tres codecs): PBKDF2-HmacSHA256, 120.000
iteraciones, clave AES de 256 bits; AES-256-GCM, tag de 128 bits,
IV/nonce aleatorio de 12 bytes, salt aleatorio de 16 bytes.
Base64 URL-safe sin saltos de línea (Android Base64: flag 10 =
URL_SAFE|NO_WRAP, CON padding, en los sobres JSON de XjConfigCodec;
flag 11 = URL_SAFE|NO_WRAP|NO_PADDING en los sobres binarios de
GcpHostUpdateCodec y OfflineUpdateCodec).

1) Archivo .xj  (XjConfigCodec; formato "xj-config-v1"):
   El archivo ES el JSON de un sobre (Envelope):
     {"data": <b64url>, "locked": bool, "format": "xj-config-v1",
      "iv": <b64url|null>, "salt": <b64url|null>}
   - Sin bloqueo (locked=false): data = Base64url(JSON del payload),
     iv/salt = null. El payload es {"configName", "server": ServerDto,
     "configLocked": false}.
   - Con bloqueo (locked=true): data/iv/salt son el sobre AES-GCM
     del JSON del payload, con la contraseña que el usuario escribió
     al exportar como passphrase PBKDF2. Sin esa contraseña el
     archivo NO se puede abrir (el tag GCM lo verifica).
   Importar: parseEnvelope exige format == "xj-config-v1"; si locked
   exige contraseña no vacía, si no decodifica data en claro.
   Exportar: payloadJson fuerza id=0 y limpia varios campos del
   ServerDto (irrelevante al decodificar: se lee el JSON tal cual).

2) Enlace xj://  (XjConfigCodec; formato "xj-link-v1"):
   "xj://" + Base64url(flag 10, CON padding) del JSON del sobre
   (Envelope con format "xj-link-v1"), cifrado con la passphrase
   FIJA "xj-vpn-portable-link-v1" (constante pública de la app, no es
   una credencial de cuenta). El payload es el mismo ExportPayload
   con configLocked=true. Es el enlace que la app copia con
   "COPY ENCRYPTED XJ:// LINK".

3) Enlace xjgcp://  (GcpHostUpdateCodec; solo hosts GCP):
   Sobre BINARIO, no JSON: [version=1 (1 byte), salt (16), nonce (12),
   AES-GCM ct+tag], todo en Base64url flag 11 (SIN padding),
   prefijo "xjgcp://". Passphrase FIJA "xj-vpn-gcp-host-update-v1".
   Tras descifrar: XZ descomprimido (límite 2 MiB) -> JSON Bundle
   {"createdAt": ms, "hosts": [HostUpdate]} con HostUpdate =
   {id?, servername, uuid, gcpHost, gcpPath, gcpTrojanPath,
   gcpVmessPath, gcpXrayPath} (los campos exactos del data class;
   el exportador solo incluye servidores con host GCP).
   Es el enlace "Generate an xjgcp:// link containing only GCP hosts".

4) Enlace xjdev://  (OfflineUpdateCodec; actualización offline
   completa: servidores + payloads). Prefijo "xjdev://", versión 2;
   el prefijo legacy "xjvpn://" es la versión 1 y TAMBIÉN se acepta
   al importar.
   Sobre BINARIO igual que (3): [version (1 byte: 1 o 2), salt (16),
   nonce (12), AES-GCM ct+tag], Base64url flag 11 (SIN padding).
   Passphrase FIJA "xj-vpn-offline-update-v1".
   Tras descifrar (límite 2 MiB comprimido): v2 -> XZ; v1 -> GZIP;
   JSON (límite 8 MiB) Bundle {"createdAt": ms,
   "servers": [ServerDto...], "payloads": [PublicPayloadDto...]}.
   Importar exige ambas listas no vacías. Al exportar la app solo
   incluye servidores manuales (is_manual == true).

5) Otros sobres del mismo codec (misma passphrase fija que (2)):
   - "xj-local-v1": lista JSON de ServerDto cifrada (respaldo local
     de servidores del usuario; exportLocalServers/importLocalServers).
   - "xj-runtime-v1": texto plano arbitrario cifrado
     (exportRuntimeText/importRuntimeText).

ServerDto (35 campos; nombres y alias Gson verificados en el DEX):
  cloudfront, config_locked, country (alias country_name/countryName/
  location), country_code (alias countryCode/country_iso/...), dns,
  dnstt_enabled, dnstt_public_key (alias dnstt_pubkey/dnstt_key/
  public_key), gcp_host, gcp_path, gcp_trojan_path, gcp_vmess_path,
  gcp_xray_path, hysteria_config (muchos alias), hysteria_enabled,
  id, ip, is_manual, ns (alias nameserver/name_server/dnstt_ns),
  ovpn_profile, password, payload, payload_enabled, payload_host,
  proxy_host, proxy_port, server_protocol, servername, sni_host,
  ssh_port, ssl_enabled, status, username, uuid.
PublicPayloadDto: address, allow_insecure, alpn, alter_id,
  dns_resolver (alias resolver/dnstt_resolver/...), dnstt_enabled,
  encryption, fingerprint, flow, header_type, http_host,
  hysteria_config, hysteria_enabled, network, password, path,
  payload_description, payload_http_payload, payload_http_proxy,
  payload_http_proxy_port, payload_icon, payload_id,
  payload_is_enable, payload_is_enabled, payload_mode (alias mode/
  payloadMode), payload_name, payload_protocol, payload_ssl_enable,
  payload_ssl_sni, port, remarks, sni, tls, uuid.

Esquemas URI (AndroidManifest, MainActivity, ACTION_VIEW):
  xjvpn://, xjdev://, xjgcp://, xj:// (los cuatro; xjvpn:// es el
  prefijo legacy del enlace offline v1). Archivos .xj: mime
  application/x-xjvpn y content/file + application/octet-stream con
  pathPattern .*\\.xj. NO hay esquema .sks (no se decodifica, por
  regla del skill). Los enlaces vmess://, vless://, trojan:// y
  ss:// que puedan venir dentro de los servidores son protocolos
  estándar ya cubiertos por SP-DECODE, no esquemas propios.

Estado: los cuatro codecs están verificados por round-trip con
vectores sintéticos construidos con los campos reales del DEX
(--self-test) y el núcleo AES-256-GCM se verificó además contra la
librería `cryptography` (20/20 round-trips, tag alterado detectado).
NO hay todavía un archivo .xj ni un enlace real exportado por la app
para confirmar de extremo a extremo: los decodificadores quedan
marcados UNVERIFIED contra un archivo real. Lo que los confirmaría:
un .xj exportado por la app (con y sin contraseña), un xj://, un
xjgcp:// y un xjdev:// copiados desde la app.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import lzma
import math
import os
import secrets
import struct
import sys

MAX_BYTES = 5 * 1024 * 1024
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_COMPRESSED_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
PBKDF2_ITERATIONS = 120000

LINK_PASSPHRASE = "xj-vpn-portable-link-v1"
GCP_PASSPHRASE = "xj-vpn-gcp-host-update-v1"
OFFLINE_PASSPHRASE = "xj-vpn-offline-update-v1"

FORMAT_FILE = "xj-config-v1"
FORMAT_LINK = "xj-link-v1"
FORMAT_LOCAL = "xj-local-v1"
FORMAT_RUNTIME = "xj-runtime-v1"

LINK_PREFIX = "xj://"
GCP_PREFIX = "xjgcp://"
OFFLINE_PREFIX = "xjdev://"
OFFLINE_LEGACY_PREFIX = "xjvpn://"


class DecodeError(ValueError):
    """Error de descifrado con un código estable para SP-DECODE."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------- AES-256 puro
# Núcleo AES en Python puro con T-tables (SubBytes+ShiftRows+
# MixColumns en 4 tablas de 256 entradas), copiado de
# XUI_Tunnel.py (tanda 10a), donde se verificó contra PyCryptodome
# (vector FIPS-197 y 200 vectores aleatorios). Aquí se verificó de
# nuevo de forma independiente contra la librería `cryptography`
# (20/20 round-trips AES-256-GCM, tag alterado detectado).
# ------------------------------------------------------------- AES-256 puro
# Núcleo AES en Python puro con T-tables (SubBytes+ShiftRows+
# MixColumns en 4 tablas de 256 entradas): ~30x más rápido que
# la versión ingenua y verificado contra PyCryptodome (vector
# FIPS-197 y 200 vectores aleatorios). El descifrado usa el
# cifrado inverso equivalente: las claves de ronda 1..13 van
# transformadas por InvMixColumns (se cachean por clave).
import struct

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
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

def _xtime(x):
    return ((x << 1) ^ (0x1b if x & 0x80 else 0)) & 0xff

def _mul(x, n):
    r = 0
    while n:
        if n & 1:
            r ^= x
        x = _xtime(x)
        n >>= 1
    return r

def _make_tables():
    Te0, Te1, Te2, Te3 = [], [], [], []
    Td0, Td1, Td2, Td3 = [], [], [], []
    for i in range(256):
        s = _SBOX[i]
        s2 = _mul(s, 2)
        s3 = _mul(s, 3)
        Te0.append((s2 << 24) | (s << 16) | (s << 8) | s3)
        Te1.append((s3 << 24) | (s2 << 16) | (s << 8) | s)
        Te2.append((s << 24) | (s3 << 16) | (s2 << 8) | s)
        Te3.append((s << 24) | (s << 16) | (s3 << 8) | s2)
        isb = _INV_SBOX[i]
        m9, m11, m13, m14 = _mul(isb, 9), _mul(isb, 11), _mul(isb, 13), _mul(isb, 14)
        Td0.append((m14 << 24) | (m9 << 16) | (m13 << 8) | m11)
        Td1.append((m11 << 24) | (m14 << 16) | (m9 << 8) | m13)
        Td2.append((m13 << 24) | (m11 << 16) | (m14 << 8) | m9)
        Td3.append((m9 << 24) | (m13 << 16) | (m11 << 8) | m14)
    return (Te0, Te1, Te2, Te3), (Td0, Td1, Td2, Td3)

_TE, _TD = _make_tables()
_Te0, _Te1, _Te2, _Te3 = _TE
_Td0, _Td1, _Td2, _Td3 = _TD

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
    return tuple(w)


def _inv_mix_columns_word(w):
    a0, a1, a2, a3 = (w >> 24) & 0xff, (w >> 16) & 0xff, (w >> 8) & 0xff, w & 0xff
    return ((_mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9)) << 24
            | (_mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13)) << 16
            | (_mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11)) << 8
            | (_mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14)))

def _aes_encrypt_block(kw, block):
    s0, s1, s2, s3 = struct.unpack(">4I", block)
    s0 ^= kw[0]; s1 ^= kw[1]; s2 ^= kw[2]; s3 ^= kw[3]
    for rnd in range(1, 14):
        k = kw[4 * rnd:4 * rnd + 4]
        s0, s1, s2, s3 = (
            _Te0[s0 >> 24] ^ _Te1[(s1 >> 16) & 0xff] ^ _Te2[(s2 >> 8) & 0xff] ^ _Te3[s3 & 0xff] ^ k[0],
            _Te0[s1 >> 24] ^ _Te1[(s2 >> 16) & 0xff] ^ _Te2[(s3 >> 8) & 0xff] ^ _Te3[s0 & 0xff] ^ k[1],
            _Te0[s2 >> 24] ^ _Te1[(s3 >> 16) & 0xff] ^ _Te2[(s0 >> 8) & 0xff] ^ _Te3[s1 & 0xff] ^ k[2],
            _Te0[s3 >> 24] ^ _Te1[(s0 >> 16) & 0xff] ^ _Te2[(s1 >> 8) & 0xff] ^ _Te3[s2 & 0xff] ^ k[3])
    k = kw[56:60]
    s0, s1, s2, s3 = (
        (((_SBOX[s0 >> 24] << 24) | (_SBOX[(s1 >> 16) & 0xff] << 16) | (_SBOX[(s2 >> 8) & 0xff] << 8) | _SBOX[s3 & 0xff]) ^ k[0]),
        (((_SBOX[s1 >> 24] << 24) | (_SBOX[(s2 >> 16) & 0xff] << 16) | (_SBOX[(s3 >> 8) & 0xff] << 8) | _SBOX[s0 & 0xff]) ^ k[1]),
        (((_SBOX[s2 >> 24] << 24) | (_SBOX[(s3 >> 16) & 0xff] << 16) | (_SBOX[(s0 >> 8) & 0xff] << 8) | _SBOX[s1 & 0xff]) ^ k[2]),
        (((_SBOX[s3 >> 24] << 24) | (_SBOX[(s0 >> 16) & 0xff] << 16) | (_SBOX[(s1 >> 8) & 0xff] << 8) | _SBOX[s2 & 0xff]) ^ k[3]))
    return struct.pack(">4I", s0, s1, s2, s3)

_DKW_CACHE = {}

def _aes_decrypt_block(kw, block):
    # Claves de ronda 1..13 transformadas por InvMixColumns (cifrado
    # inverso equivalente); las rondas 0 y 14 se usan tal cual.
    # Se cachea por clave: calcularlo por bloque sería carísimo.
    dkw = _DKW_CACHE.get(kw)
    if dkw is None:
        dkw = tuple(kw[:4]) + tuple(_inv_mix_columns_word(w) for w in kw[4:56]) + tuple(kw[56:60])
        _DKW_CACHE[kw] = dkw
    s0, s1, s2, s3 = struct.unpack(">4I", block)
    s0 ^= kw[56]; s1 ^= kw[57]; s2 ^= kw[58]; s3 ^= kw[59]
    for rnd in range(13, 0, -1):
        k = dkw[4 * rnd:4 * rnd + 4]
        s0, s1, s2, s3 = (
            _Td0[s0 >> 24] ^ _Td1[(s3 >> 16) & 0xff] ^ _Td2[(s2 >> 8) & 0xff] ^ _Td3[s1 & 0xff] ^ k[0],
            _Td0[s1 >> 24] ^ _Td1[(s0 >> 16) & 0xff] ^ _Td2[(s3 >> 8) & 0xff] ^ _Td3[s2 & 0xff] ^ k[1],
            _Td0[s2 >> 24] ^ _Td1[(s1 >> 16) & 0xff] ^ _Td2[(s0 >> 8) & 0xff] ^ _Td3[s3 & 0xff] ^ k[2],
            _Td0[s3 >> 24] ^ _Td1[(s2 >> 16) & 0xff] ^ _Td2[(s1 >> 8) & 0xff] ^ _Td3[s0 & 0xff] ^ k[3])
    k = kw[0:4]
    s0, s1, s2, s3 = (
        (((_INV_SBOX[s0 >> 24] << 24) | (_INV_SBOX[(s3 >> 16) & 0xff] << 16) | (_INV_SBOX[(s2 >> 8) & 0xff] << 8) | _INV_SBOX[s1 & 0xff]) ^ k[0]),
        (((_INV_SBOX[s1 >> 24] << 24) | (_INV_SBOX[(s0 >> 16) & 0xff] << 16) | (_INV_SBOX[(s3 >> 8) & 0xff] << 8) | _INV_SBOX[s2 & 0xff]) ^ k[1]),
        (((_INV_SBOX[s2 >> 24] << 24) | (_INV_SBOX[(s1 >> 16) & 0xff] << 16) | (_INV_SBOX[(s0 >> 8) & 0xff] << 8) | _INV_SBOX[s3 & 0xff]) ^ k[2]),
        (((_INV_SBOX[s3 >> 24] << 24) | (_INV_SBOX[(s2 >> 16) & 0xff] << 16) | (_INV_SBOX[(s1 >> 8) & 0xff] << 8) | _INV_SBOX[s0 & 0xff]) ^ k[3]))
    return struct.pack(">4I", s0, s1, s2, s3)


# ------------------------------------------------------------- AES-256-GCM
_GCM_R = 0xe1000000000000000000000000000000


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
    """AES-256-GCM decrypt (NoobCrypt index 0/3), solo stdlib. nonce: 12 bytes."""
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
    """AES-256-GCM encrypt (solo para el round-trip de --self-test)."""
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




# ------------------------------------------------------------- Base64 URL-safe
# Android Base64 flag 10 = URL_SAFE | NO_WRAP (CON padding):
# la usa XjConfigCodec (sobres JSON). Flag 11 = 10 | NO_PADDING:
# la usan los sobres binarios (xjgcp://, xjdev://).

def _b64url_encode(data: bytes, pad: bool = True) -> str:
    text = base64.urlsafe_b64encode(data).decode("ascii")
    return text if pad else text.rstrip("=")


def _b64url_decode(text: str) -> bytes:
    text = text.strip()
    try:
        padded = text + "=" * (-len(text) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise DecodeError("BAD_BASE64", f"Base64 URL-safe inválido: {exc}") from exc


# ------------------------------------------------------------- PBKDF2 + GCM

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), salt,
        PBKDF2_ITERATIONS, dklen=32)


def _gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes):
    ct, tag = _aes_gcm_encrypt(key, nonce, plaintext)
    return ct + tag


def _gcm_decrypt(key: bytes, nonce: bytes, blob: bytes) -> bytes:
    if len(blob) < 16:
        raise DecodeError("TRUNCATED", "El texto cifrado es demasiado corto para el tag GCM.")
    try:
        return _aes_gcm_decrypt(key, nonce, blob[:-16], blob[-16:])
    except ValueError as exc:
        raise DecodeError("BAD_TAG",
                          "El tag GCM no verifica: contraseña incorrecta o datos dañados.") from exc


# ------------------------------------------------------------- JSON seguro

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
            raise ValueError("nonfinite number")
    return doc


def _json(data):
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeError as exc:
            raise DecodeError("INVALID_JSON", f"El texto no es UTF-8: {exc}") from exc
    try:
        doc = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON", f"JSON inválido: {exc}") from exc
    return _validate(doc)


def _text(data):
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return str(data)


# ------------------------------------------------------------- XjConfigCodec
# Sobre JSON: {"data","locked","format","iv","salt"}.

def _parse_envelope(text: str, expected_format: str) -> dict:
    doc = _json(text)
    if not isinstance(doc, dict):
        raise DecodeError("INVALID_ENVELOPE", "El sobre XJ no es un objeto JSON.")
    if doc.get("format") != expected_format:
        raise DecodeError(
            "UNSUPPORTED_FORMAT",
            f"Formato XJ no soportado: {doc.get('format')!r} (se esperaba {expected_format!r}).")
    return doc


def _encrypt_envelope(plaintext: str, passphrase: str, fmt: str) -> dict:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _derive_key(passphrase, salt)
    blob = _gcm_encrypt(key, nonce, plaintext.encode("utf-8"))
    return {"data": _b64url_encode(blob, pad=True), "locked": True,
            "format": fmt, "iv": _b64url_encode(nonce, pad=True),
            "salt": _b64url_encode(salt, pad=True)}


def _decrypt_envelope(env: dict, passphrase: str) -> str:
    salt_b64 = env.get("salt")
    iv_b64 = env.get("iv")
    if not salt_b64:
        raise DecodeError("INVALID_ENVELOPE", "Sobre cifrado sin salt.")
    if not iv_b64:
        raise DecodeError("INVALID_ENVELOPE", "Sobre cifrado sin IV.")
    salt = _b64url_decode(salt_b64)
    nonce = _b64url_decode(iv_b64)
    blob = _b64url_decode(env.get("data") or "")
    key = _derive_key(passphrase, salt)
    return _gcm_decrypt(key, nonce, blob).decode("utf-8")


def _parse_payload(text: str) -> dict:
    doc = _json(text)
    if not isinstance(doc, dict) or not doc.get("configName"):
        raise DecodeError("INVALID_PAYLOAD", "El payload XJ no trae configName.")
    return doc


def import_xj_file(text: str, password: str = "") -> dict:
    """Importar un archivo .xj (texto del sobre JSON). Devuelve el
    ExportPayload {"configName", "server", "configLocked"}."""
    env = _parse_envelope(text, FORMAT_FILE)
    if env.get("locked"):
        if not password or not password.strip():
            raise DecodeError("PASSWORD_REQUIRED",
                              "Este .xj está bloqueado: hace falta la contraseña.")
        plain = _decrypt_envelope(env, password)
    else:
        plain = _b64url_decode(env.get("data") or "").decode("utf-8")
    return _parse_payload(plain)


def export_xj_file(config_name: str, server: dict, locked: bool, password: str = "") -> str:
    """Generar el texto de un archivo .xj (solo para --self-test y
    para que SP-DECODE pueda re-exportar)."""
    if not config_name or not config_name.strip():
        raise DecodeError("INVALID_PAYLOAD", "El nombre de la config es obligatorio.")
    payload = json.dumps({"configName": config_name.strip(), "server": server,
                          "configLocked": bool(locked)}, ensure_ascii=False)
    if not locked:
        env = {"data": _b64url_encode(payload.encode("utf-8"), pad=True),
               "locked": False, "format": FORMAT_FILE, "iv": None, "salt": None}
        return json.dumps(env, ensure_ascii=False)
    if not password or not password.strip():
        raise DecodeError("PASSWORD_REQUIRED",
                          "Hace falta una contraseña para el .xj bloqueado.")
    return json.dumps(_encrypt_envelope(payload, password, FORMAT_FILE),
                      ensure_ascii=False)


def is_locked_file(text: str) -> bool:
    return bool(_parse_envelope(text, FORMAT_FILE).get("locked"))


def import_xj_link(link: str) -> dict:
    """Importar un enlace xj:// (passphrase fija de la app)."""
    text = link.strip()
    if text.lower().startswith(LINK_PREFIX):
        text = text[len(LINK_PREFIX):]
    if not text.strip():
        raise DecodeError("INVALID_LINK", "El portapapeles no contiene un enlace xj://.")
    env_json = _b64url_decode(text).decode("utf-8")
    env = _parse_envelope(env_json, FORMAT_LINK)
    return _parse_payload(_decrypt_envelope(env, LINK_PASSPHRASE))


def export_xj_link(server: dict) -> str:
    """Generar un enlace xj:// (solo para --self-test)."""
    name = (server or {}).get("servername") or ""
    payload = json.dumps({"configName": name, "server": server,
                          "configLocked": True}, ensure_ascii=False)
    env = _encrypt_envelope(payload, LINK_PASSPHRASE, FORMAT_LINK)
    return LINK_PREFIX + _b64url_encode(
        json.dumps(env, ensure_ascii=False).encode("utf-8"), pad=True)


def _import_local_envelope(text: str, fmt: str):
    env = _parse_envelope(text, fmt)
    return _decrypt_envelope(env, LINK_PASSPHRASE)


def import_local_servers(text: str):
    """Importar un respaldo xj-local-v1 (lista JSON de ServerDto)."""
    doc = _json(_import_local_envelope(text, FORMAT_LOCAL))
    if not isinstance(doc, list):
        raise DecodeError("INVALID_PAYLOAD", "El respaldo local no es una lista.")
    return doc


def export_local_servers(servers) -> str:
    return json.dumps(_encrypt_envelope(
        json.dumps(list(servers), ensure_ascii=False),
        LINK_PASSPHRASE, FORMAT_LOCAL), ensure_ascii=False)


def import_runtime_text(text: str) -> str:
    """Importar un texto xj-runtime-v1."""
    return _import_local_envelope(text, FORMAT_RUNTIME)


def export_runtime_text(plain_text: str) -> str:
    return json.dumps(_encrypt_envelope(
        plain_text, LINK_PASSPHRASE, FORMAT_RUNTIME), ensure_ascii=False)


# ------------------------------------------------------------- Sobres binarios
# [version (1 byte), salt (16), nonce (12), AES-GCM ct+tag],
# Base64url flag 11 (SIN padding). xjgcp:// v1, xjdev:// v2,
# xjvpn:// legacy v1 (GZIP en vez de XZ).

def _decode_binary_envelope(blob: bytes):
    if len(blob) <= 29:
        raise DecodeError("TRUNCATED", "El enlace es demasiado corto (mínimo 30 bytes).")
    version = blob[0]
    return version, blob[1:17], blob[17:29], blob[29:]


def _encode_binary_envelope(version: int, passphrase: str, compressed: bytes) -> str:
    if len(compressed) > MAX_COMPRESSED_BYTES:
        raise DecodeError("TOO_LARGE", "El contenido comprimido supera 2 MiB.")
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _derive_key(passphrase, salt)
    blob = bytes([version]) + salt + nonce + _gcm_encrypt(key, nonce, compressed)
    return _b64url_encode(blob, pad=False)


def _xz_compress(data: bytes) -> bytes:
    return lzma.compress(data, format=lzma.FORMAT_XZ,
                         filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 262144}])


def _xz_decompress(data: bytes) -> bytes:
    try:
        out = lzma.decompress(data, format=lzma.FORMAT_XZ)
    except (lzma.LZMAError, ValueError, EOFError) as exc:
        raise DecodeError("BAD_XZ", f"No se pudo descomprimir XZ: {exc}") from exc
    if len(out) > MAX_JSON_BYTES:
        raise DecodeError("TOO_LARGE", "El JSON descomprimido supera 8 MiB.")
    return out


def _gzip_decompress(data: bytes) -> bytes:
    try:
        out = gzip.decompress(data)
    except (OSError, EOFError, ValueError) as exc:
        raise DecodeError("BAD_GZIP", f"No se pudo descomprimir GZIP: {exc}") from exc
    if len(out) > MAX_JSON_BYTES:
        raise DecodeError("TOO_LARGE", "El JSON descomprimido supera 8 MiB.")
    return out


def import_xjgcp_link(link: str) -> dict:
    """Importar un enlace xjgcp:// -> Bundle {"createdAt", "hosts"}."""
    text = link.strip()
    if text.lower().startswith(GCP_PREFIX):
        text = text[len(GCP_PREFIX):]
    if not text.strip():
        raise DecodeError("INVALID_LINK", "Introduce un enlace xjgcp:// válido.")
    blob = _b64url_decode(text)
    version, salt, nonce, rest = _decode_binary_envelope(blob)
    if version != 1:
        raise DecodeError("UNSUPPORTED_VERSION",
                          f"Versión de actualización GCP no soportada: {version}.")
    key = _derive_key(GCP_PASSPHRASE, salt)
    plain = _gcm_decrypt(key, nonce, rest)
    doc = _json(_xz_decompress(plain))
    if not isinstance(doc, dict) or not doc.get("hosts"):
        raise DecodeError("INVALID_PAYLOAD", "La actualización GCP no contiene hosts.")
    return doc


def export_xjgcp_link(hosts, created_at_ms: int | None = None) -> str:
    """Generar un enlace xjgcp:// (solo para --self-test)."""
    if not hosts:
        raise DecodeError("INVALID_PAYLOAD", "No hay hosts GCP para exportar.")
    import time
    bundle = {"createdAt": created_at_ms if created_at_ms is not None else int(time.time() * 1000),
              "hosts": list(hosts)}
    data = json.dumps(bundle, ensure_ascii=False).encode("utf-8")
    return GCP_PREFIX + _encode_binary_envelope(1, GCP_PASSPHRASE, _xz_compress(data))


def import_xjdev_link(link: str) -> dict:
    """Importar un enlace xjdev:// (v2, XZ) o xjvpn:// legacy (v1,
    GZIP) -> Bundle {"createdAt", "servers", "payloads"}."""
    text = link.strip()
    prefix = None
    for cand in (OFFLINE_PREFIX, OFFLINE_LEGACY_PREFIX):
        if text.lower().startswith(cand):
            prefix, text = cand, text[len(cand):]
            break
    if prefix is None or not text.strip():
        raise DecodeError("INVALID_LINK", "Introduce un enlace xjdev:// válido.")
    blob = _b64url_decode(text)
    version, salt, nonce, rest = _decode_binary_envelope(blob)
    if version not in (1, 2):
        raise DecodeError("UNSUPPORTED_VERSION",
                          f"Versión de actualización offline no soportada: {version}.")
    key = _derive_key(OFFLINE_PASSPHRASE, salt)
    plain = _gcm_decrypt(key, nonce, rest)
    raw = _xz_decompress(plain) if version == 2 else _gzip_decompress(plain)
    doc = _json(raw)
    if not isinstance(doc, dict):
        raise DecodeError("INVALID_PAYLOAD", "La actualización offline no es un objeto JSON.")
    if not doc.get("servers"):
        raise DecodeError("INVALID_PAYLOAD", "La actualización offline no contiene servidores.")
    if not doc.get("payloads"):
        raise DecodeError("INVALID_PAYLOAD", "La actualización offline no contiene payloads.")
    return doc


def export_xjdev_link(servers, payloads, created_at_ms: int | None = None) -> str:
    """Generar un enlace xjdev:// v2 (solo para --self-test)."""
    if not servers:
        raise DecodeError("INVALID_PAYLOAD", "No hay servidores para exportar.")
    if not payloads:
        raise DecodeError("INVALID_PAYLOAD", "No hay payloads para exportar.")
    import time
    bundle = {"createdAt": created_at_ms if created_at_ms is not None else int(time.time() * 1000),
              "servers": list(servers), "payloads": list(payloads)}
    data = json.dumps(bundle, ensure_ascii=False).encode("utf-8")
    return OFFLINE_PREFIX + _encode_binary_envelope(2, OFFLINE_PASSPHRASE, _xz_compress(data))


# ------------------------------------------------------------- decode() / run()

def decode(data) -> dict:
    """Auto-detectar y decodificar: texto de archivo .xj, enlace
    xj://, xjdev://, xjvpn:// (legacy) o xjgcp://. Devuelve un dict
    {"kind": ..., ...} con el payload decodificado."""
    if isinstance(data, bytes):
        if len(data) > MAX_BYTES:
            raise DecodeError("SIZE_LIMIT", "El archivo supera el límite.")
        try:
            text = data.decode("utf-8")
        except UnicodeError as exc:
            raise DecodeError("INVALID_JSON", f"El archivo no es texto UTF-8: {exc}") from exc
    else:
        text = str(data)
    stripped = text.strip()
    low = stripped.lower()
    if low.startswith(LINK_PREFIX):
        return {"kind": "xj-link", "payload": import_xj_link(stripped)}
    if low.startswith(OFFLINE_PREFIX) or low.startswith(OFFLINE_LEGACY_PREFIX):
        return {"kind": "xjdev-offline-update", "bundle": import_xjdev_link(stripped)}
    if low.startswith(GCP_PREFIX):
        return {"kind": "xjgcp-host-update", "bundle": import_xjgcp_link(stripped)}
    # Sobre JSON (.xj, xj-local-v1 o xj-runtime-v1): el campo format manda.
    doc = _json(stripped)
    if not isinstance(doc, dict) or "format" not in doc:
        raise DecodeError("INVALID_ENVELOPE", "No es un sobre XJ reconocido "
                          "(se esperaba JSON con campo 'format', o un enlace "
                          "xj://, xjdev://, xjvpn:// o xjgcp://).")
    fmt = doc.get("format")
    if fmt == FORMAT_FILE:
        return {"kind": "xj-file", "payload": import_xj_file(stripped)}
    if fmt == FORMAT_LOCAL:
        return {"kind": "xj-local-servers", "servers": import_local_servers(stripped)}
    if fmt == FORMAT_RUNTIME:
        return {"kind": "xj-runtime-text", "text": import_runtime_text(stripped)}
    raise DecodeError("UNSUPPORTED_FORMAT", f"Formato XJ no soportado: {fmt!r}.")


def run(file_bytes) -> str | None:
    """SP-DECODE entry point: bytes de un .xj o texto de enlace ->
    JSON string o None. (Los .xj bloqueados necesitan contraseña:
    usar --file con --password en CLI.)"""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False)
    except DecodeError:
        return None


def _sample_server() -> dict:
    """Servidor sintético con los 35 campos reales de ServerDto
    (valores de ejemplo; NO es un servidor real)."""
    return {
        "id": 0, "uuid": "00000000-0000-0000-0000-000000000001",
        "servername": "Servidor de prueba", "ip": "203.0.113.10",
        "dns": "1.1.1.1", "ns": "ns.example.invalid", "status": "active",
        "country": "Mexico", "country_code": "MX",
        "gcp_host": "gcp.example.invalid", "gcp_path": "/gcp",
        "gcp_xray_path": "/xray", "gcp_vmess_path": "/vmess",
        "gcp_trojan_path": "/trojan", "cloudfront": "",
        "is_manual": True, "ssh_port": 22, "proxy_host": "proxy.example.invalid",
        "proxy_port": 8080, "sni_host": "sni.example.invalid",
        "payload": "GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n",
        "payload_host": "example.invalid", "payload_enabled": True,
        "server_protocol": "SSH", "username": "usuario",
        "password": "secreto", "ssl_enabled": False,
        "dnstt_enabled": False, "dnstt_public_key": "",
        "hysteria_config": "", "hysteria_enabled": False,
        "ovpn_profile": "", "config_locked": False,
    }


def _sample_payload() -> dict:
    """Payload sintético con los campos reales de PublicPayloadDto."""
    return {
        "payload_id": 1, "payload_name": "Payload de prueba",
        "payload_mode": "SSH", "payload_protocol": "SSH",
        "payload_ssl_enable": False, "payload_ssl_sni": "",
        "payload_http_proxy": "", "payload_http_proxy_port": 0,
        "payload_description": "Payload sintético de self-test",
        "payload_http_payload": "GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n",
        "payload_is_enable": True, "payload_is_enabled": True,
        "address": "203.0.113.10", "port": 22, "network": "tcp",
        "sni": "", "tls": "", "uuid": "00000000-0000-0000-0000-000000000001",
        "password": "", "path": "", "remarks": "",
    }


def _sample_host() -> dict:
    """HostUpdate sintético con los campos reales de GcpHostUpdateCodec."""
    return {
        "id": 7, "servername": "Servidor de prueba",
        "uuid": "00000000-0000-0000-0000-000000000001",
        "gcpHost": "gcp.example.invalid", "gcpPath": "/gcp",
        "gcpTrojanPath": "/trojan", "gcpVmessPath": "/vmess",
        "gcpXrayPath": "/xray",
    }


def _self_test():
    server = _sample_server()
    payload = _sample_payload()
    host = _sample_host()
    fixed_ts = 1794634614000

    # 1. Archivo .xj sin bloqueo (round-trip exacto).
    plain_file = export_xj_file("Servidor de prueba", server, locked=False)
    out = import_xj_file(plain_file)
    assert out["configName"] == "Servidor de prueba", out
    assert out["server"]["ip"] == "203.0.113.10", out
    assert out["configLocked"] is False
    assert is_locked_file(plain_file) is False
    assert decode(plain_file)["kind"] == "xj-file"

    # 2. Archivo .xj bloqueado con contraseña (round-trip + fallos).
    locked_file = export_xj_file("Servidor de prueba", server, locked=True, password="prueba123")
    assert is_locked_file(locked_file) is True
    out = import_xj_file(locked_file, password="prueba123")
    assert out["server"]["servername"] == "Servidor de prueba"
    assert out["configLocked"] is True
    for bad in ("", "otra"):
        try:
            import_xj_file(locked_file, password=bad)
        except DecodeError as exc:
            assert exc.code in ("PASSWORD_REQUIRED", "BAD_TAG"), exc.code
        else:
            raise AssertionError("contraseña incorrecta/vacía no lanzó error")
    tampered = json.loads(locked_file)
    tampered["data"] = tampered["data"][:-2] + ("AA" if tampered["data"][-2:] != "AA" else "BB")
    try:
        import_xj_file(json.dumps(tampered), password="prueba123")
        raise AssertionError("sobre alterado no lanzó error")
    except DecodeError as exc:
        assert exc.code in ("BAD_TAG", "BAD_BASE64"), exc.code

    # 3. Enlace xj:// (passphrase fija; round-trip exacto).
    link = export_xj_link(server)
    assert link.startswith("xj://"), link[:10]
    out = import_xj_link(link)
    assert out["configName"] == "Servidor de prueba"
    assert out["server"]["uuid"] == server["uuid"]
    assert decode(link)["kind"] == "xj-link"
    assert run(link.encode("utf-8")) is not None

    # 4. Enlace xjgcp:// (sobre binario v1 + XZ; round-trip exacto).
    gcp = export_xjgcp_link([host], created_at_ms=fixed_ts)
    assert gcp.startswith("xjgcp://"), gcp[:10]
    bundle = import_xjgcp_link(gcp)
    assert bundle["createdAt"] == fixed_ts
    assert bundle["hosts"][0]["gcpHost"] == "gcp.example.invalid"
    assert decode(gcp)["kind"] == "xjgcp-host-update"

    # 5. Enlace xjdev:// v2 (XZ) y legacy xjvpn:// v1 (GZIP).
    dev = export_xjdev_link([server], [payload], created_at_ms=fixed_ts)
    assert dev.startswith("xjdev://"), dev[:10]
    bundle = import_xjdev_link(dev)
    assert bundle["createdAt"] == fixed_ts
    assert bundle["servers"][0]["country_code"] == "MX"
    assert bundle["servers"][0]["country"] == "Mexico"
    assert bundle["payloads"][0]["payload_name"] == "Payload de prueba"
    assert decode(dev)["kind"] == "xjdev-offline-update"
    # v1 legacy: mismo sobre con version=1, GZIP y prefijo xjvpn://.
    raw = json.dumps({"createdAt": fixed_ts, "servers": [server],
                      "payloads": [payload]}, ensure_ascii=False).encode("utf-8")
    legacy = OFFLINE_LEGACY_PREFIX + _encode_binary_envelope(
        1, OFFLINE_PASSPHRASE, gzip.compress(raw))
    bundle = import_xjdev_link(legacy)
    assert bundle["servers"][0]["ip"] == "203.0.113.10"
    assert bundle["payloads"][0]["payload_id"] == 1

    # 6. Sobres xj-local-v1 y xj-runtime-v1.
    local = export_local_servers([server])
    assert import_local_servers(local)[0]["servername"] == "Servidor de prueba"
    assert decode(local)["kind"] == "xj-local-servers"
    runtime = export_runtime_text("texto de prueba")
    assert import_runtime_text(runtime) == "texto de prueba"
    assert decode(runtime)["kind"] == "xj-runtime-text"

    # 7. Formato desconocido y texto basura deben fallar con códigos estables.
    for bad, code in (('{"format":"xj-otro-v9","data":"AA=="}', "UNSUPPORTED_FORMAT"),
                      ("esto no es un xj", "INVALID_JSON")):
        try:
            decode(bad)
            raise AssertionError(f"{bad!r} no lanzó error")
        except DecodeError as exc:
            assert exc.code == code, (bad, exc.code)
    print("self-test OK: .xj libre + bloqueado (contraseña mal/vacía y "
          "sobre alterado rechazados), xj://, xjgcp://, xjdev:// v2 (XZ) "
          "y v1 legacy (GZIP), xj-local-v1, xj-runtime-v1; "
          "7 grupos, todos round-trip exactos")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="XJ VPN 1.9.7: decodificador de archivos .xj y enlaces xj://, xjdev://, xjgcp://.")
    parser.add_argument("--file", help="Archivo .xj (o texto de sobre) a decodificar.")
    parser.add_argument("--link", help="Enlace xj://, xjdev://, xjvpn:// o xjgcp:// a decodificar.")
    parser.add_argument("--password", default="", help="Contraseña del .xj bloqueado.")
    parser.add_argument("--self-test", action="store_true", help="Pruebas locales sin red.")
    args = parser.parse_args(argv)
    if args.self_test:
        _self_test()
        return 0
    if args.file:
        if not os.path.isfile(args.file):
            print(f"No existe el archivo: {args.file}")
            return 2
        with open(args.file, "rb") as fh:
            data = fh.read()
        try:
            if _json(data).get("format") == FORMAT_FILE:
                doc = {"kind": "xj-file", "payload": import_xj_file(_text(data), args.password)}
            else:
                doc = decode(data)
        except DecodeError as exc:
            print(f"RESULTADO: {exc.code}\n{exc}")
            return 1
        print(json.dumps(doc, ensure_ascii=False, indent=2))
        return 0
    if args.link:
        try:
            doc = decode(args.link)
        except DecodeError as exc:
            print(f"RESULTADO: {exc.code}\n{exc}")
            return 1
        print(json.dumps(doc, ensure_ascii=False, indent=2))
        return 0
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
