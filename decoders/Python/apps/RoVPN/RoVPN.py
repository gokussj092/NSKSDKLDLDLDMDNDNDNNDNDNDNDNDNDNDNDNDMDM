#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RoVPN (com.mobileapp.rovpn, 7.6) — catálogo, archivos profile.json y esquemas de texto.

App: **RoVPN**, paquete `com.mobileapp.rovpn`, versionCode **76**,
versionName `7.6`, minSdk 32. APK analizado: XAPK de APKPure con la versión
de Google Play (7.6), SHA-256 del XAPK
`d41033a0e676d9cb000da78ad0a8820ae4914df6469aaf1c250e4b6955fa2a4f`.
Fecha de trabajo: 2026-11-13. Alcance: **catálogo + archivos profile.json
+ esquemas de texto**, desde cero — el repo SP-DECODE (rama
`feat/nuevas-integraciones`) no tiene cobertura de RoVPN (86 carpetas de
apps, ninguna RoVPN; es un fork de v2rayNG). No se modificó el repo
SP-DECODE ni se subió nada a Git. No se guardan ni se imprimen en este
documento valores descifrados, contraseñas, claves de usuario ni datos
sensibles: solo recuentos, hashes y estructura.

## Método exacto del catálogo

### Descarga

- **Endpoint activo:** `https://iovpn.me/app/config/rooojshsh727272h3n.php`
  (GET). Es una URL fija sin parámetros, sin token de ruta. Es el valor
  por defecto de la preferencia `key_url`, sembrado por `ro3` (MainApplication)
  solo cuando `xe1.b()` verifica la firma del APK: lee `/proc/self/maps`,
  toma la ruta real de `base.apk` y comprueba que su SHA-256 esté en la
  lista de dos hashes permitidos de la app (anti-tamper). Si el usuario
  cambia `key_url`, la app descarga de esa URL en su lugar.
- **Dónde vive la URL en el APK:** `ro3.<init>` escribe `key_url` =
  `ku2.n(-34070443699437L)` y `key_secured` = `ku2.n(-27761136741613L)`
  (cadenas LSParanoid resueltas con el deobfuscator de referencia).
  `nq0` (update check, desde MainActivity.onCreate) lee `key_url` y hace
  el GET con OkHttp (`gg0`: timeouts 5 s + 5 s, sin cabeceras propias,
  User-Agent por defecto de OkHttp).
- **Petición replicada:** GET plano, cabeceras `User-Agent: okhttp/4.12.0`,
  `Accept-Encoding: identity`, `Connection: keep-alive`. **Sin User-Agent
  de OkHttp el endpoint responde 403** (verificado: el User-Agent por
  defecto de Python-urllib da 403). Sin autenticación, token ni firma.
- **Incidencia de red (igual que Fat Tunnel):** el endpoint responde con
  `Transfer-Encoding: chunked` y sin Content-Length; `urllib` añade
  `Connection: close` y la descarga se corta a mitad (18.791 bytes de
  54.128, determinista) a través del proxy de salida de esta máquina.
  `fetch_catalog` usa `http.client` directamente y nunca envía
  `Connection: close`; un cuerpo truncado se reintenta con un GET nuevo
  (hasta 6 intentos) y el tag GCM de `decode()` es lo que prueba que un
  cuerpo está completo. El servidor **no** acepta `Range` (416).

### Descifrado de la respuesta

Es Google Tink **AesGcmHkdfStreaming** (clases `x5`/`w5`/`gg1`/`dk1`
en el DEX, sin ofuscar el nombre del algoritmo):

1. **Base64 estándar** del cuerpo completo (54.128 B en la prueba viva).
2. Cabecera de 40 bytes: byte 0 = 40 (tamaño de cabecera), bytes 1..32 =
   salt aleatoria, bytes 33..39 = noncePrefix aleatorio (7 bytes).
3. IKM = **PBKDF2-HmacSHA256** (contraseña de formato `key_secured`,
   salt UTF-8 `MY_APP_FIXED_SALT_V1`, 100.000 iteraciones, 32 bytes).
4. Clave de segmento = **HKDF-SHA256** (ikm, salt de cabecera,
   info = `MY_SECURE_JSON_STREAM_V1`, 32 bytes).
5. Segmentos: el primer segmento de cifrado mide 4.056 bytes
   (4.096 - 40 de cabecera) y los siguientes 4.096; cada uno es
   **AES-256-GCM** con nonce = noncePrefix || nº de segmento (BE32) ||
   flag último (1 byte), sin AAD, tag de 16 bytes. Segmento de texto
   plano: 4.040 bytes el primero, 4.080 los siguientes.
6. Resultado: **JSON UTF-8 completo** con `Version`, `Message`,
   `Servers[]`, `Networks[]` y `setOpenVPN` (config OpenVPN por defecto).

- La contraseña de formato `key_secured` es una constante de la app
  (no una credencial de usuario): `UED%tS^yeUXI{C=,i_Y#J5+Vb}uFnAz8;}7)n8)PaTOe97=.3%`.
- `nq0` compara `Version` con la preferencia `update` (por defecto
  `0.0`); si la remota es mayor, `tq0` importa el catálogo descifrado
  con `MainActivity.a0.b(...)` (ye1.b → Tink StreamingAead con clave
  maestra del Android Keystore → `profile.enc`), guarda la versión y
  muestra un diálogo con Version + Message.

### Valores `ED:`

Casi todos los campos de servidor y payload van con el prefijo `ED:` y
son **Base32 del texto plano UTF-8** (sin más cifrado): `ServerIP`,
`Cloudfront`, `Username`, `Password`, `Sni`, `ServerDNS`, `NameServer`,
`Payload`, `SquidProxy` y `setOpenVPN`. `decoded(doc)` devuelve el
catálogo con esos valores ya decodificados; `--decoded` lo imprime.

### Archivos

- **profile.json (legacy, importable):** `MainActivity.onCreate` lee
  `filesDir/profile.json` si existe, lo decodifica con Base64 propio
  (`aj2.c`, alfabeto estándar) y **XXTEA modificado** (`aj2.d`, delta
  `0x2E0BA747`, clave = primeros 16 bytes UTF-8 de `MainDetail.b()`),
  renombra claves (ver `RoVPN_archivos.py`), lo importa con el mismo
  `a0.b(...)` que el catálogo y **borra el archivo**. Sin muestra real
  de teléfono todavía; el round-trip sintético está verificado.
- **profile.enc (actual):** el catálogo importado se guarda cifrado con
  Tink StreamingAead y clave maestra del Android Keystore
  (`android-keystore://private_master_key`, AD =
  `MY_SECURE_JSON_STREAM_V1`): **no se puede abrir offline**.
- **Sin `.sks`** en el manifiesto ni en el DEX.

### Esquemas de texto

- **Ninguno propio.** Solo MAIN/LAUNCHER + Firebase messaging + servicios
  VPN en el manifiesto; la única acción VIEW está dentro de `<queries>`,
  no es una activity. Solo los estándares vmess://, vless://, ss:// y
  trojan:// (import de v2rayNG). `MainDetail.a()` y `c()` exponen otras
  dos URLs (`https://iovpn.me/app/config/hg77hsushshss.php` y
  `https://iovpn.me/app/v2ovpn/ping.json`) pero **ninguna tiene llamadores
  desde Java**: la primera devuelve 404 y la segunda es solo una lista
  de ping de 4 servidores TH (g18/g7/g5/g4.drm.ac.th, puerto 82), no el
  catálogo.

## Prueba viva 2026-11-13 (este script, --url, GET exacto)

HTTP 200, cuerpo 54.128 B, descifrado completo (10 segmentos GCM):
**Version 46.1**, Message ` Up`, **12 servidores** (todos libres, sin
marca premium) y **23 payloads** (Networks): 1 OpenVPN directo
(d1.rovpn.uk), 5 Default (f1–f5.rovpn.uk + home.rovpn.uk), 2 UDP
(u1/u2.rovpn.uk), 3 SLOW (IPs 119.10.142.150, 43.249.33.11,
119.10.136.127); payloads HTTP Proxy / Cloudfront (21 con texto),
2 SlowDNS (SSH, sin payload) y 1 Direct + 1 UDP Hysteria (sin payload).
Usuario/contraseña compartidos del catálogo: mnbv / xxxxx (en claro
tras el Base32). El cuerpo vivo completo va adjunto como
`catalog_sample.b64` para `--self-test` / `--asset`.

## Pendiente

- Un `profile.json` real exportado del teléfono para la confirmación
  end-to-end del decodificador legacy (el round-trip sintético pasa).
- Si el proveedor rota `key_secured` o cambia el endpoint, el script
  dejará de abrir el catálogo vivo y lo reportará como
  LIVE_DECRYPT_FAILED / DOWNLOAD_FAILED, sin inventar servidores.

Pure-Python AES-256-GCM implementado aquí en la stdlib (núcleo copiado
de `Fat_Tunnel_Lite.py`, verificado contra `cryptography` y contra un
vector NIST); un descifrado completo tarda ~1-2 s en esta máquina.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import struct
import sys
from http.client import HTTPException, HTTPSConnection, IncompleteRead
from pathlib import Path
from urllib.parse import urlsplit

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000

# Constantes de formato de la app (no credenciales de usuario).
CATALOG_URL = "https://iovpn.me/app/config/rooojshsh727272h3n.php"
CATALOG_PASSWORD = "UED%tS^yeUXI{C=,i_Y#J5+Vb}uFnAz8;}7)n8)PaTOe97=.3%"  # key_secured
PBKDF2_SALT = b"MY_APP_FIXED_SALT_V1"
STREAM_AD = b"MY_SECURE_JSON_STREAM_V1"
USER_AGENT = "okhttp/4.12.0"  # User-Agent por defecto de OkHttp; sin él el endpoint da 403.
LIST_FIELDS = ("Servers", "Networks")
BUNDLED_ASSET = "catalog_sample.b64"


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _text(data: bytes | str) -> str:
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "Se esperaba texto o bytes UTF-8.")
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    try:
        value = data.decode("utf-8-sig") if isinstance(data, bytes) else data.removeprefix("\ufeff")
    except UnicodeDecodeError as exc:
        raise DecodeError("FORMAT_ERROR", "La entrada no es texto UTF-8.") from exc
    if len(value.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    return value


def _base64(text: str) -> bytes:
    try:
        return base64.b64decode("".join(text.split()), validate=False)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("FORMAT_ERROR", "La entrada no es Base64 válido.") from exc


def _json(data: bytes) -> dict:
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError("FORMAT_ERROR", "El contenido descifrado no es JSON UTF-8.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El catálogo descifrado no es un objeto JSON.")
    return doc


def _nonfinite(_value):
    return False


# ------------------------------------------------------------- AES-256-GCM
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
    """AES-256-GCM decrypt (pure stdlib). nonce: 12 bytes."""
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
    """AES-256-GCM encrypt (pure stdlib). Returns (ciphertext, tag)."""
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


# ------------------------------------------------- Tink AesGcmHkdfStreaming
def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 (RFC 5869)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _tink_decrypt_stream(raw: bytes) -> bytes:
    """Descifra un cuerpo Tink AesGcmHkdfStreaming (ver docstring del módulo).

    Cabecera de 40 bytes: [40][salt 32][noncePrefix 7]; segmentos de
    cifrado de 4.056 bytes el primero y 4.096 los siguientes; nonce por
    segmento = noncePrefix || nº BE32 || flag último.
    """
    if len(raw) < 40 + 16:
        raise DecodeError("TRUNCATED", "El cuerpo es demasiado corto para el formato Tink.")
    if raw[0] != 40:
        raise DecodeError("FORMAT_ERROR", "La cabecera Tink no empieza con el tamaño 40.")
    salt, nonce_prefix = raw[1:33], raw[33:40]
    ikm = hashlib.pbkdf2_hmac("sha256", CATALOG_PASSWORD.encode("utf-8"),
                              PBKDF2_SALT, 100000, 32)
    key = _hkdf_sha256(ikm, salt, STREAM_AD, 32)
    ct = raw[40:]
    chunks, pos, first = [], 0, True
    while pos < len(ct):
        cap = 4056 if first else 4096
        first = False
        chunks.append(ct[pos:pos + cap])
        pos += cap
    plain = bytearray()
    for index, chunk in enumerate(chunks):
        last = index == len(chunks) - 1
        nonce = nonce_prefix + index.to_bytes(4, "big") + (b"\x01" if last else b"\x00")
        try:
            plain += _aes_gcm_decrypt(key, nonce, chunk[:-16], chunk[-16:])
        except ValueError as exc:
            raise DecodeError("DECRYPT_FAILED", "La autenticación GCM falló.") from exc
    return bytes(plain)


def _tink_encrypt_stream(plaintext: bytes, *, salt: bytes | None = None,
                         nonce_prefix: bytes | None = None) -> bytes:
    """Inverso de _tink_decrypt_stream (solo para --self-test)."""
    salt = salt if salt is not None else os.urandom(32)
    nonce_prefix = nonce_prefix if nonce_prefix is not None else os.urandom(7)
    ikm = hashlib.pbkdf2_hmac("sha256", CATALOG_PASSWORD.encode("utf-8"),
                              PBKDF2_SALT, 100000, 32)
    key = _hkdf_sha256(ikm, salt, STREAM_AD, 32)
    capacities = [4040] + [4080] * ((len(plaintext) + 4079) // 4080)
    chunks, pos, index = [], 0, 0
    while pos < len(plaintext) or index == 0:
        cap = capacities[index] if index < len(capacities) else 4080
        piece = plaintext[pos:pos + cap]
        pos += len(piece)
        last = pos >= len(plaintext)
        nonce = nonce_prefix + index.to_bytes(4, "big") + (b"\x01" if last else b"\x00")
        ciphertext, tag = _aes_gcm_encrypt(key, nonce, piece)
        chunks.append(ciphertext + tag)
        index += 1
        if last:
            break
    return bytes([40]) + salt + nonce_prefix + b"".join(chunks)


def decrypt_catalog_bytes(data: bytes | str) -> bytes:
    """Base64 -> Tink AesGcmHkdfStreaming -> JSON bytes (ver docstring)."""
    return _tink_decrypt_stream(_base64(_text(data)))


def _catalog_json(data) -> dict:
    doc = _json(data)
    if not any(field in doc for field in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "No hay listas de servidores o payloads en el catálogo.")
    for field in LIST_FIELDS:
        if field in doc and (not isinstance(doc[field], list)
                             or any(not isinstance(v, dict) for v in doc[field])):
            raise DecodeError("WRONG_DOCUMENT", "Las listas de catálogo deben contener objetos completos.")
    return doc


def decode(data: bytes | str) -> dict:
    """Offline API: descifra el catálogo completo y devuelve su JSON."""
    return _catalog_json(decrypt_catalog_bytes(data))


def _ed_decode(value):
    """Decodifica un valor `ED:` (Base32 del texto plano UTF-8)."""
    if isinstance(value, str) and value.startswith("ED:"):
        try:
            return base64.b32decode(value[3:]).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return value
    return value


_ED_FIELDS = ("ServerIP", "Cloudfront", "Username", "Password", "Sni",
              "ServerDNS", "NameServer", "Payload", "SquidProxy", "setOpenVPN")


def decoded(doc: dict) -> dict:
    """Copia del catálogo con los valores `ED:` ya decodificados."""
    out = dict(doc)
    for field in LIST_FIELDS:
        items = doc.get(field)
        if isinstance(items, list):
            out[field] = [{k: _ed_decode(v) if k in _ED_FIELDS else v
                           for k, v in item.items()} for item in items]
    out["setOpenVPN"] = _ed_decode(doc.get("setOpenVPN", ""))
    return out


def run(file_bytes: bytes | str) -> str | None:
    """Offline API: JSON completo del catálogo o None; nunca una lista parcial."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


def summary(doc: dict) -> dict:
    """Recuentos y versión; nunca reproduce valores descifrados."""
    out = {"Version": doc.get("Version"), "Message": doc.get("Message")}
    for field in LIST_FIELDS:
        value = doc.get(field)
        out[field] = len(value) if isinstance(value, list) else None
    out["sections"] = sorted(doc.keys())
    return out


def _https_url(url: str):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment):
        raise ValueError("invalid HTTPS URL")
    return parsed


def _proxy_env():
    """(host, port, auth_header) desde https_proxy/HTTPS_PROXY, o None.

    Las credenciales del proxy rotan; se leen del entorno en cada
    llamada, nunca se guardan.
    """
    raw = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY") or ""
    match = re.match(r"^https?://(?:([^:@]+):([^@]*)@)?([^:/]+):(\d+)", raw)
    if not match:
        return None
    user, password, host, port = match.groups()
    auth = None
    if user is not None:
        auth = "Basic " + base64.b64encode(
            f"{user}:{password or ''}".encode("utf-8")).decode("ascii")
    return host, int(port), auth


class _Redirect(Exception):
    def __init__(self, location):
        super().__init__("redirect")
        self.location = location


class _Truncated(Exception):
    def __init__(self, partial: bytes):
        super().__init__("download truncated")
        self.partial = partial


def _one_get(url, parsed):
    """Un GET con http.client (nunca urllib: urllib añade
    'Connection: close', que corta este endpoint chunked a través del
    proxy de salida de esta máquina). Devuelve el cuerpo completo.
    """
    proxy = _proxy_env()
    if proxy is not None:
        phost, pport, pauth = proxy
        conn = HTTPSConnection(phost, pport, timeout=60)
        tunnel_headers = {"Proxy-Authorization": pauth} if pauth else {}
        conn.set_tunnel(parsed.hostname, parsed.port or 443, tunnel_headers)
    else:
        conn = HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=60)
    try:
        conn.putrequest("GET", parsed.path or "/")
        conn.putheader("User-Agent", USER_AGENT)
        conn.putheader("Accept-Encoding", "identity")
        conn.putheader("Connection", "keep-alive")
        conn.endheaders()
        resp = conn.getresponse()
        if resp.status in (301, 302, 303, 307, 308):
            location = resp.getheader("Location")
            resp.read()
            if not location:
                raise DecodeError("DOWNLOAD_FAILED", "Redirección sin destino.")
            raise _Redirect(location)
        if resp.status != 200:
            resp.read()
            raise DecodeError("DOWNLOAD_FAILED", "El endpoint no devolvió 200.")
        try:
            data = resp.read()
        except IncompleteRead as exc:
            raise _Truncated(exc.partial or b"") from exc
        if len(data) > MAX_BYTES:
            raise DecodeError("SIZE_LIMIT", "La respuesta supera el límite de tamaño.")
        return data
    except (DecodeError, _Redirect, _Truncated):
        raise
    except (HTTPException, OSError, ValueError) as exc:
        raise DecodeError("DOWNLOAD_FAILED", "No se pudo descargar el catálogo mediante HTTPS.") from exc
    finally:
        conn.close()


def fetch_catalog(url: str = CATALOG_URL) -> bytes:
    """GET plano exactamente como lo hace la app (User-Agent de OkHttp).

    El servidor responde el cuerpo completo en una respuesta e ignora
    Range, así que no hay reanudación. Un cuerpo truncado se reintenta
    con un GET nuevo (hasta 6 intentos); el tag GCM de decode() es lo
    que prueba que un cuerpo está completo.
    """
    current = url
    for _attempt in range(6):
        _https_url(current)
        try:
            body = _one_get(current, _https_url(current))
        except _Redirect as exc:
            current = exc.location
            continue
        except _Truncated:
            continue
        try:
            decode(body)
        except DecodeError:
            continue
        return body
    raise DecodeError("DOWNLOAD_TRUNCATED", "La descarga se cortó y no se pudo completar.")


def _bundled_asset() -> bytes:
    path = Path(__file__).resolve().parent / BUNDLED_ASSET
    try:
        return path.read_bytes()
    except OSError as exc:
        raise DecodeError("ASSET_MISSING", "No se encontró el catálogo de muestra adjunto.") from exc


def _read_file(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def _write_output(path: Path, rendered: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, rendered.encode("utf-8"))
    finally:
        os.close(fd)


def _self_test() -> int:
    """Round-trip sintético + cuerpo vivo adjunto; no usa archivos reales ni red.

    Casos: 1. Vector NIST AES-256-GCM. 2. Round-trip Tink de un catálogo
    sintético (cifrar -> descifrar). 3. El cuerpo vivo adjunto
    (`catalog_sample.b64`) abre y tiene Servers/Networks. 4. Un tag GCM
    alterado se rechaza (DECRYPT_FAILED). 5. Valores `ED:` se decodifican.
    """
    cases = []

    def check(name, ok):
        cases.append(ok)
        print(f"  [{'OK' if ok else 'FAIL'}] {name}")

    print("RoVPN self-test:")
    try:
        pt = _aes_gcm_decrypt(bytes(32), bytes(12),
                              bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18"),
                              bytes.fromhex("d0d1c8a799996bf0265b98b5d48ab919"))
        check("vector NIST AES-256-GCM", pt == bytes(16))
    except ValueError:
        check("vector NIST AES-256-GCM", False)
    doc = {"Version": "9.99", "Message": "self-test",
           "Servers": [{"ServerName": "Test", "ServerIP": "ED:GEZDGNBV"}],
           "Networks": [{"PayloadName": "Test", "Payload": "ED:GEZDGNBV"}]}
    raw = json.dumps(doc, ensure_ascii=False).encode("utf-8")
    blob = base64.b64encode(_tink_encrypt_stream(raw)).decode("ascii")
    try:
        check("round-trip Tink (cifrar -> descifrar)", decode(blob) == doc)
    except DecodeError:
        check("round-trip Tink (cifrar -> descifrar)", False)
    try:
        live = decode(_bundled_asset())
        check("cuerpo vivo adjunto abre (Version/Servers/Networks)",
              isinstance(live.get("Version"), str)
              and isinstance(live.get("Servers"), list)
              and isinstance(live.get("Networks"), list))
    except DecodeError:
        check("cuerpo vivo adjunto abre (Version/Servers/Networks)", False)
    bad = bytearray(base64.b64decode(blob))
    bad[-1] ^= 0x01
    try:
        decode(base64.b64encode(bytes(bad)).decode("ascii"))
        check("tag GCM alterado rechazado", False)
    except DecodeError as exc:
        check("tag GCM alterado rechazado", exc.code == "DECRYPT_FAILED")
    check("valores ED: se decodifican",
          _ed_decode("ED:GEZDGNBV") == "12345"
          and _ed_decode("sin prefijo") == "sin prefijo")
    passed = sum(cases)
    print(json.dumps({"self_test": "pass" if passed == len(cases) else "fail",
                      "passed": passed, "total": len(cases)}, ensure_ascii=False))
    return 0 if passed == len(cases) else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, help="Respuesta del catálogo guardada localmente")
    source.add_argument("--url", nargs="?", const=CATALOG_URL,
                        help="Descarga explícita; por defecto usa el endpoint original")
    source.add_argument("--asset", action="store_true",
                        help="Usa el cuerpo vivo adjunto (catalog_sample.b64)")
    source.add_argument("--stdin", action="store_true", help="Lee la respuesta cifrada desde stdin")
    source.add_argument("--self-test", action="store_true",
                        help="Round-trip sintético + cuerpo adjunto; no usa archivos reales ni red")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; no sobrescribe")
    parser.add_argument("--summary", action="store_true",
                        help="Solo recuentos (versión y tamaños de lista), sin valores descifrados")
    parser.add_argument("--decoded", action="store_true",
                        help="Imprime el catálogo con los valores ED: ya decodificados")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    try:
        if args.url is not None:
            raw = fetch_catalog(args.url)
        elif args.asset:
            raw = _bundled_asset()
        elif args.stdin:
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
        else:
            raw = _read_file(args.file)
        doc = decode(raw)
        if args.summary:
            rendered = json.dumps(summary(doc), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        elif args.decoded:
            rendered = json.dumps(decoded(doc), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        else:
            rendered = json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            _write_output(args.output, rendered)
        else:
            sys.stdout.write(rendered)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
