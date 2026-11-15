#!/usr/bin/env python3
"""V2OVPN 2.2.3: catalog decoder (Google Tink StreamingAead / AesGcmHkdfStreaming).

Python 3.10+, solo biblioteca estandar. AES-256-GCM, HKDF-SHA256 y
PBKDF2-HmacSHA256 estan implementados en Python puro en este archivo
(el nucleo AES-GCM es el mismo de Fat_Tunnel_Lite.py, verificado contra
PyCryptodome y contra vectores NIST; el HKDF sigue RFC 5869).
Package com.v2rayservice.v2ovpn, versionCode 63, versionName 2.2.3,
minSdk 32. El APK es la version publica de Google Play (2.2.3); se
descargo de APKPure porque APKMirror no tenia listado. Sin cobertura
previa en el repo de SP-DECODE (86 carpetas revisadas; V2ray_Tunnel_Plus
es otra app).

Catalogo (Lwg0.a, Lyh1, Lu5/Ls51/Le80/Lnh, libreria nativa
libapi-v2ovpn.so solo para los endpoints viejos):

  GET https://iovpn.me/app/config/rooojshsh727272h3n.php
  (GET con User-Agent okhttp/4.12.0, sin autenticacion; el User-Agent
  por defecto de Python-urllib recibe 403 de Cloudflare. El cuerpo es
  una sola linea de Base64, 54128 B en vivo el 2026-11-13. En este
  entorno la descarga va por el proxy de salida con un tunel CONNECT
  explicito (http.client set_tunnel): urllib trunca la respuesta
  chunked a 18791 B, el primer chunk, mientras que el tunel explicito
  devuelve el cuerpo completo. Sin proxy en el entorno se usa
  conexion directa.)

  El cuerpo Base64 decodifica a un flujo Tink StreamingAead:
    byte 0            = longitud de la cabecera (40)
    bytes 1..32       = salt de 32 B (HKDF)
    bytes 33..39      = prefijo de nonce de 7 B
    resto             = segmentos cifrados AES-256-GCM (sin AAD)

  Clave:
    IKM = PBKDF2-HmacSHA256(password = key_secured, salt =
          b"MY_APP_FIXED_SALT_V1", 100000 iteraciones, 32 B)
      key_secured = "UED%tS^yeUXI{C=,i_Y#J5+Vb}uFnAz8;}7)n8)PaTOe97=.3%"
      (constante de la app, guardada en EncryptedSharedPreferences
      como key_secured junto a key_url; es la misma en cada instalacion)
    key = HKDF-SHA256(IKM, salt = salt de la cabecera,
                      info = b"MY_SECURE_JSON_STREAM_V1", 32 B)

  Segmentos (la primera lectura del flujo consume la cabecera de 40 B,
  asi que el primer segmento cifrado es 40 B mas corto):
    segmento 0 : 4056 B cifrados (4040 texto + 16 tag)
    segmentos 1..n-2 : 4096 B cifrados (4080 texto + 16 tag)
    ultimo segmento : el resto (texto + 16 tag)
    nonce por segmento = prefijo(7) || BE32(indice) || (0x01 si es el
    ultimo, 0x00 si no). AES-256-GCM, sin AAD. Todos los tags se
    verifican; si uno falla, el catalogo no abre (LIVE_DECRYPT_FAILED).

  El texto plano es un JSON: {Version, Message, Servers[], Networks[],
  setOpenVPN}. Los campos sensibles llevan el prefijo "ED:" y son
  Base32 del valor en claro (ServerIP -> nombre de host, Username,
  Password, Payload -> plantilla HTTP, setOpenVPN -> configuracion
  OpenVPN completa con certificado CA, Cloudfront, UDPConfig,
  NameServer, PublicKey, ServerDNS, SquidProxy). Este script los
  decodifica y devuelve el JSON con los valores en claro.

LIVE STATUS (2026-11-13, verificado con --url): el endpoint responde
HTTP 200 (54128 B) y el catalogo abre: Version "46.1", Message " Up",
12 servidores (d1/f1-f5/home/u1/u2.rovpn.uk y 3 SlowDNS por IP; el
catalogo no marca premium/free/VIP en ningun campo: los 12 son libres)
y 23 redes (payloads). El descifrado completo tarda ~2 s en Python
puro (el PBKDF2 de 100000 iteraciones es en C via hashlib; el AES-GCM
puro es el resto). El cuerpo no ha cambiado entre las 22:08 y las
22:30 del 2026-11-13 (mismo SHA-256).

Endpoints secundarios (verificados en vivo):
  GET https://iovpn.me/app/v2ovpn/ping.json -> 200, lista de 4
  servidores TH (g18/g7/g5/g4.drm.ac.th, puerto 82). Esos 4 hosts ya
  no responden a :82/server/online_app.json (respuesta vacia).
  GET http://<host-del-catalogo>:82/server/online_app.json ->
  [{"onlines":"78","limite":"150"}] (verificado con d1.rovpn.uk).
  El endpoint viejo https://iovpn.me/app/config/hg77hsushshss.php
  (de libapi-v2ovpn.so) devuelve 404: esta muerto, no se usa.

Archivos de configuracion: profile.json en getFilesDir() es el
catalogo guardado con una segunda capa: el flujo Tink del catalogo
cifra una cadena Base64 del JSON con nombres antiguos, cifrado con
XXTEA modificado (delta 0x2E0BA747, clave = primeros 16 B UTF-8 de
MainDetail.b() = aZ%RU%itRMB^8&Ue). Ver V2OVPN_archivos.py, que lo
descifra y migra los nombres (Name->ServerName, Profiles->Networks,
etc.). profile.enc (Lm11) es otro flujo Tink pero con una clave de un
keyset Tink de la app, no reproducible sin el dispositivo. La app no
tiene formato propio de archivo de perfiles exportable (.ovpn es
texto plano y SP-DECODE ya lo cubre). Enlaces de texto: la app no
define esquema propio (no hay v2ovpn:// en el manifiesto ni en el
DEX); solo maneja los estandar vmess:// / vless:// / trojan:// /
ss://, que SP-DECODE ya cubre.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import http.client
import json
import re
import struct
import sys
import urllib.request
from pathlib import Path

CATALOG_URL = "https://iovpn.me/app/config/rooojshsh727272h3n.php"
PING_URL = "https://iovpn.me/app/v2ovpn/ping.json"
# La app es un fork de v2rayNG sobre OkHttp; el endpoint acepta este
# User-Agent y devuelve 403 al User-Agent por defecto de Python-urllib.
USER_AGENT = "okhttp/4.12.0"
KEY_SECURED = "UED%tS^yeUXI{C=,i_Y#J5+Vb}uFnAz8;}7)n8)PaTOe97=.3%"
FIXED_SALT = b"MY_APP_FIXED_SALT_V1"
STREAM_MAGIC = b"MY_SECURE_JSON_STREAM_V1"
PBKDF2_ITERATIONS = 100000
SEGMENT_SIZE = 4096
TAG_LEN = 16
MAX_BYTES = 8 * 1024 * 1024


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- AES-256-GCM (pure python, stdlib only)
# Nucleo reutilizado de Fat_Tunnel_Lite.py (verificado contra
# PyCryptodome, argon2-cffi/cryptography y vectores NIST).

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


# ---------------------------------------------------------------- HKDF-SHA256 (RFC 5869)

def _hkdf_sha256(ikm, salt, info, length=32):
    if salt is None:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


# ---------------------------------------------------------------- Tink StreamingAead

def _derive_key(header_salt):
    ikm = hashlib.pbkdf2_hmac("sha256", KEY_SECURED.encode("utf-8"),
                              FIXED_SALT, PBKDF2_ITERATIONS, 32)
    return _hkdf_sha256(ikm, header_salt, STREAM_MAGIC, 32)


def encrypt_stream(plain, header_salt=None, nonce_prefix=None):
    """Cifra un texto plano en un flujo Tink StreamingAead (el inverso
    de decrypt_stream). Solo se usa para construir archivos de prueba;
    la app no cifra con la clave fija fuera del dispositivo. Devuelve
    el flujo como bytes (sin Base64)."""
    import os as _os
    if header_salt is None:
        header_salt = _os.urandom(32)
    if nonce_prefix is None:
        nonce_prefix = _os.urandom(7)
    key = _derive_key(header_salt)
    header = bytes([40]) + header_salt + nonce_prefix
    body = bytearray()
    # segmento 0: 4040 B de texto; los siguientes: 4080 B
    first = plain[:4040]
    rest = plain[4040:]
    chunks = [first]
    while rest:
        chunks.append(rest[:4080])
        rest = rest[4080:]
    for idx, chunk in enumerate(chunks):
        is_last = idx == len(chunks) - 1
        nonce = nonce_prefix + struct.pack(">I", idx) + (b"\x01" if is_last else b"\x00")
        ct, tag = _aes_gcm_encrypt(key, nonce, chunk)
        body += ct + tag
    return header + bytes(body)


def decrypt_stream(data):
    """Descifra un flujo Tink StreamingAead (bytes ya decodificados de
    Base64) y devuelve el texto plano. Verifica todos los tags GCM."""
    if len(data) < 1 + 32 + 7 + TAG_LEN:
        raise DecodeError("FORMAT_ERROR", "Flujo demasiado corto.")
    header_len = data[0]
    if header_len < 40 or header_len > 64 or len(data) < header_len + TAG_LEN:
        raise DecodeError("FORMAT_ERROR", "Cabecera de flujo invalida.")
    header_salt = data[1:header_len - 7]
    nonce_prefix = data[header_len - 7:header_len]
    body = data[header_len:]
    key = _derive_key(header_salt)
    plain = bytearray()
    offset = 0
    index = 0
    first_len = SEGMENT_SIZE - header_len
    while offset < len(body):
        remaining = len(body) - offset
        if index == 0:
            seg_len = min(first_len, remaining)
        else:
            seg_len = min(SEGMENT_SIZE, remaining)
        if seg_len <= TAG_LEN:
            raise DecodeError("FORMAT_ERROR", "Segmento demasiado corto.")
        segment = body[offset:offset + seg_len]
        is_last = (offset + seg_len) >= len(body)
        nonce = nonce_prefix + struct.pack(">I", index) + (b"\x01" if is_last else b"\x00")
        try:
            plain += _aes_gcm_decrypt(key, nonce, segment[:-TAG_LEN], segment[-TAG_LEN:])
        except ValueError as exc:
            raise DecodeError("LIVE_DECRYPT_FAILED",
                              "El tag GCM del segmento %d no verifica; el catalogo "
                              "vivo no abre con la clave actual." % index) from exc
        offset += seg_len
        index += 1
    return bytes(plain)


def _as_stream_bytes(data):
    """Acepta el cuerpo Base64 (texto o bytes) o los bytes ya
    decodificados del flujo, y devuelve los bytes del flujo."""
    if isinstance(data, str):
        raw = data.encode("utf-8", "replace")
    else:
        raw = bytes(data)
    if len(raw) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el limite de tamano.")
    compact = re.sub(rb"[ \t\r\n]", b"", raw)
    candidates = []
    if compact:
        try:
            candidates.append(base64.b64decode(compact + b"=" * (-len(compact) % 4),
                                                validate=True))
        except (ValueError, binascii.Error):
            pass
    candidates.append(raw)
    for cand in candidates:
        if len(cand) >= 40 and 8 <= cand[0] <= 64 and len(cand) >= cand[0] + TAG_LEN:
            return cand
    raise DecodeError("FORMAT_ERROR",
                      "Se esperaba el cuerpo Base64 del catalogo o el flujo Tink.")


def _decode_ed(value):
    """Decodifica un campo 'ED:<Base32>' a su valor en claro; deja los
    demas valores tal cual."""
    if not isinstance(value, str) or not value.startswith("ED:"):
        return value
    body = value[3:]
    try:
        decoded = base64.b32decode(body + "=" * ((-len(body)) % 8))
    except (ValueError, binascii.Error):
        return value
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        return value


def _open_fields(doc):
    """Abre todos los campos ED: del catalogo (servidores, redes y el
    OpenVPN de nivel superior)."""
    for server in doc.get("Servers", []) or []:
        if isinstance(server, dict):
            for key in list(server.keys()):
                server[key] = _decode_ed(server[key])
    for network in doc.get("Networks", []) or []:
        if isinstance(network, dict):
            for key in list(network.keys()):
                network[key] = _decode_ed(network[key])
    if isinstance(doc.get("setOpenVPN"), str):
        doc["setOpenVPN"] = _decode_ed(doc["setOpenVPN"])
    return doc


def decode(data):
    """Descifra el catalogo (cuerpo Base64 o flujo) y devuelve el dict
    con los campos ED: ya abiertos. Acepta tambien JSON plano (por si el
    archivo guardado ya es texto)."""
    if isinstance(data, (bytes, str)):
        text = data.decode("utf-8-sig") if isinstance(data, bytes) else data
        stripped = text.strip()
        if stripped.startswith("{"):
            try:
                doc = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise DecodeError("FORMAT_ERROR", "JSON invalido.") from exc
            if not isinstance(doc, dict) or "Servers" not in doc:
                raise DecodeError("FORMAT_ERROR", "El JSON no es un catalogo V2OVPN.")
            return _open_fields(doc)
    stream = _as_stream_bytes(data)
    try:
        plain = decrypt_stream(stream)
    except DecodeError:
        raise
    except Exception as exc:
        raise DecodeError("FORMAT_ERROR", "No se pudo descifrar el flujo.") from exc
    try:
        doc = json.loads(plain.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError("FORMAT_ERROR", "El texto plano no es JSON.") from exc
    if not isinstance(doc, dict) or "Servers" not in doc:
        raise DecodeError("FORMAT_ERROR", "El texto plano no es un catalogo V2OVPN.")
    return _open_fields(doc)


def run(file_bytes):
    """Devuelve el catalogo decodificado como JSON (texto)."""
    doc = decode(file_bytes)
    return json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


# ---------------------------------------------------------------- descarga en vivo

def _https_url(url):
    if not isinstance(url, str) or not url.startswith("https://"):
        raise DecodeError("URL_ERROR", "Se esperaba una URL https://.")
    return url


def _proxy_env():
    """Devuelve (host, puerto, usuario, clave) del proxy HTTPS del
    entorno, o None si no hay proxy (entonces se usa conexion directa)."""
    import os
    from urllib.parse import urlparse
    raw = (os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
           or os.environ.get("all_proxy") or os.environ.get("ALL_PROXY"))
    if not raw:
        return None
    parsed = urlparse(raw)
    if not parsed.hostname or not parsed.port:
        return None
    return parsed.hostname, parsed.port, parsed.username, parsed.password


def _http_get(url, timeout=30):
    """GET via http.client. Con proxy en el entorno, usa un tunel CONNECT
    explicito (set_tunnel): urllib trunca la respuesta chunked de este
    endpoint a 18791 B (el primer chunk) mientras que el tunel explicito
    devuelve el cuerpo completo. Sin proxy, conexion directa. Devuelve
    (status, bytes)."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
    proxy = _proxy_env()
    no_proxy = __import__("os").environ.get("no_proxy", "") or ""
    if proxy and host not in [h.strip() for h in no_proxy.split(",") if h.strip()]:
        import ssl
        p_host, p_port, p_user, p_pass = proxy
        tunnel_headers = {}
        if p_user is not None:
            token = base64.b64encode(
                ("%s:%s" % (p_user, p_pass or "")).encode()).decode()
            tunnel_headers["Proxy-Authorization"] = "Basic " + token
        if parsed.scheme == "https":
            conn = http.client.HTTPSConnection(
                p_host, p_port, timeout=timeout,
                context=ssl.create_default_context())
            conn.set_tunnel(host, port, headers=tunnel_headers)
        else:
            conn = http.client.HTTPConnection(p_host, p_port, timeout=timeout)
            conn.set_tunnel(host, port, headers=tunnel_headers)
        try:
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            body = resp.read()
            return resp.status, body
        finally:
            conn.close()
    import urllib.request as _urlreq
    req = _urlreq.Request(url, method="GET", headers=headers)
    with _urlreq.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read()


def fetch_url(url, retries=4):
    """GET simple exactamente como lo acepta el endpoint (User-Agent de
    OkHttp, sin autenticacion; el User-Agent de Python-urllib recibe
    403 de Cloudflare). Reintenta el GET completo si la conexion se
    corta a mitad (no se usa Range: el servidor devuelve otra version
    del catalogo para las peticiones con Range)."""
    _https_url(url)
    last_error = None
    for attempt in range(max(1, retries)):
        try:
            status, raw = _http_get(url)
            if status != 200:
                raise DecodeError("ACCESS_DENIED" if status in (401, 403) else "DOWNLOAD_FAILED",
                                  "El endpoint devolvio HTTP %d." % status)
        except DecodeError:
            raise
        except (OSError, ValueError, http.client.HTTPException) as exc:
            last_error = exc
            if attempt + 1 < max(1, retries):
                import time
                time.sleep(1 + attempt)
            continue
        if not raw or len(raw) > MAX_BYTES or raw.lstrip().startswith(b"<"):
            raise DecodeError("DOWNLOAD_FAILED", "Catalogo vacio, incompatible o superior a 8 MiB.")
        return raw
    raise DecodeError("DOWNLOAD_FAILED", "No se pudo descargar el catalogo mediante HTTPS.") from last_error


def fetch_catalog(url=CATALOG_URL):
    """Descarga el catalogo en vivo y devuelve (catalogo, info)."""
    raw = fetch_url(url)
    doc = decode(raw)
    info = {
        "catalog_url": url,
        "version": doc.get("Version"),
        "message": doc.get("Message"),
        "servers": len(doc.get("Servers", []) or []),
        "networks": len(doc.get("Networks", []) or []),
        "bytes": len(raw),
    }
    return doc, info


def fetch_ping(url=PING_URL):
    """Descarga ping.json (lista de servidores TH con puerto 82)."""
    raw = fetch_url(url)
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError("FORMAT_ERROR", "ping.json no es JSON.") from exc
    if not isinstance(doc, list):
        raise DecodeError("FORMAT_ERROR", "ping.json no es una lista.")
    return doc


def fetch_online(host):
    """Consulta el estado en vivo de un servidor del catalogo:
    GET http://<host>:82/server/online_app.json."""
    url = "http://%s:82/server/online_app.json" % host
    last_error = None
    for attempt in range(3):
        try:
            status, raw = _http_get(url, timeout=20)
            if status != 200:
                raise OSError("unexpected HTTP status %d" % status)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            last_error = exc
            if attempt + 1 < 3:
                import time
                time.sleep(1 + attempt)
            continue
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DecodeError("FORMAT_ERROR", "online_app.json no es JSON.") from exc
        return doc
    raise DecodeError("DOWNLOAD_FAILED",
                      "No se pudo consultar %s." % url) from last_error


# ---------------------------------------------------------------- self-test

def _self_test():
    """Verifica la criptografia y el descifrado con datos sinteticos y
    con la captura real del catalogo (catalog_sample.b64)."""
    checks = {}
    # 1. AES-256-GCM contra el vector NIST (clave de 256 bits y nonce
    # cero, 16 B cero). El tag ab6e47d4... es el de la clave de 128
    # bits; con clave de 256 bits el tag es d0d1c8a7....
    key256 = bytes(32)
    ct, tag = _aes_gcm_encrypt(key256, bytes(12), bytes(16))
    checks["gcm_nist_zero"] = (
        ct.hex() == "cea7403d4d606b6e074ec5d3baf39d18"
        and tag.hex() == "d0d1c8a799996bf0265b98b5d48ab919")
    pt0 = _aes_gcm_decrypt(key256, bytes(12), ct, tag)
    checks["gcm_nist_zero_roundtrip"] = pt0 == bytes(16)
    # 2. HKDF-SHA256 contra RFC 5869, caso 1 (L=42).
    ikm = b"\x0b" * 22
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = _hkdf_sha256(ikm, salt, info, 42)
    checks["hkdf_rfc5869_case1"] = okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5"
        "bf34007208d5b887185865")
    # 3. PBKDF2-HmacSHA256 contra un vector conocido.
    dk = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 1, 32)
    checks["pbkdf2_sha256"] = dk.hex() == (
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
    # 4. Ida y vuelta de un flujo Tink sintetico (2 segmentos).
    sample_doc = {"Version": "99.9", "Message": "test",
                  "Servers": [{"ServerName": "TEST", "ServerIP": "ED:ORSXG5BOMV4GC3LQNRSQ===="}],
                  "Networks": [], "setOpenVPN": ""}
    plain = json.dumps(sample_doc, ensure_ascii=False).encode("utf-8")
    stream = encrypt_stream(plain, header_salt=bytes(range(32)),
                            nonce_prefix=bytes.fromhex("01020304050607"))
    encoded = base64.b64encode(stream).decode("ascii")
    opened = decode(encoded)
    checks["tink_roundtrip"] = (
        opened.get("Version") == "99.9"
        and opened["Servers"][0].get("ServerIP") == "test.example")
    checks["ed_base32"] = _decode_ed("ED:ORSXG5BOMV4GC3LQNRSQ====") == "test.example"
    # 5. Captura real del catalogo (2026-11-13, version 46.1).
    sample_path = Path(__file__).with_name("catalog_sample.b64")
    if sample_path.exists():
        raw = sample_path.read_bytes()
        doc = decode(raw)
        checks["live_sample_version"] = doc.get("Version") == "46.1"
        checks["live_sample_servers"] = len(doc.get("Servers", [])) == 12
        checks["live_sample_networks"] = len(doc.get("Networks", [])) == 23
        checks["live_sample_first_server"] = (
            doc["Servers"][0].get("ServerIP") == "d1.rovpn.uk")
    else:
        checks["live_sample_present"] = False
    return checks


# ---------------------------------------------------------------- CLI

def _read(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el limite de tamano.")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("file", nargs="?", type=Path,
                        help="Cuerpo cifrado guardado (Base64) o profile.json")
    source.add_argument("--url", nargs="?", const=CATALOG_URL,
                        help="Descarga el catalogo en vivo; por defecto usa el endpoint original")
    source.add_argument("--ping", action="store_true",
                        help="Descarga ping.json (servidores TH con puerto 82)")
    source.add_argument("--online", metavar="HOST",
                        help="Consulta :82/server/online_app.json de un servidor del catalogo")
    source.add_argument("--stdin", action="store_true",
                        help="Leer el cuerpo cifrado desde stdin")
    parser.add_argument("-o", "--output", type=Path,
                        help="Guardar JSON completo; por defecto stdout")
    parser.add_argument("--self-test", action="store_true",
                        help="Verifica AES-GCM, HKDF, PBKDF2, ida y vuelta Tink y la muestra real")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            result = _self_test()
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if all(result.values()) else 1
        if args.ping:
            doc = fetch_ping()
            rendered = json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
            if args.output:
                args.output.write_text(rendered, encoding="utf-8")
            else:
                sys.stdout.write(rendered)
            print(json.dumps({"ping_servers": len(doc)}, ensure_ascii=False),
                  file=sys.stderr)
            return 0
        if args.online:
            doc = fetch_online(args.online)
            rendered = json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
            if args.output:
                args.output.write_text(rendered, encoding="utf-8")
            else:
                sys.stdout.write(rendered)
            return 0
        if args.url is not None:
            doc, info = fetch_catalog(args.url)
            rendered = json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
            if args.output:
                args.output.write_text(rendered, encoding="utf-8")
            else:
                sys.stdout.write(rendered)
            print(json.dumps(info, ensure_ascii=False), file=sys.stderr)
            return 0
        if args.stdin:
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        elif args.file is not None:
            raw = _read(args.file)
        else:
            parser.error("se requiere un archivo, --url, --ping, --online o --stdin (o --self-test)")
        rendered = run(raw)
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False),
              file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
