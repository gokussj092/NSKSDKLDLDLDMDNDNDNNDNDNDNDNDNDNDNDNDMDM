#!/usr/bin/env python3
"""MinaProNet - AIO Tunnel VPN 88.0.0: catalogo, servidores publicos y nube.

Python 3.10+, solo biblioteca estandar. El AES-256-CBC y el PBKDF2 se
implementan en Python puro en este archivo (el AES fue verificado byte
a byte contra PyCryptodome con el catalogo real de la familia).
Package vpn.minapronet.com.eg, versionCode 88, versionName 88.0.0.
El APK es la version publica de Google Play (88.0.0); se descargo de
APKPure (XAPK arm64-v8a, SHA-1 verificado contra el publicado).

Esta app es DISTINTA de SLOW DNS (slowdns.minapronetvpn.com.eg, tanda 6):
mismo desarrollador (MinaProNet Dev), distinto paquete y distinta app.
El metodo de catalogo es de la misma familia (la funcion k() es
identica), pero se verifico de forma independiente en ESTE APK
(Manager.java: getter/dc/ecr/generateKey; libchzcore.so: xde/xec;
libminacore.so: nativeGetConfigUrl recuperada por emulacion con Unicorn).

Catalogo principal (dos etapas, Manager.getter + ConfigRepository):
  Etapa 1 -- indice:
    GET https://raw.githubusercontent.com/MinaDiNabil/update.link/refs/heads/main/minapronet.updater
    (GET simple, sin cabeceras propias ni autenticacion). El cuerpo se
    descifra con k(body, "m") y da el GettterConfig JSON:
    {ServerLink, ServerPassWD, appSecurity}.
  Etapa 2 -- catalogo real:
    server_pass = k(ServerPassWD, "m")
    catalog_url = k(ServerLink, server_pass)
    GET catalog_url (GET simple) y k(body, server_pass) da el MinaConfig
    JSON: {version, message, serversList[], networksList[]}.
  La URL del updater NO esta en el DEX: la construye el codigo nativo
  (MinaCore.nativeGetConfigUrl en libminacore.so) y se recupero
  emulando esa funcion con Unicorn.

La funcion k(input, password) (Manager.getter) es:
  1. Quitar 6 caracteres basura: los de las posiciones 5-7 y, del
     resultado, los de las posiciones 20-22.
  2. Base64-decodificar el resto (Android Base64, flag NO_WRAP).
  3. CHZCORE.ii() = el nativo xde(str, 0) de libchzcore.so:
       a. Base64-decodificar, b. invertir los bytes, c. ROT+20 letras.
     Su inversa es xec: ROT+6, reverse, Base64-codificar.
  4. dc(resultado, password) (Manager.dc):
     Base64-decodificar -> salt[0:16] || IV[16:32] || ct ->
     PBKDF2WithHmacSHA1(password, salt, 10000 iteraciones, clave de
     256 bits) -> AES/CBC/PKCS7Padding -> texto UTF-8 (JSON).

LIVE STATUS (2026-11-14, verificado con --url):
  El updater responde HTTP 200 pero con solo 14 bytes: "hello world..".
  El vendedor VACIO el updater: k() no puede abrirlo (demasiado corto).
  El respaldo de emergencia minapronet.json responde HTTP 404 en raw y
  en jsDelivr. La app hoy NO recibe ningun catalogo MinaConfig de la
  red y usa su configuracion local. Este script lo reporta como
  LIVE_UPDATER_EMPTY (resultado fallido honesto, no inventado).
  Comprobacion de que k() sigue funcionando: el psiphon_updater del
  mismo repositorio (4675 B) SI descifra con k("m") y resuelve el
  catalogo de SLOW DNS (ya cubierto en la tanda 6); pero ese archivo
  NO aparece en el DEX de MinaProNet, asi que no es su catalogo.

Endpoint real minapronet.site (metodo v19, aportado por Pedro;
script de DataPhreak, t.me/DataPhreak): POST
https://minapronet.site/api/v1/config con body {"hwid"} y cabeceras
x-hwid / x-timestamp / x-signature (HMAC-SHA256 de "hwid:ts:body") /
x-app-version / x-package, UA okhttp/4.12.0. La respuesta trae un blob
"config" Base64 = salt[16] || IV[16] || AES-256-CBC con clave
PBKDF2-HmacSHA1 (10.000 iteraciones), y luego correccion Caesar -1 en
campos (pubkey, psiphonEntry, slowDnsPubKey, slowDnsPubKeyV2ray,
udpAuth, v2rayEntry, slowDnsLinkV2ray). Modo --site en este script.
LIVE STATUS (2026-11-14, verificado con --site): el endpoint ES real
y la firma SE valida (firma mala -> conexion cerrada sin respuesta;
sin x-signature -> HTTP 400), pero responde HTTP 200
{"update_required": true} para las versiones 88 y 89: hoy NO entrega
config. El script lo reporta como UPDATE_REQUIRED, sin inventar nada.

Servidores publicos (segunda fuente, VIVA): la app tambien descarga
  GET https://raw.githubusercontent.com/MinaDiNabil/update.link/refs/heads/main/v2ray-verified.json
  (espejo jsDelivr) -- JSON plano, sin cifrar, con servidores V2Ray
  publicos (ss/vmess/vless/trojan) para la funcion "Public Servers".
  Verificado en vivo 2026-11-14: 213 entradas, todas "online",
  33 paises (168 ss, 27 trojan, 14 vless, 4 vmess).

Nube -- compartir por clave (ExportActivity.addData / MainActivity.getCloudConfig):
  Exportar: la app sube el texto .mina a Firebase Storage bajo una
  clave aleatoria de 27 caracteres alfanumericos (<clave>.mina) y le
  muestra la clave al usuario (la copia al portapapeles).
  Importar: el usuario escribe la clave; la app pide la URL de descarga
  de Firebase Storage y hace un GET simple con OkHttp.
  Bucket: minapronetvpn-tunnel-717e3.appspot.com
  Este script replica la descarga con --cloud-key <CLAVE> usando la API
  REST de Firebase (sign-in anonimo + GET alt=media). Sin una clave
  real de un usuario no hay nada que descargar: las claves son
  aleatorias de 27 caracteres y no se pueden adivinar.

Sin catalogo MinaConfig vivo no hay version/servidores/payloads que
reportar; la fuente viva es v2ray-verified.json (ver arriba).

Archivos de configuracion: ver MinaProNet_archivos.py (formato .mina).
Enlaces de texto: la app no define esquema propio; maneja los enlaces
estandar vmess:// / vless:// / trojan:// / ss://, que SP-DECODE ya
cubre (Manager.dcx/dpt aplica ROT-1 a esos enlaces internamente).
Telegram: https://t.me/MinaProNetVPN
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import random
import struct
import sys
import time
import urllib.parse
import urllib.request
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError, URLError

MAX_BYTES = 8 * 1024 * 1024

UPDATER_URL = ("https://raw.githubusercontent.com/MinaDiNabil/update.link/"
               "refs/heads/main/minapronet.updater")
EMERGENCY_URL = ("https://raw.githubusercontent.com/MinaDiNabil/update.link/"
                 "refs/heads/main/minapronet.json")
PUBLIC_SERVERS_URL = ("https://raw.githubusercontent.com/MinaDiNabil/update.link/"
                      "refs/heads/main/v2ray-verified.json")
PUBLIC_SERVERS_MIRROR = ("https://cdn.jsdelivr.net/gh/MinaDiNabil/update.link"
                         "@main/v2ray-verified.json")
STAGE1_PASSWORD = "m"

# --- Firebase (nube: compartir .mina por clave de 27 caracteres) --------
# Constantes de formato de la app (google-services.xml del APK). La clave
# de API web de Firebase es un identificador publico del cliente, no una
# credencial de usuario; la descarga exige ademas el certificado de firma
# de la app (X-Android-Cert) y una clave de 27 caracteres valida.
FIREBASE_API_KEY = "AIzaSyAV1ClH8aBzdFOWnnrKW7KsOsEciyApFHM"
FIREBASE_BUCKET = "minapronetvpn-tunnel-717e3.appspot.com"
FIREBASE_PACKAGE = "vpn.minapronet.com.eg"
FIREBASE_CERT_SHA1 = "1DC86B23EE631D04F1F7C2AB856EAC0D8515CF60"

# --- minapronet.site (endpoint real; metodo v19 aportado por Pedro, script de DataPhreak, t.me/DataPhreak)
# Las dos claves viven aqui, en el script operativo, como en el v19
# (ofuscadas en Base64 igual que en el script original). El endpoint
# responde {"update_required": true} para las versiones 88 y 89 hoy
# (2026-11-14): no entrega config hasta que el servidor (o una
# version nueva de la app) lo vuelva a servir.
SITE_URL = "https://minapronet.site/api/v1/config"
SITE_APP_VERSION = "88"
SITE_PACKAGE = "vpn.minapronet.com.eg"
SITE_UA = "okhttp/4.12.0"
SITE_PBKDF2_ITER = 10000
_SITE_HMAC_KEY_B64 = "bU5wUjBuM3Rfc1luQ19rM3lfMjAyNF9zRWNVckU="
_SITE_CONFIG_PW_B64 = "bU5wUl9jMG5GMWdfazN5XzIwMjQh"
SITE_HMAC_KEY = base64.b64decode(_SITE_HMAC_KEY_B64)
SITE_CONFIG_PW = base64.b64decode(_SITE_CONFIG_PW_B64).decode("ascii")


class DecodeError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------- AES-256-CBC (puro stdlib)
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


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _aes_key_expand(key):
    w = [x for grp in (struct.unpack(">4I", key[i:i + 16])
                       for i in range(0, 32, 16)) for x in grp]
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


def _aes_decrypt_block(kw, block):
    s = list(struct.unpack(">4I", block))
    for i in range(4):
        s[i] ^= kw[56 + i]
    for rnd in range(13, 0, -1):
        b = bytearray(16)
        for i in range(4):
            for j in range(4):
                b[4 * j + i] = (s[j] >> (24 - 8 * i)) & 0xff
        sb = bytearray(16)
        for r in range(4):
            for c in range(4):
                sb[4 * c + r] = b[4 * ((c - r) % 4) + r]
        sb = bytearray(_INV_SBOX[x] for x in sb)
        s = list(struct.unpack(">4I", bytes(sb)))
        for i in range(4):
            s[i] ^= kw[4 * rnd + i]
        out = [0] * 4
        for c in range(4):
            s0 = (s[c] >> 24) & 0xff
            s1 = (s[c] >> 16) & 0xff
            s2 = (s[c] >> 8) & 0xff
            s3 = s[c] & 0xff
            out[c] = (_gmul(s0, 14) ^ _gmul(s1, 11) ^ _gmul(s2, 13) ^ _gmul(s3, 9)) << 24 \
                | (_gmul(s0, 9) ^ _gmul(s1, 14) ^ _gmul(s2, 11) ^ _gmul(s3, 13)) << 16 \
                | (_gmul(s0, 13) ^ _gmul(s1, 9) ^ _gmul(s2, 14) ^ _gmul(s3, 11)) << 8 \
                | (_gmul(s0, 11) ^ _gmul(s1, 13) ^ _gmul(s2, 9) ^ _gmul(s3, 14))
        s = out
    b = bytearray(16)
    for i in range(4):
        for j in range(4):
            b[4 * j + i] = (s[j] >> (24 - 8 * i)) & 0xff
    sb = bytearray(16)
    for r in range(4):
        for c in range(4):
            sb[4 * c + r] = b[4 * ((c - r) % 4) + r]
    sb = bytearray(_INV_SBOX[x] for x in sb)
    s = list(struct.unpack(">4I", bytes(sb)))
    for i in range(4):
        s[i] ^= kw[i]
    return struct.pack(">4I", *s)


def _aes_cbc_decrypt(key, iv, ct):
    if len(ct) == 0 or len(ct) % 16:
        raise DecodeError("BAD_CIPHERTEXT", "El cifrado no es multiplo de 16 bytes.")
    kw = _aes_key_expand(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(ct), 16):
        blk = _aes_decrypt_block(kw, ct[i:i + 16])
        out += bytes(a ^ b for a, b in zip(blk, prev))
        prev = ct[i:i + 16]
    return bytes(out)


def _aes_encrypt_block(kw, block):
    s = list(struct.unpack(">4I", block))
    for i in range(4):
        s[i] ^= kw[i]
    for rnd in range(1, 14):
        b = bytearray(16)
        for i in range(4):
            for j in range(4):
                b[4 * j + i] = _SBOX[(s[j] >> (24 - 8 * i)) & 0xff]
        sb = bytearray(16)
        for r in range(4):
            for c in range(4):
                sb[4 * c + r] = b[4 * ((c + r) % 4) + r]
        out = [0] * 4
        for c in range(4):
            a0, a1, a2, a3 = sb[4 * c], sb[4 * c + 1], sb[4 * c + 2], sb[4 * c + 3]
            out[c] = (_xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3) << 24 \
                | (a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3) << 16 \
                | (a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3)) << 8 \
                | ((_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3))
        s = out
        for i in range(4):
            s[i] ^= kw[4 * rnd + i]
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
        s[i] ^= kw[56 + i]
    return struct.pack(">4I", *s)


def _aes_cbc_encrypt(key, iv, padded):
    kw = _aes_key_expand(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(padded), 16):
        blk = bytes(a ^ b for a, b in zip(padded[i:i + 16], prev))
        enc = _aes_encrypt_block(kw, blk)
        out += enc
        prev = enc
    return bytes(out)


# ------------------------------------------------------------- xde / xec (nativo libchzcore.so)
def _rot_letters(data: bytes, shift: int) -> bytes:
    out = bytearray()
    for c in data:
        if 65 <= c <= 90:
            out.append(65 + (c - 65 + shift) % 26)
        elif 97 <= c <= 122:
            out.append(97 + (c - 97 + shift) % 26)
        else:
            out.append(c)
    return bytes(out)


def xde(inp: str) -> str:
    """CHZCORE.ii() / nativo xde(str, 0): Base64 -> reverse -> ROT+20 (letras)."""
    raw = base64.b64decode(inp.encode("ascii"))
    return _rot_letters(raw[::-1], 20).decode("utf-8")


def xec(inp: str) -> str:
    """Nativo xec(str, 0), inversa de xde: ROT+6 -> reverse -> Base64."""
    raw = _rot_letters(inp.encode("utf-8"), 6)[::-1]
    return base64.b64encode(raw).decode("ascii")


# ------------------------------------------------------------- dc / ecr (Manager.java)
def _a_decrypt(inp_b64: str, password: str) -> str:
    """Manager.dc: Base64 -> salt|IV|ct -> PBKDF2-HmacSHA1 -> AES-256-CBC."""
    try:
        raw = base64.b64decode(inp_b64.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("BAD_BASE64", "El sobre no es Base64 valido.") from exc
    if len(raw) < 32:
        raise DecodeError("SHORT_ENVELOPE", "El sobre es demasiado corto (sin salt/IV).")
    salt, iv, ct = raw[:16], raw[16:32], raw[32:]
    key = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), salt, 10000, dklen=32)
    pt = _aes_cbc_decrypt(key, iv, ct)
    if not pt:
        raise DecodeError("BAD_PADDING", "El descifrado quedo vacio.")
    pad = pt[-1]
    if pad < 1 or pad > 16 or pt[-pad:] != bytes([pad]) * pad:
        raise DecodeError("BAD_PADDING", "El relleno PKCS7 no es valido (clave incorrecta).")
    try:
        return pt[:-pad].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError("BAD_UTF8", "El descifrado no es texto UTF-8.") from exc


def _a_encrypt(plaintext: str, password: str) -> str:
    """Manager.ecr: salt/IV aleatorios -> PBKDF2-HmacSHA1 -> AES-256-CBC -> Base64(salt||IV||ct)."""
    salt = random.randbytes(16)
    iv = random.randbytes(16)
    key = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), salt, 10000, dklen=32)
    data = plaintext.encode("utf-8")
    pad = 16 - (len(data) % 16)
    pt = data + bytes([pad]) * pad
    ct = _aes_cbc_encrypt(key, iv, pt)
    return base64.b64encode(salt + iv + ct).decode("ascii")


def k_decrypt(inp: str, password: str) -> str:
    """Manager.getter: quitar basura -> Base64 -> xde -> dc(password)."""
    if len(inp) < 26:
        raise DecodeError("SHORT_INPUT", "La entrada es demasiado corta para el formato k().")
    concat = inp[0:5] + inp[8:]
    stripped = concat[0:20] + concat[23:]
    try:
        stage1 = base64.b64decode(stripped.encode("ascii")).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise DecodeError("BAD_BASE64", "La primera capa Base64 no es valida.") from exc
    try:
        stage3 = xde(stage1)
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise DecodeError("BAD_XDE", "La capa xde no es valida.") from exc
    return _a_decrypt(stage3, password)


def k_encrypt(plaintext: str, password: str) -> str:
    """Inversa de k_decrypt (para pruebas): dc -> xec -> Base64 -> insertar basura."""
    stage3 = _a_encrypt(plaintext, password)
    stage1 = xec(stage3)
    stripped = base64.b64encode(stage1.encode("utf-8")).decode("ascii")
    garbage = (random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
               + random.choice("0123456789")
               + random.choice("abcdefghijklmnopqrstuvwxyz"))
    concat = stripped[:20] + garbage + stripped[20:]
    return concat[:5] + garbage + concat[5:]


# ------------------------------------------------------------- HTTP
def fetch_url(url: str, retries: int = 3) -> bytes:
    """GET simple como la app (OkHttp sin cabeceras propias)."""
    last = None
    for _ in range(retries):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "okhttp/4.12.0",
                "Accept-Encoding": "identity",
            })
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read(MAX_BYTES + 1)
                if len(body) > MAX_BYTES:
                    raise DecodeError("TOO_BIG", "La respuesta supera el limite.")
                return body
        except HTTPError as exc:
            # 404 y demas: la app tambien los recibe; no reintentar.
            raise DecodeError("HTTP_%d" % exc.code,
                              "HTTP %d en %s" % (exc.code, url)) from exc
        except (URLError, HTTPException, TimeoutError) as exc:
            last = exc
    raise DecodeError("NETWORK", "No se pudo descargar %s: %s" % (url, last))


def _json(data: bytes | str) -> dict:
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    try:
        obj = json.loads(data)
    except json.JSONDecodeError as exc:
        raise DecodeError("BAD_JSON", "El texto no es JSON valido: %s" % exc) from exc
    if not isinstance(obj, dict):
        raise DecodeError("BAD_JSON", "El JSON no es un objeto.")
    return obj


def decode_updater(data: bytes | str) -> dict:
    """Etapa 1: k(body, "m") -> GettterConfig."""
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace").strip()
    else:
        data = data.strip()
    if len(data) < 26:
        raise DecodeError("LIVE_UPDATER_EMPTY",
                          "El updater no trae catalogo (cuerpo de %d bytes)." % len(data))
    return _json(k_decrypt(data, STAGE1_PASSWORD))


def decode_catalog_body(data: bytes | str, server_password: str) -> dict:
    """Etapa 2: k(body, server_pass) -> MinaConfig."""
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace").strip()
    else:
        data = data.strip()
    return _json(k_decrypt(data, server_password))


def fetch_catalog(updater_url: str = UPDATER_URL) -> dict:
    """Descarga y descifra el catalogo MinaConfig en dos etapas.

    Devuelve un dict con status y, si abre, getter + catalog.
    status: OK | LIVE_UPDATER_EMPTY | LIVE_EMERGENCY_404 | HTTP_xxx | ...
    """
    result: dict = {"updater_url": updater_url, "status": None}
    try:
        raw = fetch_url(updater_url)
    except DecodeError as exc:
        result["status"] = exc.code
        result["error"] = str(exc)
        return result
    result["updater_bytes"] = len(raw)
    result["updater_preview"] = raw[:80].decode("utf-8", errors="replace")
    try:
        getter = decode_updater(raw)
    except DecodeError as exc:
        result["status"] = exc.code
        result["error"] = str(exc)
        # Respaldo de emergencia: minapronet.json (JSON plano, sin cifrar).
        try:
            em = fetch_url(EMERGENCY_URL)
            result["emergency_bytes"] = len(em)
            result["emergency"] = _json(em)
            result["status"] = "OK_EMERGENCY"
            return result
        except DecodeError as exc2:
            result["emergency_status"] = exc2.code
            result["emergency_error"] = str(exc2)
            return result
    result["getter"] = getter
    try:
        server_pass = k_decrypt(getter["ServerPassWD"], STAGE1_PASSWORD)
        catalog_url = k_decrypt(getter["ServerLink"], server_pass)
    except (KeyError, DecodeError) as exc:
        result["status"] = "BAD_GETTER"
        result["error"] = "El GettterConfig no trae ServerLink/ServerPassWD validos: %s" % exc
        return result
    result["catalog_url"] = catalog_url
    try:
        raw2 = fetch_url(catalog_url)
    except DecodeError as exc:
        result["status"] = exc.code
        result["error"] = str(exc)
        return result
    result["catalog_bytes"] = len(raw2)
    try:
        result["catalog"] = decode_catalog_body(raw2, server_pass)
    except DecodeError as exc:
        result["status"] = exc.code
        result["error"] = str(exc)
        return result
    result["status"] = "OK"
    return result


def summarize_catalog(catalog: dict) -> dict:
    servers = catalog.get("serversList") or []
    networks = catalog.get("networksList") or []
    payloads = sum(1 for n in networks if (n.get("payload") or "").strip())
    return {
        "version": catalog.get("version"),
        "message": catalog.get("message"),
        "servers": len(servers),
        "servers_free": sum(1 for s in servers if not s.get("isCustomServer")),
        "networks": len(networks),
        "networks_with_payload": payloads,
        "server_names": [s.get("name") for s in servers[:50]],
    }


def fetch_public_servers(url: str = PUBLIC_SERVERS_URL) -> dict:
    """Fuente secundaria viva: v2ray-verified.json (JSON plano)."""
    raw = fetch_url(url)
    try:
        arr = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DecodeError("BAD_JSON", "v2ray-verified.json no es JSON: %s" % exc) from exc
    if not isinstance(arr, list):
        raise DecodeError("BAD_JSON", "v2ray-verified.json no es una lista.")
    from collections import Counter
    return {
        "url": url,
        "bytes": len(raw),
        "entries": len(arr),
        "online": sum(1 for e in arr if e.get("status") == "online"),
        "countries": len({e.get("country") for e in arr}),
        "protocols": dict(Counter(e.get("protocol") for e in arr)),
        "servers": arr,
    }


# ------------------------------------------------------------- minapronet.site (metodo v19, DataPhreak)
# POST https://minapronet.site/api/v1/config, body {"hwid"}, firma
# HMAC-SHA256 de "hwid:ts:body". Respuesta: {"config": "<blob b64>"}
# (o {"update_required": true} cuando el servidor no sirve config,
# o {"sealed": ...} sin "config" cuando el config va sellado ECIES
# para la clave del dispositivo). El blob es salt[16] || IV[16] ||
# AES-256-CBC con clave PBKDF2-HmacSHA1 (10.000 iteraciones); despues
# se aplica la correccion Caesar -1 a ciertos campos (v19, capa 3).
SITE_CAESAR_FIELDS = ("pubkey", "psiphonEntry", "slowDnsPubKey",
                      "slowDnsPubKeyV2ray", "udpAuth", "v2rayEntry",
                      "slowDnsLinkV2ray")
SITE_PLAIN_PREFIXES = ("vmess://", "vless://", "ss://", "trojan://",
                       "hysteria2://", "hysteria://", "hy2://",
                       "socks://", "ssh://", "ssl://")


def _site_caesar(s: str, k: int) -> str:
    """Caesar +k sobre letras (mod 26) y digitos (mod 10), como el v19."""
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + k) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + k) % 26 + 65))
        elif "0" <= c <= "9":
            out.append(chr((ord(c) - 48 + k) % 10 + 48))
        else:
            out.append(c)
    return "".join(out)


def _site_fix_field(key: str, value: str):
    """Correccion Caesar -1 de un campo del config (v19, fix_field)."""
    if not isinstance(value, str) or not value:
        return value
    if key == "v2rayEntry":
        if value.startswith(SITE_PLAIN_PREFIXES):
            return value
        fixed = _site_caesar(value, -1)
        return fixed if fixed.startswith(SITE_PLAIN_PREFIXES) else value
    if key in ("slowDnsPubKey", "slowDnsPubKeyV2ray"):
        fixed = _site_caesar(value, -1)
        return fixed if (len(fixed) == 64
                         and all(c in "0123456789abcdefABCDEF" for c in fixed)) else value
    if key == "udpAuth":
        return _site_caesar(value, -1)
    if key == "pubkey":
        return _site_caesar(value, -1) if ("CFHJO" in value or "QSJWBUF" in value) else value
    return value


def _site_fix_all(obj):
    """Aplica la correccion Caesar a todo el config (v19, fix_all)."""
    if isinstance(obj, dict):
        return {k: (_site_fix_field(k, v) if isinstance(v, str) and k in SITE_CAESAR_FIELDS
                    else _site_fix_all(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_site_fix_all(x) for x in obj]
    return obj


def site_decrypt_blob(b64: str) -> str:
    """Abre el blob "config" del sitio: salt||IV||ct -> PBKDF2-HmacSHA1 -> AES-256-CBC.

    Reutiliza _a_decrypt (misma KDF y mismo AES que la familia k()).
    Devuelve el texto JSON; si no es JSON, el llamador lo rechaza.
    """
    try:
        raw = base64.b64decode(b64.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("BAD_BASE64", "El blob del sitio no es Base64 valido.") from exc
    if len(raw) < 48 or (len(raw) - 32) % 16:
        raise DecodeError("BAD_BLOB", "El blob del sitio tiene longitud invalida: %d bytes." % len(raw))
    text = _a_decrypt(b64, SITE_CONFIG_PW)
    if not text or text[0] not in "{[":
        raise DecodeError("BAD_BLOB", "El blob del sitio no descifra a JSON (clave incorrecta).")
    return text


def _site_encrypt_blob(plaintext: str) -> str:
    """Inversa de site_decrypt_blob (para pruebas): _a_encrypt con la clave del sitio."""
    return _a_encrypt(plaintext, SITE_CONFIG_PW)


def fetch_site_response(hwid: str, url: str = SITE_URL,
                        app_version: str = SITE_APP_VERSION,
                        timeout: int = 25) -> dict:
    """POST firmado al endpoint del sitio; devuelve el JSON de la respuesta."""
    body = json.dumps({"hwid": hwid}, separators=(",", ":"))
    ts = str(int(time.time()))
    sig = hmac.new(SITE_HMAC_KEY, ("%s:%s:%s" % (hwid, ts, body)).encode(),
                   hashlib.sha256).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "User-Agent": SITE_UA,
        "x-hwid": hwid,
        "x-timestamp": ts,
        "x-signature": sig,
        "x-app-version": app_version,
        "x-package": SITE_PACKAGE,
    }
    req = urllib.request.Request(url, data=body.encode(), method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(MAX_BYTES + 1)
    except HTTPError as exc:
        detail = exc.read()[:200].decode("utf-8", errors="replace")
        raise DecodeError("HTTP_%d" % exc.code,
                          "HTTP %d en %s: %s" % (exc.code, url, detail)) from exc
    except (URLError, HTTPException, TimeoutError) as exc:
        raise DecodeError("NETWORK", "No se pudo contactar %s: %s" % (url, exc)) from exc
    if len(raw) > MAX_BYTES:
        raise DecodeError("TOO_BIG", "La respuesta del sitio supera el limite.")
    return _json(raw)


def handle_site_response(resp: dict) -> dict:
    """Interpreta la respuesta del sitio.

    status: OK | UPDATE_REQUIRED | SEALED | NO_CONFIG.
    OK incluye "config" (dict o lista, con Caesar aplicado) y "summary".
    UPDATE_REQUIRED y SEALED son fallos honestos: el servidor no
    entrego config hoy (o lo sello para la clave del dispositivo).
    """
    if not isinstance(resp, dict):
        raise DecodeError("BAD_JSON", "La respuesta del sitio no es un objeto JSON.")
    if resp.get("update_required") is True:
        return {"status": "UPDATE_REQUIRED", "site_url": SITE_URL,
                "response": resp,
                "error": "El servidor pide actualizar la app (update_required): "
                         "no entrega config para esta version."}
    if "config" not in resp:
        if "sealed" in resp:
            return {"status": "SEALED", "site_url": SITE_URL,
                    "response": resp,
                    "error": "El config viene sellado (ECIES): necesita la clave del dispositivo."}
        return {"status": "NO_CONFIG", "site_url": SITE_URL,
                "response": resp,
                "error": "La respuesta no trae 'config' (claves: %s)."
                         % ", ".join(sorted(resp.keys()))}
    text = site_decrypt_blob(resp["config"])
    cfg = _json(text)
    cfg = _site_fix_all(cfg)
    out = {"status": "OK", "site_url": SITE_URL,
           "config_version": resp.get("config_version"), "config": cfg}
    if isinstance(cfg, dict):
        out["summary"] = summarize_catalog(cfg)
    else:
        out["summary"] = {"entries": len(cfg)}
    return out


def fetch_site(hwid: str, url: str = SITE_URL,
               app_version: str = SITE_APP_VERSION) -> dict:
    """Descarga y abre el config del sitio en un paso."""
    return handle_site_response(fetch_site_response(hwid, url, app_version))


# ------------------------------------------------------------- Nube (Firebase Storage por clave)
def _firebase_anonymous_token() -> str:
    """Sign-in anonimo con la API REST de Firebase (como el SDK de la app)."""
    body = json.dumps({"returnSecureToken": True}).encode()
    headers = {"Content-Type": "application/json"}
    if FIREBASE_CERT_SHA1:
        headers["X-Android-Package"] = FIREBASE_PACKAGE
        headers["X-Android-Cert"] = FIREBASE_CERT_SHA1
    req = urllib.request.Request(
        "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=" + FIREBASE_API_KEY,
        data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            tok = json.load(resp)
    except HTTPError as exc:
        detail = exc.read()[:300].decode("utf-8", errors="replace")
        raise DecodeError("FIREBASE_AUTH_%d" % exc.code,
                          "El sign-in anonimo fallo (HTTP %d): %s" % (exc.code, detail)) from exc
    except (URLError, HTTPException, TimeoutError) as exc:
        raise DecodeError("NETWORK", "No se pudo contactar Firebase Auth: %s" % exc) from exc
    if "idToken" not in tok:
        raise DecodeError("FIREBASE_AUTH", "Firebase Auth no devolvio idToken: %s" % tok)
    return tok["idToken"]


def fetch_cloud_config(key: str) -> str:
    """Descarga el .mina compartido con la clave de 27 caracteres.

    Devuelve el texto .mina tal como lo subio la app (para abrirlo con
    MinaProNet_archivos.py). Sin una clave real no hay nada que bajar.
    """
    key = key.strip()
    if len(key) != 27 or not key.isalnum():
        raise DecodeError("BAD_KEY", "La clave debe tener 27 caracteres alfanumericos.")
    token = _firebase_anonymous_token()
    obj = urllib.parse.quote(key + ".mina", safe="")
    url = ("https://firebasestorage.googleapis.com/v0/b/%s/o/%s?alt=media"
           % (FIREBASE_BUCKET, obj))
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read(MAX_BYTES + 1).decode("utf-8")
    except HTTPError as exc:
        if exc.code == 404:
            raise DecodeError("CLOUD_KEY_NOT_FOUND",
                              "No existe ningun .mina con esa clave (HTTP 404).") from exc
        raise DecodeError("HTTP_%d" % exc.code,
                          "HTTP %d al descargar el .mina." % exc.code) from exc
    except (URLError, HTTPException, TimeoutError) as exc:
        raise DecodeError("NETWORK", "No se pudo descargar el .mina: %s" % exc) from exc


# ------------------------------------------------------------- Self-test
def _self_test() -> dict:
    checks = {}

    # 1. Vector AES-256 FIPS-197.
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = _aes_cbc_encrypt(key, bytes(16), pt)
    checks["aes256_fips197"] = ct.hex() == "8ea2b7ca516745bfeafc49904b496089"
    checks["aes256_roundtrip"] = _aes_cbc_decrypt(key, bytes(16), ct) == pt

    # 2. xde/xec inversas (xec produce Base64; xde lo consume).
    s = "Hello, MinaProNet 88! vmess://abc-XYZ_123"
    enc = xec(s)
    checks["xec_xde"] = xde(enc) == s
    checks["xde_xec"] = xec(xde(enc)) == enc

    # 3. k() ida y vuelta (cifrado real de la app, con salt/IV aleatorios).
    doc = json.dumps({"ServerLink": "https://example.invalid/x",
                      "ServerPassWD": "secreto", "appSecurity": "1"},
                     ensure_ascii=False)
    enc = k_encrypt(doc, "m")
    checks["k_roundtrip"] = json.loads(k_decrypt(enc, "m")) == json.loads(doc)
    checks["k_wrong_password_fails"] = False
    try:
        k_decrypt(enc, "clave-equivocada")
    except DecodeError:
        checks["k_wrong_password_fails"] = True

    # 4. dc/ecr ida y vuelta (capa AES de los .mina, password "u").
    cfg = json.dumps({"i": "x", "t": "0", "message": "prueba"}, ensure_ascii=False)
    checks["a_roundtrip"] = _a_decrypt(_a_encrypt(cfg, "u"), "u") == cfg

    # 5. El updater vacio se detecta como LIVE_UPDATER_EMPTY, no como JSON.
    try:
        decode_updater(b"hello world..")
        checks["updater_empty_detected"] = False
    except DecodeError as exc:
        checks["updater_empty_detected"] = exc.code == "LIVE_UPDATER_EMPTY"

    # 6. minapronet.site (v19): blob ida y vuelta con la clave del sitio.
    site_cfg = json.dumps({"version": "19",
                           "serversList": [{"name": "Servidor 1", "isCustomServer": False}],
                           "networksList": [{"name": "Red 1", "payload": "GET / HTTP/1.1"},
                                            {"name": "Red 2", "payload": ""}]},
                          ensure_ascii=False)
    site_blob = _site_encrypt_blob(site_cfg)
    checks["site_blob_roundtrip"] = site_decrypt_blob(site_blob) == site_cfg
    checks["site_blob_bad_key_fails"] = False
    try:
        _a_decrypt(site_blob, "clave-equivocada")
    except DecodeError:
        checks["site_blob_bad_key_fails"] = True

    # 7. Correccion Caesar -1 de los campos del config (v19, capa 3).
    checks["site_caesar_v2ray"] = (
        _site_fix_field("v2rayEntry", _site_caesar("vmess://abcDEF123", 1))
        == "vmess://abcDEF123")
    hex64 = "0123456789abcdef" * 4
    checks["site_caesar_pubkey"] = (
        _site_fix_field("slowDnsPubKey", _site_caesar(hex64, 1)) == hex64)
    checks["site_caesar_udpauth"] = (
        _site_fix_field("udpAuth", _site_caesar("AuthToken9", 1)) == "AuthToken9")

    # 8. Respuestas del sitio sin config: update_required y sellado.
    checks["site_update_required"] = (
        handle_site_response({"update_required": True})["status"] == "UPDATE_REQUIRED")
    checks["site_sealed_detected"] = (
        handle_site_response({"sealed": "AAAA"})["status"] == "SEALED")

    # 9. Respuesta del sitio con config: abre, aplica Caesar y resume.
    site_res = handle_site_response({"config": site_blob, "config_version": 19})
    checks["site_response_ok"] = (
        site_res["status"] == "OK"
        and site_res["summary"]["servers"] == 1
        and site_res["summary"]["networks"] == 2
        and site_res["summary"]["networks_with_payload"] == 1)

    checks["all_ok"] = all(checks.values())
    return checks


# ------------------------------------------------------------- CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="MinaProNet 88.0.0: catalogo MinaConfig (updater y minapronet.site), "
                    "servidores publicos y nube por clave.")
    ap.add_argument("--url", default=UPDATER_URL,
                    help="URL del updater (por defecto, el de la app).")
    ap.add_argument("--updater-file", help="Leer el updater desde un archivo local.")
    ap.add_argument("--catalog-file", help="Leer el cuerpo del catalogo desde un archivo local.")
    ap.add_argument("--server-password", help="Password del servidor (etapa 2) para --catalog-file.")
    ap.add_argument("--public-servers", action="store_true",
                    help="Descargar v2ray-verified.json (servidores publicos vivos).")
    ap.add_argument("--public-servers-file", help="Leer v2ray-verified.json desde un archivo local.")
    ap.add_argument("--cloud-key", help="Clave de 27 caracteres para descargar un .mina de la nube.")
    ap.add_argument("--site", action="store_true",
                    help="Consultar minapronet.site (endpoint real, metodo v19 de DataPhreak).")
    ap.add_argument("--site-url", default=SITE_URL,
                    help="URL del endpoint del sitio (por defecto, la de la app).")
    ap.add_argument("--site-hwid",
                    help="HWID a enviar (por defecto, uno de prueba derivado de 'sp-decode').")
    ap.add_argument("--site-app-version", default=SITE_APP_VERSION,
                    help="Version de app a declarar (por defecto, 88).")
    ap.add_argument("--site-file", help="Leer la respuesta JSON del sitio desde un archivo local.")
    ap.add_argument("--site-b64", help="Descifrar un blob 'config' del sitio (Base64 o @archivo).")
    ap.add_argument("--json", action="store_true", help="Salida en JSON.")
    ap.add_argument("--self-test", action="store_true", help="Pruebas internas sin red.")
    args = ap.parse_args(argv)

    if args.self_test:
        res = _self_test()
        if args.json:
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            for k, v in res.items():
                print(("OK  " if v else "FALLO  ") + k)
        return 0 if res["all_ok"] else 1

    if args.cloud_key:
        try:
            text = fetch_cloud_config(args.cloud_key)
        except DecodeError as exc:
            print("CLOUD: %s: %s" % (exc.code, exc))
            return 2
        print(text)
        return 0

    if args.site or args.site_file or args.site_b64:
        try:
            if args.site_b64:
                b64 = (Path(args.site_b64[1:]).read_text(encoding="utf-8").strip()
                       if args.site_b64.startswith("@") else args.site_b64.strip())
                cfg = _site_fix_all(_json(site_decrypt_blob(b64)))
                res = {"status": "OK", "site_url": SITE_URL, "config": cfg}
                if isinstance(cfg, dict):
                    res["summary"] = summarize_catalog(cfg)
                else:
                    res["summary"] = {"entries": len(cfg)}
            elif args.site_file:
                res = handle_site_response(_json(Path(args.site_file).read_bytes()))
            else:
                hwid = args.site_hwid or hashlib.md5(b"sp-decode").hexdigest()
                res = fetch_site(hwid, args.site_url, args.site_app_version)
        except DecodeError as exc:
            print("SITE: %s: %s" % (exc.code, exc))
            return 2
        if args.json:
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            print("Estado: %s" % res.get("status"))
            if res.get("status") == "OK":
                s = res["summary"]
                print("Config del sitio (version %s): %d servidores, %d redes (%d con payload)"
                      % (res.get("config_version"), s.get("servers", s.get("entries")),
                         s.get("networks", 0), s.get("networks_with_payload", 0)))
            else:
                print("Detalle: %s" % res.get("error", res))
        return 0 if res.get("status") == "OK" else 3

    if args.public_servers or args.public_servers_file:
        try:
            if args.public_servers_file:
                raw = Path(args.public_servers_file).read_bytes()
                arr = json.loads(raw.decode("utf-8"))
                from collections import Counter
                res = {"entries": len(arr),
                       "online": sum(1 for e in arr if e.get("status") == "online"),
                       "countries": len({e.get("country") for e in arr}),
                       "protocols": dict(Counter(e.get("protocol") for e in arr)),
                       "servers": arr}
            else:
                res = fetch_public_servers()
        except DecodeError as exc:
            print("PUBLIC: %s: %s" % (exc.code, exc))
            return 2
        if args.json:
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            print("Servidores publicos (v2ray-verified.json): %d entradas, %d online, %d paises"
                  % (res["entries"], res["online"], res["countries"]))
            print("Protocolos: %s" % res["protocols"])
        return 0

    # Catalogo principal.
    if args.updater_file:
        raw = Path(args.updater_file).read_bytes()
        try:
            getter = decode_updater(raw)
        except DecodeError as exc:
            print("UPDATER: %s: %s" % (exc.code, exc))
            return 2
        if args.catalog_file:
            if not args.server_password:
                print("Falta --server-password para descifrar el catalogo local.")
                return 2
            try:
                catalog = decode_catalog_body(Path(args.catalog_file).read_bytes(),
                                              args.server_password)
            except DecodeError as exc:
                print("CATALOGO: %s: %s" % (exc.code, exc))
                return 2
            res = {"status": "OK", "getter": getter, "catalog": catalog,
                   "summary": summarize_catalog(catalog)}
        else:
            res = {"status": "GETTER_ONLY", "getter": getter}
    else:
        res = fetch_catalog(args.url)
        if res.get("status") == "OK":
            res["summary"] = summarize_catalog(res["catalog"])

    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        status = res.get("status")
        print("Estado: %s" % status)
        if status == "OK":
            s = res["summary"]
            print("Catalogo version %s: %d servidores (%d libres), %d redes (%d con payload)"
                  % (s["version"], s["servers"], s["servers_free"],
                     s["networks"], s["networks_with_payload"]))
            if s["message"]:
                print("Mensaje: %s" % s["message"])
        elif status == "LIVE_UPDATER_EMPTY":
            print("El updater en vivo esta vacio (el vendedor lo vacio).")
            print("Cuerpo: %r (%d bytes)" % (res.get("updater_preview"), res.get("updater_bytes")))
            print("Respaldo de emergencia: %s" % res.get("emergency_status"))
        else:
            print("Detalle: %s" % res.get("error", res))
    return 0 if res.get("status") in ("OK", "OK_EMERGENCY", "GETTER_ONLY") else 3


if __name__ == "__main__":
    sys.exit(main())
