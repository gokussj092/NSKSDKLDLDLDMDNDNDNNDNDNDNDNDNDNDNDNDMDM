#!/usr/bin/env python3
"""SLOW DNS 6.0.0: catalog decoder, local or explicit HTTPS.

Python 3.10+, solo biblioteca estandar: PBKDF2-HmacSHA1 (hashlib) y
AES-256-CBC estan implementados en Python puro en este archivo (el AES
fue verificado byte a byte contra PyCryptodome con el catalogo real).
Package slowdns.minapronetvpn.com.eg, versionCode 6, versionName 6.0.0.
El APK es la version publica de Google Play (6.0.0, actualizada 19 oct
2026); se descargo de APKPure porque APKMirror no tenia listado.

Catalogo en dos etapas (w9/f.java, u9/a.java, libchzcore.so):

  Etapa 1 -- indice del catalogo:
    GET https://raw.githubusercontent.com/MinaDiNabil/update.link/refs/heads/main/slowdns_updater
    (GET simple, sin cabeceras propias ni autenticacion; el cuerpo es una
    sola linea de Base64). El cuerpo se descifra con k(body, "m") y da el
    GettterConfig JSON: {ServerLink, ServerPassWD, appSecurity}.

  Etapa 2 -- catalogo real:
    server_pass = k(ServerPassWD, "m")
    catalog_url = k(ServerLink, server_pass)
      -> https://raw.githubusercontent.com/MinaDiNabil/update.link/refs/heads/main/slowdns_config.json
    GET catalog_url (GET simple) y k(body, server_pass) da el MinaConfig
    JSON: {version, message, serversList[], networksList[]}.

La funcion k(input, password) (u9/a.java, metodo k) es:

    1. Quitar 6 caracteres basura: los de las posiciones 5-7 y, del
       resultado, los de las posiciones 20-22 (son "L5p" en el vivo).
    2. Base64-decodificar el resto (Android Base64, flag NO_WRAP).
    3. Pasar el texto resultante por CHZCORE.p() = el nativo xde(str, 0)
       de libchzcore.so (CHZCORE = xyz.chz.kntinjector.core.chzcore.CHZCORE,
       un almacen MMKV sobre libchzcore.so; los nombres de los metodos
       nativos estan ofuscados con el ofuscador "oz" y solo aparecen
       descifrados en .bss tras ejecutar los constructores de la libreria).
       xde hace, en este orden:
         a. Base64-decodificar la entrada,
         b. invertir los bytes (reverse),
         c. ROT+20 solo sobre letras A-Z/a-z (conservando mayusculas).
       Su inversa es xec: ROT+6, reverse, Base64-codificar
       (xde(xec(s)) == s y xec(xde(s)) == s).
    4. a(resultado, password) (u9/a.java, metodo a):
       Base64-decodificar -> salt[0:16] || IV[16:32] || ct ->
       PBKDF2WithHmacSHA1(password, salt, 10000 iteraciones, clave de
       256 bits) -> AES/CBC/PKCS7Padding -> texto UTF-8 (JSON).

LIVE STATUS (2026-11-13, verificado con --url por el analista): el
endpoint de la etapa 1 responde HTTP 200 (4674 B) y el de la etapa 2
responde HTTP 200 (177958 B); ambas etapas descifran y el catalogo
abre: version 4, message vacio, 7 servidores (US, CA, DE, NL, UK, SG,
AU; el catalogo no marca premium/free/VIP en ningun campo: los 7 son
libres) y 54 redes (todas SlowDNS+SSH, nombres de DNS publicos como
GoogleDNS 8.8.8.8 o CloudflareDNS 1.1.1.1; el campo payload viene vacio
en las 54: son entradas DNS, no payloads HTTP). Un descifrado completo
tarda ~1 s en Python puro (el PBKDF2 de 10000 iteraciones es lo mas
costoso; se ejecuta 3 veces por catalogo).

Archivos de configuracion: la app NO tiene formato propio de archivo.
El manifiesto no declara ningun intent-filter VIEW para archivos ni
esquema propio (no hay slowdns:// ni similar) y el DEX no tiene
importar/exportar perfiles como archivo: los servidores personalizados
(ConfigCustom/CustomSetupData) se crean en la interfaz y se guardan en
el almacen CHZCORE/MMKV, no se exportan. Por eso no hay
SLOW_DNS_archivos.py. Enlaces de texto: la app solo maneja los
estandar vmess:// / vless:// / trojan:// / ss://, que SP-DECODE ya
cubre; u9/a.java l() solo re-codifica el id de un enlace vmess:// con
el cifrado de sustitucion b() (letras ROT-1, digitos ROT-1), sin crear
un esquema propio.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import struct
import sys
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 64

UPDATER_URL = ("https://raw.githubusercontent.com/MinaDiNabil/update.link/"
               "refs/heads/main/slowdns_updater")
STAGE1_PASSWORD = "m"


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
    """CHZCORE.p() / nativo xde(str, 0): Base64 -> reverse -> ROT+20 (letras)."""
    raw = base64.b64decode(inp.encode("ascii"))
    return _rot_letters(raw[::-1], 20).decode("utf-8")


def xec(inp: str) -> str:
    """Nativo xec(str, 0), inversa de xde: ROT+6 -> reverse -> Base64."""
    raw = _rot_letters(inp.encode("utf-8"), 6)[::-1]
    return base64.b64encode(raw).decode("ascii")


# ------------------------------------------------------------- k() de u9/a.java
def _a_decrypt(inp_b64: str, password: str) -> str:
    """u9/a.java a(): Base64 -> salt|IV|ct -> PBKDF2-HmacSHA1 -> AES-256-CBC."""
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


def k_decrypt(inp: str, password: str) -> str:
    """u9/a.java k(): quitar basura -> Base64 -> xde -> a(password)."""
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


# ------------------------------------------------------------- JSON
def _nonfinite(_value):
    raise ValueError("constante no finita")


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("clave duplicada")
        obj[key] = value
    return obj


def _json(data):
    try:
        doc = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON", "JSON invalido o con claves duplicadas.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El documento debe contener un objeto JSON.")
    return doc


def _catalog_json(data: bytes) -> dict:
    doc = _json(data)
    if not isinstance(doc.get("version"), int):
        raise DecodeError("WRONG_DOCUMENT", "El catalogo no trae un version entero.")
    if not isinstance(doc.get("serversList"), list) or not isinstance(doc.get("networksList"), list):
        raise DecodeError("WRONG_DOCUMENT", "Faltan las listas serversList o networksList.")
    if not doc["serversList"] and not doc["networksList"]:
        raise DecodeError("WRONG_DOCUMENT", "El catalogo no trae servidores ni redes.")
    return doc


def _updater_json(data: bytes) -> dict:
    doc = _json(data)
    if not isinstance(doc.get("ServerLink"), str) or not doc.get("ServerLink"):
        raise DecodeError("WRONG_DOCUMENT", "El indice no trae ServerLink.")
    if not isinstance(doc.get("ServerPassWD"), str) or not doc.get("ServerPassWD"):
        raise DecodeError("WRONG_DOCUMENT", "El indice no trae ServerPassWD.")
    return doc


def _text(data: bytes | str) -> str:
    if isinstance(data, bytes):
        text = data.decode("utf-8", errors="strict")
    else:
        text = data
    return text.strip()


# ------------------------------------------------------------- API offline
def decode_updater(data: bytes | str) -> dict:
    """Descifra el cuerpo del indice (etapa 1) con la clave "m"."""
    return _updater_json(k_decrypt(_text(data), STAGE1_PASSWORD).encode("utf-8"))


def decode_catalog_body(data: bytes | str, server_password: str) -> dict:
    """Descifra el cuerpo del catalogo (etapa 2) con la clave del servidor."""
    return _catalog_json(k_decrypt(_text(data), server_password).encode("utf-8"))


def decode(data: bytes | str, server_password: str | None = None) -> dict:
    """Offline API: descifra un cuerpo guardado y devuelve el dict.

    Sin server_password intenta la etapa 1 (clave "m", indice). Con
    server_password descifra un cuerpo de etapa 2 (catalogo MinaConfig).
    Si el texto ya es JSON plano, lo valida y lo devuelve.
    """
    text = _text(data)
    if text.startswith("{"):
        doc = _json(text.encode("utf-8"))
        if isinstance(doc.get("version"), int):
            return _catalog_json(text.encode("utf-8"))
        return _updater_json(text.encode("utf-8"))
    if server_password is not None:
        return decode_catalog_body(text, server_password)
    return decode_updater(text)


def run(file_bytes: bytes | str) -> str | None:
    """Offline API: JSON completo del catalogo o None; nunca una lista parcial."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


# ------------------------------------------------------------- descarga en vivo (dos etapas)
def _https_url(url: str):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment):
        raise ValueError("invalid HTTPS URL")
    return parsed


def fetch_url(url: str, retries: int = 4) -> bytes:
    """GET simple exactamente como lo hace la app (OkHttp, sin cabeceras
    propias ni autenticacion). GitHub raw no exige User-Agent. Se usa
    urllib con el proxy del entorno (si lo hay): en este entorno el
    proxy es la unica salida a Internet y urllib lee sus credenciales
    vivas del entorno en cada llamada."""
    parsed = _https_url(url)
    last_error: Exception | None = None
    for attempt in range(max(1, retries)):
        try:
            import urllib.request as _urlreq
            req = _urlreq.Request(url, method="GET")
            req.add_header("Accept-Encoding", "identity")
            with _urlreq.urlopen(req, timeout=30) as resp:
                if resp.status != 200:
                    raise OSError(f"unexpected HTTP status {resp.status}")
                raw = resp.read(MAX_BYTES + 1)
        except HTTPError as exc:
            code = "ACCESS_DENIED" if exc.code in (401, 403) else "DOWNLOAD_FAILED"
            raise DecodeError(code, "El endpoint no devolvio un catalogo accesible.") from exc
        except (OSError, ValueError, URLError) as exc:
            last_error = exc
            if attempt + 1 < max(1, retries):
                import time
                time.sleep(1 + attempt)
            continue
        if not raw or len(raw) > MAX_BYTES or raw.lstrip().startswith(b"<"):
            raise DecodeError("DOWNLOAD_FAILED", "Catalogo vacio, incompatible o superior a 8 MiB.")
        return raw
    raise DecodeError("DOWNLOAD_FAILED", "No se pudo descargar el catalogo mediante HTTPS.") from last_error


def fetch_catalog(updater_url: str = UPDATER_URL) -> tuple[dict, dict]:
    """Descarga en vivo en dos etapas y devuelve (catalogo, info).

    info trae catalog_url, server_password (la clave del servidor, util
    para descifrar un cuerpo de etapa 2 guardado con --password) y los
    tamanos descargados.
    """
    updater_raw = fetch_url(updater_url)
    updater = decode_updater(updater_raw)
    server_password = k_decrypt(updater["ServerPassWD"], STAGE1_PASSWORD)
    catalog_url = k_decrypt(updater["ServerLink"], server_password)
    config_raw = fetch_url(catalog_url)
    catalog = decode_catalog_body(config_raw, server_password)
    info = {
        "catalog_url": catalog_url,
        "server_password": server_password,
        "updater_bytes": len(updater_raw),
        "config_bytes": len(config_raw),
    }
    return catalog, info


def _read(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el limite de tamano.")
    return data


def _self_test() -> dict:
    """Verifica la criptografia sin datos vivos: xde/xec inversos, AES
    contra un vector conocido y un sobre k() sintetico de ida y vuelta."""
    sample = "Hello, World! Test 123 abc XYZ"
    if xde(xec(sample)) != sample:
        raise DecodeError("SELF_TEST_FAIL", "xde(xec()) no es identidad.")
    b64in = base64.b64encode(b"some test data 12345").decode("ascii")
    if xec(xde(b64in)) != b64in:
        raise DecodeError("SELF_TEST_FAIL", "xec(xde()) no es identidad.")
    # AES-256: vector FIPS-197 (clave 000102...1f, texto 001122...eeff)
    key = bytes(range(32))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected_ct = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    kw = _aes_key_expand(key)
    got = _aes_decrypt_block(kw, expected_ct)
    if got != pt:
        raise DecodeError("SELF_TEST_FAIL", "El AES-256 no coincide con FIPS-197.")
    # Sobre k() sintetico: construir con xec + a() inverso no existe, asi
    # que se verifica el descifrado de un sobre generado con las mismas
    # primitivas (PBKDF2 + AES-CBC + xec + basura) en sentido inverso.
    password = "test-password"
    payload = json.dumps({"version": 99, "message": "ok",
                          "serversList": [{"name": "X"}],
                          "networksList": []}).encode("utf-8")
    salt = bytes(range(16))
    iv2 = bytes(range(16, 32))
    key2 = hashlib.pbkdf2_hmac("sha1", password.encode(), salt, 10000, dklen=32)
    pad = 16 - len(payload) % 16
    padded = payload + bytes([pad]) * pad
    # cifrar CBC con el bloque de cifrado (se cifra con _aes_decrypt_block? no:
    # se usa el cifrado AES puro reimplementado aqui con las mismas tablas)
    ct = _aes_cbc_encrypt_for_test(key2, iv2, padded)
    envelope = base64.b64encode(salt + iv2 + ct).decode("ascii")
    stage3 = xec(envelope)
    stage1 = base64.b64encode(stage3.encode("ascii")).decode("ascii")
    body = stage1[:5] + "L5p" + stage1[5:20] + "L5p" + stage1[20:]
    doc = _catalog_json(k_decrypt(body, password).encode("utf-8"))
    if doc.get("version") != 99:
        raise DecodeError("SELF_TEST_FAIL", "El sobre k() sintetico no abrio.")
    return {"self_test": "OK", "version": 99}


def _aes_cbc_encrypt_for_test(key, iv, padded):
    """Solo para el self-test: cifra AES-256-CBC con las tablas de este archivo."""
    # SubBytes + ShiftRows + MixColumns hacia adelante, con la SBOX de arriba.
    def enc_block(kw, block):
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

    kw = _aes_key_expand(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(padded), 16):
        blk = bytes(a ^ b for a, b in zip(padded[i:i + 16], prev))
        enc = enc_block(kw, blk)
        out += enc
        prev = enc
    return bytes(out)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("file", nargs="?", type=Path,
                        help="Cuerpo cifrado guardado (etapa 1 o etapa 2 con --password; tambien acepta JSON plano)")
    source.add_argument("--url", nargs="?", const=UPDATER_URL,
                        help="Descarga en vivo en dos etapas; por defecto usa el indice original")
    source.add_argument("--stdin", action="store_true", help="Leer el cuerpo cifrado desde stdin")
    parser.add_argument("--password", default=None,
                        help="Clave del servidor para descifrar un cuerpo de etapa 2 guardado (la muestra --url en stderr)")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; por defecto stdout")
    parser.add_argument("--self-test", action="store_true",
                        help="Verifica xde/xec, AES-256-CBC (FIPS-197) y un sobre k() sintetico")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            result = _self_test()
            print(json.dumps(result, ensure_ascii=False))
            return 0
        if args.url is not None:
            doc, info = fetch_catalog(args.url)
            rendered = json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
            if args.output:
                args.output.write_text(rendered, encoding="utf-8")
            else:
                sys.stdout.write(rendered)
            print(json.dumps({"version": doc.get("version"),
                              "servers": len(doc.get("serversList", [])),
                              "networks": len(doc.get("networksList", [])),
                              "catalog_url": info["catalog_url"],
                              "server_password": info["server_password"],
                              "updater_bytes": info["updater_bytes"],
                              "config_bytes": info["config_bytes"]},
                             ensure_ascii=False), file=sys.stderr)
            return 0
        if args.stdin:
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        elif args.file is not None:
            raw = _read(args.file)
        else:
            parser.error("se requiere un archivo, --url o --stdin (o --self-test)")
        doc = decode(raw, server_password=args.password)
        rendered = json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        if isinstance(doc.get("version"), int):
            print(json.dumps({"version": doc.get("version"),
                              "servers": len(doc.get("serversList", [])),
                              "networks": len(doc.get("networksList", []))},
                             ensure_ascii=False), file=sys.stderr)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
