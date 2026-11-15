#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
E-SAN VPN (com.misaki.esanvpn) — descifrador de catálogo para SP-DECODE.
Python 3.10+, solo biblioteca estándar (AES-256-GCM en Python puro).

App: E-SAN VPN 1.6.4 (versionCode 74), minSdk 32. Solo 32 bits (armeabi_v7a).
Sin cobertura previa en el repositorio SP-DECODE (verificado 2026-11-13).

Catálogo (verificado en vivo 2026-11-13):
  GET https://e-san-vpn.in.net/ServerUpdate/e-san-vpn.json
  Petición GET simple, sin autenticación ni parámetros. El servidor es
  Cloudflare y rechaza el User-Agent por defecto de Python-urllib (403);
  con un User-Agent Dalvik/Java/navegador responde 200. Este script usa
  "Dalvik/2.1.0 (Linux; U; Android 14)".
  Respuesta: una línea de Base64 (26.996 B) -> 20.247 B cifrados.

Cifrado (clase jc0 / p5 / my0 / t1 del APK; variante de Tink StreamingAead):
  1. Contraseña = valor del ajuste "key_secured"
     (por defecto "l{0[$~A1grg3+k1HhyMK7.IlF!m%^B0AKfqpOc0g", tk3.<init>).
  2. PBKDF2-HmacSHA256, 100.000 iteraciones, clave de 256 bits,
     salt = b"MY_APP_FIXED_SALT_V1" -> ikm de 32 B.
  3. Cabecera de 40 B: [0x28] [salt de 32 B] [prefijo de nonce de 7 B].
  4. Clave AES = HKDF-SHA256(ikm, salt=cabecera[1:33],
     info=b"MY_SECURE_JSON_STREAM_V1", 32 B).
  5. Segmentos AES-256-GCM (sin AAD, tag de 16 B): el PRIMER segmento de
     texto cifrado mide 4.056 B (4.040 de texto plano + tag); los demás
     4.096 B (4.080 + tag). Nonce de 12 B = prefijo(7) + nº de segmento
     BE32 + byte de último segmento (0/1).
  El JSON resultante trae Version, Message, Servers, Networks y setOpenVPN.

Campos "ED:..." (Base32): ServerIP, Username, Password, UDPConfig,
setOpenVPN y cualquier otro valor de texto con ese prefijo se decodifican
a UTF-8 en su lugar (se conserva el valor original si no es UTF-8 válido).
Los usuarios/contraseñas se devuelven tal como los guarda la app
(incluidas las comillas simples literales: 'IElsIAlN' / 'lSIelRIvIcIE').

Resultado en vivo (2026-11-13, --url):
  Versión 36.6, 15 servidores (todos de Tailandia, flag "th", sin marca de
  free/premium en el catálogo): 5 UDP (udp1-5.e-san-dns.com, Hysteria2) y
  10 OpenVPN (thailand1-10.e-san-dns.com, TCP 1194). 5 redes (3G, 4G, 5G,
  Default, WiFi), protocolo OVPN, con Payload vacío en las 5: 0 payloads
  HTTP. setOpenVPN es una configuración de cliente OpenVPN (2.074 B).

Otras URLs de la app (no son el catálogo):
  GET https://e-san-vpn.in.net/WarnApplication/warn.json — aviso de
  actualización (diálogo; Boolean false el 2026-11-13).
  GET https://e-san-vpn.in.net/ — base (MainDetail.a(); sin uso en el dex).

Archivo guardado: la app, al confirmar la actualización, guarda el JSON
descifrado como "profile.enc" en getFilesDir() con una clave Tink
StreamingAead propia del dispositivo (EncryptedSharedPreferences +
Android Keystore), por lo que NO se puede descifrar sin conexión.
El formato antiguo "profile.json" (Base64 + XXTEA, clave = primeros
16 B del token de MainDetail.b()) lo descifra E_SAN_VPN_archivos.py.

Uso:
  python3 E_SAN_VPN.py --url [URL] [-o salida.json]
  python3 E_SAN_VPN.py --file e-san-vpn.json [-o salida.json]
  python3 E_SAN_VPN.py --self-test
"""

import base64
import hashlib
import hmac
import json
import math
import struct
import sys
import urllib.request
from urllib.parse import urlsplit

CATALOG_URL = "https://e-san-vpn.in.net/ServerUpdate/e-san-vpn.json"
WARN_URL = "https://e-san-vpn.in.net/WarnApplication/warn.json"
BASE_URL = "https://e-san-vpn.in.net/"

# Contraseña del ajuste "key_secured" (valor por defecto en tk3.<init>).
# Es la contraseña del formato, no una credencial de usuario.
CATALOG_PASSWORD = "l{0[$~A1grg3+k1HhyMK7.IlF!m%^B0AKfqpOc0g"
PBKDF2_SALT = b"MY_APP_FIXED_SALT_V1"
PBKDF2_ITERATIONS = 100000
PBKDF2_KEY_LEN = 32

# Datos asociados del sobre Tink (Leu0.b, también en du0.d).
ASSOCIATED_DATA = b"MY_SECURE_JSON_STREAM_V1"

HEADER_SIZE = 40            # 1 byte de tamaño + salt de 32 B + prefijo de 7 B
HEADER_FIRST_BYTE = 40
FIRST_SEGMENT_CT = 4056     # 4.040 de texto plano + tag de 16 B
SEGMENT_CT = 4096           # 4.080 de texto plano + tag de 16 B
TAG_LEN = 16

# Token de MainDetail.b() (solo se usa para el profile.json antiguo;
# el catálogo en vivo NO usa XXTEA).
LEGACY_TOKEN = "Bs3PI5e1Olf5Me8E9Vc7bP1oUhS0eZ"

USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 14)"
LIST_FIELDS = ("Servers", "Networks")
MAX_DEPTH = 64
MAX_NODES = 200000


class DecodeError(ValueError):
    """Error de descifrado con un código estable para SP-DECODE."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------- AES-256-GCM
# AES en Python puro (mismo núcleo verificado en RNV_Tunnel_VPN.py).
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
    """AES-256-GCM decrypt (solo stdlib). nonce: 12 bytes."""
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
    """AES-256-GCM encrypt (solo stdlib). Devuelve (ciphertext, tag).
    Solo se usa para generar el recurso de --self-test."""
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


# ------------------------------------------------------------- HKDF-SHA256
def _hkdf_sha256(ikm, salt, info, length):
    """HKDF (RFC 5869) con SHA-256. Es el cálculo de Lbz0;->b."""
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    ctr = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([ctr]), hashlib.sha256).digest()
        out += t
        ctr += 1
    return out[:length]


# ------------------------------------------------------------- Tink streaming
def _derive_ikm(password=CATALOG_PASSWORD):
    """PBKDF2-HmacSHA256 del ajuste key_secured (jc0.run)."""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), PBKDF2_SALT,
        PBKDF2_ITERATIONS, PBKDF2_KEY_LEN)


def _tink_nonce(prefix, segment_nr, is_last):
    """Nonce GCM de 12 B (Lp5;->i): prefijo(7) + nº BE32 + último(1)."""
    return prefix + struct.pack(">I", segment_nr) + (b"\x01" if is_last else b"\x00")


def tink_stream_decrypt(blob, password=CATALOG_PASSWORD):
    """Descifra un sobre Tink StreamingAead como el de e-san-vpn.json.
    Devuelve el texto plano (bytes). Lanza DecodeError si no verifica."""
    if len(blob) < HEADER_SIZE + TAG_LEN + 1:
        raise DecodeError("TRUNCATED", "El sobre cifrado es demasiado corto.")
    header = blob[:HEADER_SIZE]
    if header[0] != HEADER_FIRST_BYTE:
        raise DecodeError("BAD_HEADER", "La cabecera no empieza por 0x28 (40).")
    hkdf_salt = header[1:33]
    prefix = header[33:40]
    ikm = _derive_ikm(password)
    key = _hkdf_sha256(ikm, hkdf_salt, ASSOCIATED_DATA, 32)
    body = blob[HEADER_SIZE:]
    out = bytearray()
    pos = 0
    segment_nr = 0
    while pos < len(body):
        # El primer segmento de texto cifrado mide 4.056 B; los demás 4.096 B.
        # (La cabecera ocupa los primeros 40 B del búfer de 4.096 B del
        # cifrador; el descifrador lo refleja con limit(4096-40+1).)
        limit = FIRST_SEGMENT_CT if segment_nr == 0 else SEGMENT_CT
        seg = body[pos:pos + limit]
        pos += len(seg)
        is_last = pos >= len(body)
        if len(seg) <= TAG_LEN:
            raise DecodeError("TRUNCATED", "Segmento de texto cifrado demasiado corto.")
        nonce = _tink_nonce(prefix, segment_nr, is_last)
        try:
            out += _aes_gcm_decrypt(key, nonce, seg[:-TAG_LEN], seg[-TAG_LEN:])
        except ValueError as exc:
            raise DecodeError(
                "LIVE_DECRYPT_FAILED",
                "El segmento %d no verifica (tag GCM inválido). El servidor "
                "parece haber cambiado la contraseña o el formato." % segment_nr,
            ) from exc
        segment_nr += 1
    return bytes(out)


def tink_stream_encrypt(plaintext, password=CATALOG_PASSWORD, salt=None, prefix=None):
    """Inverso de tink_stream_decrypt (misma cabecera y segmentación).
    Solo se usa para generar el recurso sintético de --self-test."""
    import os
    if salt is None:
        salt = os.urandom(32)
    if prefix is None:
        prefix = os.urandom(7)
    ikm = _derive_ikm(password)
    key = _hkdf_sha256(ikm, salt, ASSOCIATED_DATA, 32)
    header = bytes([HEADER_FIRST_BYTE]) + salt + prefix
    out = bytearray(header)
    pos = 0
    segment_nr = 0
    first_pt = FIRST_SEGMENT_CT - TAG_LEN
    plain_seg = SEGMENT_CT - TAG_LEN
    while pos < len(plaintext) or segment_nr == 0:
        size = first_pt if segment_nr == 0 else plain_seg
        chunk = plaintext[pos:pos + size]
        pos += len(chunk)
        is_last = pos >= len(plaintext)
        nonce = _tink_nonce(prefix, segment_nr, is_last)
        ct, tag = _aes_gcm_encrypt(key, nonce, chunk)
        out += ct + tag
        segment_nr += 1
        if is_last:
            break
    return bytes(out)


# ------------------------------------------------------------- ED: (Base32)
def _ed_decode(value):
    """Decodifica un valor "ED:<Base32>" a UTF-8; si no es UTF-8 válido
    o no decodifica, devuelve el valor original sin tocar."""
    if not isinstance(value, str) or not value.startswith("ED:"):
        return value
    body = value[3:]
    try:
        raw = base64.b32decode(body + "=" * ((8 - len(body) % 8) % 8))
    except Exception:
        return value
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return value


def _decode_ed_fields(doc):
    """Decodifica en su lugar todos los valores "ED:..." del catálogo."""
    if isinstance(doc, dict):
        return {k: _decode_ed_fields(v) for k, v in doc.items()}
    if isinstance(doc, list):
        return [_decode_ed_fields(v) for v in doc]
    return _ed_decode(doc)


# ------------------------------------------------------------- JSON
def _text(data):
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return data


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
            raise DecodeError("INVALID_JSON", "Número JSON no finito.")
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError as exc:
                raise DecodeError("INVALID_JSON", "Unicode JSON inválido.") from exc
    return doc


def _json(data):
    try:
        doc = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON", "JSON inválido o con claves duplicadas.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El documento debe contener un objeto JSON.")
    return _validate(doc)


def _catalog_json(data: bytes) -> dict:
    doc = _json(data)
    if not isinstance(doc.get("Version"), str) or not doc["Version"]:
        raise DecodeError("WRONG_DOCUMENT", "El catálogo no trae una Version válida.")
    if any(not isinstance(doc.get(k), list) for k in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "Faltan las listas Servers o Networks del catálogo.")
    if not any(doc[k] for k in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "El catálogo no trae servidores ni redes.")
    return _decode_ed_fields(doc)


def _base64_candidates(text):
    """El cuerpo es una sola línea de Base64 (con o sin saltos de línea)."""
    stripped = "".join(text.split())
    if not stripped:
        return []
    try:
        yield base64.b64decode(stripped, validate=False)
    except Exception:
        return


def decode(data) -> dict:
    """API offline: descifra el catálogo completo y devuelve el dict.
    Acepta el cuerpo HTTP crudo (texto Base64), los bytes ya decodificados
    de Base64, o un JSON ya descifrado (p. ej. el recurso de --self-test
    una vez abierto, o un JSON guardado)."""
    text = _text(data)
    if text.lstrip().startswith("{"):
        return _catalog_json(text.encode("utf-8"))
    last_error = None
    for blob in _base64_candidates(text):
        try:
            return _catalog_json(tink_stream_decrypt(blob))
        except DecodeError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    # Quizá ya son los bytes cifrados sin pasar por Base64.
    if isinstance(data, (bytes, bytearray)):
        return _catalog_json(tink_stream_decrypt(bytes(data)))
    raise DecodeError("DECRYPT_FAILED", "No se pudo descifrar el catálogo.")


def run(file_bytes) -> str | None:
    """API offline: JSON completo del catálogo o None; nunca una lista parcial."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


# ------------------------------------------------------------- Descarga
def _https_url(url: str):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment):
        raise ValueError("invalid HTTPS URL")


def fetch_catalog(url=CATALOG_URL, timeout=60):
    """GET exactamente como la app: sin autenticación ni parámetros.
    User-Agent Dalvik (el de Python-urllib recibe 403 de Cloudflare)."""
    _https_url(url)
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


# ------------------------------------------------------------- CLI
def _self_test():
    """Descifra el recurso sintético e-san-vpn-test.json (misma contraseña,
    salt y AD que el catálogo real, con servidores ficticios) y comprueba
    la segmentación Tink, el HKDF y la decodificación ED:."""
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "e-san-vpn-test.json")
    with open(path, "rb") as fh:
        doc = decode(fh.read())
    assert doc["Version"] == "99.9-test", doc.get("Version")
    assert len(doc["Servers"]) == 2, len(doc["Servers"])
    assert len(doc["Networks"]) == 1, len(doc["Networks"])
    s0 = doc["Servers"][0]
    assert s0["ServerName"] == "TEST_UDP_01", s0
    assert s0["ServerIP"] == "udp1.test.example.com", s0["ServerIP"]
    import json as _json
    assert _json.loads(s0["UDPConfig"])["auth_str"] == "esan:esan", s0["UDPConfig"]
    s1 = doc["Servers"][1]
    assert s1["ServerIP"] == "thailand1.test.example.com", s1["ServerIP"]
    assert s1["Username"] == "testuser", s1["Username"]
    assert doc["Networks"][0]["PayloadName"] == "Test Network", doc["Networks"][0]
    assert doc["setOpenVPN"].startswith("client\n"), doc["setOpenVPN"][:20]
    # Round-trip del cifrado (misma segmentación, primer segmento 4.056 B).
    plain = json.dumps(doc, ensure_ascii=False).encode("utf-8")
    blob = tink_stream_encrypt(plain)
    assert tink_stream_decrypt(blob) == plain
    return ("self-test OK: Version %s, %d servidores, %d redes, "
            "ED: decodificado, round-trip Tink OK"
            % (doc["Version"], len(doc["Servers"]), len(doc["Networks"])))


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(
        description="Descifrador del catálogo de E-SAN VPN (com.misaki.esanvpn).")
    parser.add_argument("--url", nargs="?", const=CATALOG_URL, default=None,
                        help="Descarga el catálogo de la URL (por defecto %s)." % CATALOG_URL)
    parser.add_argument("--file", default=None,
                        help="Lee el catálogo de un archivo local (Base64 o JSON).")
    parser.add_argument("--self-test", action="store_true",
                        help="Verifica el descifrado con el recurso sintético.")
    parser.add_argument("-o", "--output", default=None,
                        help="Guarda el JSON descifrado en este archivo.")
    args = parser.parse_args(argv)

    if args.self_test:
        print(_self_test())
        return 0
    try:
        if args.url:
            raw = fetch_catalog(args.url)
        elif args.file:
            with open(args.file, "rb") as fh:
                raw = fh.read()
        else:
            parser.error("usa --url, --file o --self-test")
            return 2
        out = run(raw)
        if out is None:
            raise DecodeError("DECRYPT_FAILED", "No se pudo descifrar el catálogo.")
    except DecodeError as exc:
        print("error [%s]: %s" % (exc.code, exc), file=sys.stderr)
        return 1
    except Exception as exc:  # red, tiempo agotado, HTTP 403/404...
        print("error: %s" % exc, file=sys.stderr)
        return 1
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print("guardado en %s" % args.output)
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
