#!/usr/bin/env python3
"""WyrVPN - Free VPN Proxy (com.wyrhub.vpn) 2.6.9 (build 473) - archivos .wyr.

Formatos (verificados con el archivo real
"Tanzania - Vodacom FR 2" exportado por la app y con el codigo Java de la app,
clase defpackage.ni1; sin tocar codigo nativo):

1) PLANO (exportacion sin proteccion, el caso del archivo real):
   texto "wyrvpn://" + Base64("v01" || nonce[12] || AES-128-GCM(ct || tag))
   con la clave REQ_KEY (16 B ASCII, constante de formato; vive solo en este
   script). El texto plano es un JSON array con 1+ perfiles; los campos
   internos http, sni, dnstt_dns, custom_proxy, v2ray_host y v2ray_json son a
   su vez sobres v01 con la misma clave (vacio = sobre de 0 bytes).

2) WVE1 (exportacion protegida, sin muestra real todavia):
   texto "wyrvpn://p/" | "wyrvpn://h/" | "wyrvpn://h/p/" + Base64(binario):
     "WVE1" || version:u8 (1=contrasena, 2=dispositivo, 3=ambos)
       [si bit0] iteraciones:u32 (100000 al sellar) || salt[16]
       [si bit1] n:u16 (1..32) || por cada uno: len:u16 || clave envuelta
       body_len:u32 || body (nonce[12] || AES-GCM(ct || tag))
   - Clave de contrasena: PBKDF1-HmacSHA256(contrasena, salt, iteraciones)
     (U1 = HMAC(pw, salt||INT(1)); Ui = HMAC(pw, U{i-1}); clave = XOR de
     todos los Ui). Solo contrasena: el cuerpo se cifra directo con esa
     clave y AAD "WVE1|1|payload".
   - Clave de dispositivo: SHA-256(b"wyrvpn-envelope-hwid-v1\\x00" + hwid).
     El cuerpo se cifra con una CEK aleatoria de 32 B y AAD "WVE1|v|payload";
     la CEK se envuelve por dispositivo con AES-GCM y AAD "WVE1|v|hwid".
   - Ambos: la CEK se envuelve primero con la clave de contrasena
     (AAD "WVE1|3|password-cek") y luego por dispositivo.
   - El texto plano dentro de WVE1 es a su vez un "wyrvpn://..." plano (caso 1).
   Los AAD son literales "WVE1|<version>|<etiqueta>" (ni1.a()).

La app tambien acepta los archivos por intent VIEW (HtFileHandlerActivity):
mime types application/x-wyr-config, application/wyr, text/plain,
application/octet-stream y patron de ruta .*.(wyr|txt). No hay intent-filter
para el esquema wyrvpn:// en el manifest: el esquema es solo texto para
pegar/compartir.

Python 3.10+, solo biblioteca estandar. AES-128/256-GCM en Python puro.
"""
import argparse
import base64
import hashlib
import hmac as hmac_mod
import json
import os
import struct
import sys

REQ_KEY = b"84EE1C1019099C62"
HWID_PREFIX = b"wyrvpn-envelope-hwid-v1\x00"
INNER_V01_FIELDS = ("http", "sni", "dnstt_dns", "custom_proxy", "v2ray_host",
                    "v2ray_json")
PREFIX_PLAIN = "wyrvpn://"
PREFIX_PW = "wyrvpn://p/"
PREFIX_HWID = "wyrvpn://h/"
PREFIX_BOTH = "wyrvpn://h/p/"
WVE1_MAGIC = b"WVE1"
PBKDF1_ITERATIONS = 100000


class WyrError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------- AES-128/256-GCM
# Python puro (mismo nucleo que WyrVPN.py / TSC VPN Proxy / RNV Tunnel VPN).
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
                    aa = ((aa << 1) ^ (0x1B if aa & 0x80 else 0)) & 0xFF
                    bb >>= 1
                if p == 1:
                    inv = y
                    break
        s = inv ^ ((inv << 1) | (inv >> 7)) ^ ((inv << 2) | (inv >> 6)) \
            ^ ((inv << 3) | (inv >> 5)) ^ ((inv << 4) | (inv >> 4)) ^ 0x63
        sbox.append(s & 0xFF)
    return sbox


_SBOX = _make_sbox()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D]
_GCM_R = 0xE1000000000000000000000000000000


def _aes_key_expand(key):
    if len(key) not in (16, 24, 32):
        raise ValueError("clave AES de 16, 24 o 32 bytes")
    nk = len(key) // 4
    nr = nk + 6
    w = list(struct.unpack(">%dI" % nk, key))
    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            rot = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF
            sub = (_SBOX[(rot >> 24) & 0xFF] << 24) | (_SBOX[(rot >> 16) & 0xFF] << 16) \
                | (_SBOX[(rot >> 8) & 0xFF] << 8) | _SBOX[rot & 0xFF]
            temp = sub ^ (_RCON[i // nk - 1] << 24)
        elif nk > 6 and i % nk == 4:
            temp = (_SBOX[(temp >> 24) & 0xFF] << 24) | (_SBOX[(temp >> 16) & 0xFF] << 16) \
                | (_SBOX[(temp >> 8) & 0xFF] << 8) | _SBOX[temp & 0xFF]
        w.append(w[i - nk] ^ temp)
    return w, nr


def _aes_encrypt_block(key_words, nr, block):
    s = list(struct.unpack(">4I", block))
    rk = key_words
    for i in range(4):
        s[i] ^= rk[i]
    for rnd in range(1, nr):
        b = bytearray(16)
        for i in range(4):
            for j in range(4):
                b[4 * j + i] = _SBOX[(s[j] >> (24 - 8 * i)) & 0xFF]
        sb = bytearray(16)
        for r in range(4):
            for c in range(4):
                sb[4 * c + r] = b[4 * ((c + r) % 4) + r]

        def xtime(x):
            return ((x << 1) ^ (0x1B if x & 0x80 else 0)) & 0xFF
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
            b[4 * j + i] = _SBOX[(s[j] >> (24 - 8 * i)) & 0xFF]
    sb = bytearray(16)
    for r in range(4):
        for c in range(4):
            sb[4 * c + r] = b[4 * ((c + r) % 4) + r]
    s = list(struct.unpack(">4I", bytes(sb)))
    for i in range(4):
        s[i] ^= rk[4 * nr + i]
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
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    kw, nr = _aes_key_expand(key)
    h = int.from_bytes(_aes_encrypt_block(kw, nr, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    pt = bytearray()
    counter = 1
    for i in range(0, len(ciphertext), 16):
        chunk = ciphertext[i:i + 16]
        ctr = nonce + struct.pack(">I", counter + 1)
        ks = _aes_encrypt_block(kw, nr, ctr)
        pt += bytes(a ^ b for a, b in zip(chunk, ks))
        counter += 1

    def pad16(d):
        return d + b"\x00" * ((-len(d)) % 16)
    s = _ghash(h, pad16(aad) + pad16(ciphertext)
               + struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8))
    ej0 = _aes_encrypt_block(kw, nr, j0)
    calc_tag = (s ^ int.from_bytes(ej0, "big")).to_bytes(16, "big")
    if calc_tag != tag:
        raise ValueError("GCM tag mismatch")
    return bytes(pt)


def _aes_gcm_encrypt(key, nonce, plaintext, aad=b""):
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    kw, nr = _aes_key_expand(key)
    h = int.from_bytes(_aes_encrypt_block(kw, nr, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    ct = bytearray()
    counter = 1
    for i in range(0, len(plaintext), 16):
        chunk = plaintext[i:i + 16]
        ctr = nonce + struct.pack(">I", counter + 1)
        ks = _aes_encrypt_block(kw, nr, ctr)
        ct += bytes(a ^ b for a, b in zip(chunk, ks))
        counter += 1

    def pad16(d):
        return d + b"\x00" * ((-len(d)) % 16)
    s = _ghash(h, pad16(aad) + pad16(bytes(ct))
               + struct.pack(">QQ", len(aad) * 8, len(ct) * 8))
    ej0 = _aes_encrypt_block(kw, nr, j0)
    tag = (s ^ int.from_bytes(ej0, "big")).to_bytes(16, "big")
    return bytes(ct), tag


# ------------------------------------------------------------ sobre v01
def v01_encrypt(plain, key=REQ_KEY):
    nonce = os.urandom(12)
    ct, tag = _aes_gcm_encrypt(key, nonce, plain)
    return base64.b64encode(b"v01" + nonce + ct + tag).decode()


def v01_decrypt(b64, key=REQ_KEY):
    try:
        raw = base64.b64decode(b64, validate=False)
    except Exception as exc:
        raise WyrError("V01_BASE64", "sobre v01 con Base64 invalido") from exc
    if len(raw) < 3 + 12 + 16 or raw[:3] != b"v01":
        raise WyrError("V01_MAGIC", "el sobre no empieza por 'v01'")
    try:
        return _aes_gcm_decrypt(key, raw[3:15], raw[15:-16], raw[-16:])
    except ValueError as exc:
        raise WyrError("V01_TAG", "el tag GCM no verifica con esta clave") from exc


# ------------------------------------------------------------ WVE1
def _aad(version, label):
    """AAD de ni1.a(): literal 'WVE1|<version>|<etiqueta>' en UTF-8."""
    return ("WVE1|%d|%s" % (version, label)).encode()


def _pbkdf1_hmac_sha256(password, salt, iterations):
    """PBKDF1 (RFC 2898) con HMAC-SHA256 (ni1.m()): U1 = HMAC(pw, salt||1);
    Ui = HMAC(pw, U{i-1}); clave = XOR de todos los Ui."""
    pw = password.encode("utf-8")
    u = hmac_mod.new(pw, salt + struct.pack(">I", 1), hashlib.sha256).digest()
    out = bytearray(u)
    for _ in range(1, iterations):
        u = hmac_mod.new(pw, u, hashlib.sha256).digest()
        for i in range(len(out)):
            out[i] ^= u[i]
    return bytes(out)


def _device_key(hwid):
    """Clave de dispositivo (ni1.f()): SHA-256(prefijo + HWID en mayusculas)."""
    return hashlib.sha256(HWID_PREFIX + hwid.strip().upper().encode()).digest()


def _gcm_wrap(key, aad, plaintext):
    nonce = os.urandom(12)
    ct, tag = _aes_gcm_encrypt(key, nonce, plaintext, aad)
    return nonce + ct + tag


def _gcm_unwrap(key, aad, blob):
    if len(blob) < 12 + 16:
        raise WyrError("WVE1_SHORT", "envoltorio GCM demasiado corto")
    try:
        return _aes_gcm_decrypt(key, blob[:12], blob[12:-16], blob[-16:], aad)
    except ValueError as exc:
        raise WyrError("WVE1_TAG", "el tag GCM no verifica") from exc


def parse_wve1(data):
    """Desarma un binario WVE1 -> dict. Lanza WyrError si el formato es malo."""
    if len(data) < 4 + 1 + 4 or data[:4] != WVE1_MAGIC:
        raise WyrError("WVE1_MAGIC", "el binario no empieza por 'WVE1'")
    off = 4
    version = data[off]
    off += 1
    if version not in (1, 2, 3):
        raise WyrError("WVE1_VERSION", "version WVE1 no soportada: %d" % version)
    salt = None
    iterations = 0
    if version & 1:
        if len(data) < off + 4 + 16:
            raise WyrError("WVE1_SHORT", "falta salt de contrasena")
        iterations = struct.unpack(">I", data[off:off + 4])[0]
        off += 4
        if not 10000 <= iterations <= 500000:
            raise WyrError("WVE1_ITER", "iteraciones fuera de rango: %d" % iterations)
        salt = data[off:off + 16]
        off += 16
    wrapped = []
    if version & 2:
        if len(data) < off + 2:
            raise WyrError("WVE1_SHORT", "falta lista de claves envueltas")
        count = struct.unpack(">H", data[off:off + 2])[0]
        off += 2
        if not 1 <= count <= 32:
            raise WyrError("WVE1_COUNT", "numero de dispositivos fuera de rango: %d" % count)
        for _ in range(count):
            if len(data) < off + 2:
                raise WyrError("WVE1_SHORT", "falta longitud de clave envuelta")
            ln = struct.unpack(">H", data[off:off + 2])[0]
            off += 2
            if not 28 <= ln <= 4096 or len(data) < off + ln:
                raise WyrError("WVE1_LEN", "longitud de clave envuelta invalida: %d" % ln)
            wrapped.append(data[off:off + ln])
            off += ln
    if len(data) < off + 4:
        raise WyrError("WVE1_SHORT", "falta longitud del cuerpo")
    body_len = struct.unpack(">I", data[off:off + 4])[0]
    off += 4
    if not 28 <= body_len <= 4194304 or len(data) != off + body_len:
        raise WyrError("WVE1_LEN", "longitud del cuerpo invalida: %d" % body_len)
    return {"version": version, "iterations": iterations, "salt": salt,
            "wrapped": wrapped, "body": data[off:off + body_len]}


def build_wve1(version, salt, iterations, wrapped, body):
    out = bytearray(WVE1_MAGIC)
    out.append(version)
    if version & 1:
        out += struct.pack(">I", iterations)
        out += salt
    if version & 2:
        out += struct.pack(">H", len(wrapped))
        for w in wrapped:
            out += struct.pack(">H", len(w))
            out += w
    out += struct.pack(">I", len(body))
    out += body
    return bytes(out)


def open_wve1(data, password=None, hwids=()):
    """Abre un binario WVE1 -> texto plano 'wyrvpn://...' (str).
    password: contrasena de exportacion (o None). hwids: lista de HWIDs a
    probar (la app usa el HWID del dispositivo que exporto)."""
    env = parse_wve1(data)
    version = env["version"]
    if version & 2:
        if not hwids:
            raise WyrError("HWID_REQUIRED",
                           "este archivo esta atado a dispositivos; falta --hwid")
        cek = None
        for hwid in hwids:
            key = _device_key(hwid)
            for wrapped in env["wrapped"]:
                try:
                    cek = _gcm_unwrap(key, _aad(version, "hwid"), wrapped)
                    break
                except WyrError:
                    continue
            if cek is not None:
                break
        if cek is None:
            raise WyrError("HWID_NOT_AUTHORIZED",
                           "ningun HWID abre este archivo")
        if version & 1:
            if not password:
                raise WyrError("PASSWORD_REQUIRED",
                               "este archivo tambien pide contrasena")
            pwkey = _pbkdf1_hmac_sha256(password, env["salt"], env["iterations"])
            try:
                cek = _gcm_unwrap(pwkey, _aad(version, "password-cek"), cek)
            except WyrError as exc:
                raise WyrError("WRONG_PASSWORD", "contrasena incorrecta") from exc
            if len(cek) != 32:
                raise WyrError("WVE1_CEK", "la CEK descifrada no mide 32 bytes")
        return _gcm_unwrap(cek, _aad(version, "payload"), env["body"]).decode("utf-8")
    # solo contrasena
    if not password:
        raise WyrError("PASSWORD_REQUIRED", "este archivo pide contrasena")
    pwkey = _pbkdf1_hmac_sha256(password, env["salt"], env["iterations"])
    try:
        return _gcm_unwrap(pwkey, _aad(version, "payload"), env["body"]).decode("utf-8")
    except WyrError as exc:
        raise WyrError("WRONG_PASSWORD", "contrasena incorrecta") from exc


def seal_wve1(plain_text, password=None, hwids=()):
    """Sella un texto 'wyrvpn://...' en WVE1. Devuelve el texto completo
    con su prefijo ('wyrvpn://p/' | 'wyrvpn://h/' | 'wyrvpn://h/p/')."""
    if not plain_text.startswith(PREFIX_PLAIN):
        raise WyrError("SEAL_INPUT", "el texto a sellar debe empezar por 'wyrvpn://'")
    pw = (password or "").strip()
    devs = []
    for item in hwids:
        for part in str(item).replace(";", ",").split(","):
            part = part.strip().upper()
            if part:
                devs.append(part)
    devs = list(dict.fromkeys(devs))  # sin duplicados, en orden
    if not pw and not devs:
        return plain_text
    version = (1 if pw else 0) | (2 if devs else 0)
    plain = plain_text.encode("utf-8")
    if devs:
        cek = os.urandom(32)
        body = _gcm_wrap(cek, _aad(version, "payload"), plain)
        inner = cek
        salt = None
        if pw:
            salt = os.urandom(16)
            pwkey = _pbkdf1_hmac_sha256(pw, salt, PBKDF1_ITERATIONS)
            inner = _gcm_wrap(pwkey, _aad(version, "password-cek"), cek)
        wrapped = []
        for hwid in devs:
            wrapped.append(_gcm_wrap(_device_key(hwid), _aad(version, "hwid"), inner))
        blob = build_wve1(version, salt, PBKDF1_ITERATIONS, wrapped, body)
    else:
        salt = os.urandom(16)
        pwkey = _pbkdf1_hmac_sha256(pw, salt, PBKDF1_ITERATIONS)
        body = _gcm_wrap(pwkey, _aad(version, "payload"), plain)
        blob = build_wve1(version, salt, PBKDF1_ITERATIONS, [], body)
    prefix = {1: PREFIX_PW, 2: PREFIX_HWID, 3: PREFIX_BOTH}[version]
    return prefix + base64.b64encode(blob).decode()


# ------------------------------------------------------------ perfiles
def _decrypt_inner(value):
    """Descifra un campo interno si es un sobre v01; si no, lo deja tal cual."""
    if isinstance(value, str) and value.startswith("djAx"):
        try:
            return v01_decrypt(value, REQ_KEY).decode("utf-8")
        except WyrError:
            return value
    return value


def _encrypt_inner(value):
    if value is None:
        return value
    return v01_encrypt(str(value).encode(), REQ_KEY)


def open_text(text, password=None, hwids=()):
    """Abre un texto .wyr / wyrvpn:// -> (perfiles, variante).
    Variante: 'plain' | 'password' | 'hwid' | 'both'."""
    text = (text or "").strip().lstrip("\ufeff").strip()
    if not text:
        raise WyrError("EMPTY", "texto vacio")
    if text.startswith(PREFIX_BOTH):
        variant = "both"
        b64 = text[len(PREFIX_BOTH):]
    elif text.startswith(PREFIX_HWID):
        variant = "hwid"
        b64 = text[len(PREFIX_HWID):]
    elif text.startswith(PREFIX_PW):
        variant = "password"
        b64 = text[len(PREFIX_PW):]
    elif text.startswith(PREFIX_PLAIN):
        variant = "plain"
        b64 = text[len(PREFIX_PLAIN):]
    elif text.startswith("WVE1"):
        raise WyrError("WVE1_TEXT", "esto parece Base64 de WVE1 sin prefijo wyrvpn://")
    else:
        raise WyrError("BAD_FORMAT", "el texto no empieza por 'wyrvpn://'")
    try:
        raw = base64.b64decode(b64, validate=False)
    except Exception as exc:
        raise WyrError("BASE64", "Base64 invalido tras el prefijo") from exc
    if variant == "plain":
        if raw[:3] != b"v01":
            raise WyrError("V01_MAGIC", "el sobre plano no empieza por 'v01'")
        plain = v01_decrypt(b64, REQ_KEY).decode("utf-8")
    else:
        if raw[:4] != WVE1_MAGIC:
            raise WyrError("WVE1_MAGIC", "el binario no empieza por 'WVE1'")
        plain = open_wve1(raw, password=password, hwids=hwids)
        if not plain.startswith(PREFIX_PLAIN):
            raise WyrError("WVE1_CONTENT",
                           "el contenido WVE1 no es un texto wyrvpn:// plano")
        inner_b64 = plain[len(PREFIX_PLAIN):]
        plain = v01_decrypt(inner_b64, REQ_KEY).decode("utf-8")
    try:
        profiles = json.loads(plain)
    except Exception as exc:
        raise WyrError("JSON", "el texto plano no es JSON valido: %s" % exc) from exc
    if not isinstance(profiles, list):
        profiles = [profiles]
    for prof in profiles:
        if isinstance(prof, dict):
            for field in INNER_V01_FIELDS:
                if field in prof:
                    prof[field] = _decrypt_inner(prof[field])
    return profiles, variant


def open_binary(data, password=None, hwids=()):
    """Abre bytes crudos: binario WVE1 o sobre v01 -> (perfiles, variante)."""
    if data[:4] == WVE1_MAGIC:
        plain = open_wve1(data, password=password, hwids=hwids)
        if not plain.startswith(PREFIX_PLAIN):
            raise WyrError("WVE1_CONTENT",
                           "el contenido WVE1 no es un texto wyrvpn:// plano")
        plain = v01_decrypt(plain[len(PREFIX_PLAIN):], REQ_KEY).decode("utf-8")
        variant = "wve1-binary"
    elif data[:3] == b"v01":
        plain = v01_decrypt(base64.b64encode(data).decode(), REQ_KEY).decode("utf-8")
        variant = "v01-binary"
    else:
        return open_text(data.decode("utf-8", errors="replace"),
                         password=password, hwids=hwids)
    try:
        profiles = json.loads(plain)
    except Exception as exc:
        raise WyrError("JSON", "el texto plano no es JSON valido: %s" % exc) from exc
    if not isinstance(profiles, list):
        profiles = [profiles]
    for prof in profiles:
        if isinstance(prof, dict):
            for field in INNER_V01_FIELDS:
                if field in prof:
                    prof[field] = _decrypt_inner(prof[field])
    return profiles, variant


def seal_profiles(profiles, password=None, hwids=()):
    """Perfiles (lista de dicts) -> texto wyrvpn:// (plano o WVE1)."""
    if isinstance(profiles, dict):
        profiles = [profiles]
    sealed = []
    for prof in profiles:
        prof = dict(prof)
        for field in INNER_V01_FIELDS:
            if field in prof:
                prof[field] = _encrypt_inner(prof[field])
        sealed.append(prof)
    plain = json.dumps(sealed, ensure_ascii=False, separators=(",", ":"))
    text = PREFIX_PLAIN + v01_encrypt(plain.encode(), REQ_KEY)
    if password or hwids:
        text = seal_wve1(text, password=password, hwids=hwids)
    return text


# ------------------------------------------------------------ self-test
def _self_test():
    checks = []

    def check(name, fn):
        try:
            fn()
            checks.append((name, True, ""))
        except Exception as exc:  # noqa: BLE001
            checks.append((name, False, "%s: %s" % (type(exc).__name__, exc)))

    def t_aad():
        assert _aad(1, "payload") == b"WVE1|1|payload"
        assert _aad(3, "password-cek") == b"WVE1|3|password-cek"
        assert _aad(2, "hwid") == b"WVE1|2|hwid"

    def t_pbkdf1():
        k1 = _pbkdf1_hmac_sha256("Ghost", b"\x00" * 16, 1000)
        k2 = _pbkdf1_hmac_sha256("Ghost", b"\x00" * 16, 1000)
        assert k1 == k2 and len(k1) == 32
        k3 = _pbkdf1_hmac_sha256("Ghost", b"\x01" * 16, 1000)
        assert k3 != k1
        # verificacion independiente de la formula PBKDF1
        pw = b"Ghost"
        salt = b"\x00" * 16
        u = hmac_mod.new(pw, salt + struct.pack(">I", 1), hashlib.sha256).digest()
        acc = bytearray(u)
        for _ in range(1, 1000):
            u = hmac_mod.new(pw, u, hashlib.sha256).digest()
            for i in range(32):
                acc[i] ^= u[i]
        assert bytes(acc) == k1

    def t_gcm_oracle():
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            return
        for klen in (16, 32):
            key = os.urandom(klen)
            nonce = os.urandom(12)
            pt = os.urandom(200)
            aad = os.urandom(7)
            ct1 = AESGCM(key).encrypt(nonce, pt, aad)
            ct2, tag2 = _aes_gcm_encrypt(key, nonce, pt, aad)
            assert ct1 == ct2 + tag2
            assert _aes_gcm_decrypt(key, nonce, ct1[:-16], ct1[-16:], aad) == pt

    def t_real_wyr():
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "Tanzania_-_Vodacom_FR_2_26_0_8vue.wyr")
        if not os.path.exists(path):
            return
        with open(path, encoding="utf-8") as fh:
            profiles, variant = open_text(fh.read())
        assert variant == "plain", variant
        assert len(profiles) == 1
        prof = profiles[0]
        assert prof["name"].startswith("\U0001f1f9\U0001f1ff Tanzania - Vodacom FR 2"), prof["name"]
        assert prof["type"] == "CUSTOM"
        assert prof["custom_proxy"] == "umc-cdn.secb2b.com", prof["custom_proxy"]
        assert prof["http"].startswith("GET / HTTP/1.1"), prof["http"][:40]
        assert prof["v2ray_json"] == "" and prof["dnstt_dns"] == ""

    def t_plain_roundtrip():
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "Tanzania_-_Vodacom_FR_2_26_0_8vue.wyr")
        if not os.path.exists(path):
            profiles = [{"name": "Prueba", "type": "CUSTOM", "http": "GET /",
                         "sni": "ejemplo.com", "v2ray_json": ""}]
        else:
            with open(path, encoding="utf-8") as fh:
                profiles, _ = open_text(fh.read())
        sealed = seal_profiles(profiles)
        assert sealed.startswith(PREFIX_PLAIN)
        back, variant = open_text(sealed)
        assert variant == "plain"
        assert back == profiles, (back, profiles)

    def t_wve1_password():
        profiles = [{"name": "Prueba PW", "type": "CUSTOM", "http": "GET /",
                     "sni": "", "v2ray_json": ""}]
        sealed = seal_profiles(profiles, password="Ghost123")
        assert sealed.startswith(PREFIX_PW), sealed[:20]
        back, variant = open_text(sealed, password="Ghost123")
        assert variant == "password" and back == profiles
        try:
            open_text(sealed, password="otra")
        except WyrError as exc:
            assert exc.code == "WRONG_PASSWORD", exc.code
        else:
            raise AssertionError("la contrasena equivocada abrio el archivo")
        try:
            open_text(sealed)
        except WyrError as exc:
            assert exc.code == "PASSWORD_REQUIRED", exc.code
        else:
            raise AssertionError("abrio sin contrasena")

    def t_wve1_hwid():
        profiles = [{"name": "Prueba HWID", "type": "CUSTOM", "http": "GET /",
                     "sni": "", "v2ray_json": ""}]
        sealed = seal_profiles(profiles, hwids=["AABBCCDDEEFF00112233445566778899"])
        assert sealed.startswith(PREFIX_HWID), sealed[:20]
        back, variant = open_text(
            sealed, hwids=["aabbccddeeff00112233445566778899"])
        assert variant == "hwid" and back == profiles
        try:
            open_text(sealed, hwids=["00000000000000000000000000000000"])
        except WyrError as exc:
            assert exc.code == "HWID_NOT_AUTHORIZED", exc.code
            return
        raise AssertionError("un HWID no autorizado abrio el archivo")

    def t_wve1_both():
        profiles = [{"name": "Prueba Ambos", "type": "CUSTOM", "http": "GET /",
                     "sni": "", "v2ray_json": ""}]
        sealed = seal_profiles(profiles, password="Ghost123",
                               hwids=["AABBCCDDEEFF00112233445566778899"])
        assert sealed.startswith(PREFIX_BOTH), sealed[:20]
        back, variant = open_text(sealed, password="Ghost123",
                                  hwids=["AABBCCDDEEFF00112233445566778899"])
        assert variant == "both" and back == profiles
        try:
            open_text(sealed, password="otra",
                      hwids=["AABBCCDDEEFF00112233445566778899"])
        except WyrError as exc:
            assert exc.code == "WRONG_PASSWORD", exc.code
            return
        raise AssertionError("la contrasena equivocada abrio el archivo")

    def t_tamper():
        profiles = [{"name": "Prueba", "type": "CUSTOM", "http": "GET /"}]
        sealed = seal_profiles(profiles)
        raw = bytearray(base64.b64decode(sealed[len(PREFIX_PLAIN):]))
        raw[-1] ^= 1
        bad = PREFIX_PLAIN + base64.b64encode(bytes(raw)).decode()
        try:
            open_text(bad)
        except WyrError as exc:
            assert exc.code == "V01_TAG", exc.code
            return
        raise AssertionError("el sobre alterado no fue rechazado")

    check("AAD WVE1|v|etiqueta", t_aad)
    check("PBKDF1-HmacSHA256 (formula + determinismo)", t_pbkdf1)
    check("aes-gcm contra oraculo", t_gcm_oracle)
    check("archivo .wyr real abre (Tanzania Vodacom)", t_real_wyr)
    check("sellar/abrir plano round-trip", t_plain_roundtrip)
    check("WVE1 solo contrasena + contrasena equivocada", t_wve1_password)
    check("WVE1 solo HWID + HWID no autorizado", t_wve1_hwid)
    check("WVE1 contrasena+HWID", t_wve1_both)
    check("sobre alterado rechazado (tag GCM)", t_tamper)
    failed = [c for c in checks if not c[1]]
    for name, ok, err in checks:
        print(("OK  " if ok else "FAIL") + " " + name + ((" - " + err) if err else ""))
    print("SELF-TEST: %d/%d OK" % (len(checks) - len(failed), len(checks)))
    return 0 if not failed else 1


# ------------------------------------------------------------ CLI
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="WyrVPN 2.6.9 - abre y sella archivos .wyr / wyrvpn://.")
    ap.add_argument("--file", metavar="ARCHIVO",
                    help="archivo .wyr (texto wyrvpn:// o binario WVE1/v01)")
    ap.add_argument("--text", metavar="TEXTO",
                    help="texto wyrvpn:// (pegar el enlace/codigo)")
    ap.add_argument("--seal", action="store_true",
                    help="sellar perfiles JSON (con --in) en vez de abrir")
    ap.add_argument("--in", dest="infile", metavar="JSON",
                    help="perfiles JSON a sellar (array) con --seal")
    ap.add_argument("--password", metavar="CONTRASEÑA",
                    help="contrasena para abrir/sellar WVE1")
    ap.add_argument("--hwid", metavar="HWID[,HWID...]",
                    help="HWID(s) de dispositivo para abrir/sellar WVE1")
    ap.add_argument("--out", metavar="ARCHIVO",
                    help="guardar el resultado en ARCHIVO")
    ap.add_argument("--self-test", action="store_true",
                    help="pruebas internas (sin red)")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()

    hwids = []
    if args.hwid:
        for part in args.hwid.replace(";", ",").split(","):
            part = part.strip()
            if part:
                hwids.append(part)

    if args.seal:
        if not args.infile:
            ap.error("--seal necesita --in ARCHIVO.json con los perfiles")
        with open(args.infile, encoding="utf-8") as fh:
            profiles = json.load(fh)
        text = seal_profiles(profiles, password=args.password, hwids=hwids)
        print(text)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
            print("guardado en %s" % args.out)
        return 0

    if args.file:
        with open(args.file, "rb") as fh:
            data = fh.read()
        try:
            text = data.decode("utf-8")
            profiles, variant = open_text(text, password=args.password, hwids=hwids)
        except (UnicodeDecodeError, WyrError):
            profiles, variant = open_binary(data, password=args.password, hwids=hwids)
    elif args.text:
        profiles, variant = open_text(args.text, password=args.password, hwids=hwids)
    else:
        ap.error("usa --file ARCHIVO.wyr o --text 'wyrvpn://...'")
    print("variante: %s | perfiles: %d" % (variant, len(profiles)))
    for prof in profiles:
        print("  - %s [%s] %s" % (prof.get("name"), prof.get("type"), prof.get("sub")))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(profiles, fh, ensure_ascii=False, indent=2)
        print("guardado en %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
