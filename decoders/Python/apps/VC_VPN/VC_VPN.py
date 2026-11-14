#!/usr/bin/env python3
"""VC VPN 8.0 (com.vc.vpn): catalog decoder, local or explicit HTTPS.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
See README.md here.

Method (verified against this APK, versionCode 80, versionName 8.0;
tekidoer framework; NO coverage in the SP-DECODE repo as of 2026-11-14):

  GET https://raw.githubusercontent.com/guruzgh-ed/conf/refs/heads/main/vc.js
  (HTTPS GET, HttpURLConnection; plain GET, no authentication, no
  parameters, no custom headers beyond the platform User-Agent;
  GitHub serves it for any User-Agent; verified live with a Dalvik UA)
  -> body is one line:  STGCM3.VC.<b64url(IV 12 B)>.<b64url(ct + tag 16 B)>
  -> AES-256-GCM, key KEY_CONFIG3, AAD = b"STGCM3.VC." (the 10-byte
     prefix, including the trailing dot)
  -> JSON with version, schema_version, config_revision, url_updater,
     minimum_app_version, force_update, Servers[] and Tweaks[] (the app
     calls them "Tweaks", other batches call them networks/payloads)
  -> every string value inside the JSON is itself encoded, one of:
       * r95 obfuscation (r95.lI11Il1): per char index i, i%4==0 ->
         char XOR 0x57712; i%4==1 -> char XOR 0x5a0c38d7; i%4==2 ->
         char XOR 0xA25A5826; i%4==3 -> bitwise NOT char (all masked
         to 16 bits; self-inverse). Detected by the obfuscated alphabet
         (U+3800-U+38FF, U+5800-U+58FF, U+7000-U+7FFF, U+FF80-U+FFDF);
         accepted only if the decode leaves no such char. Plain text
         that merely contains an emoji (e.g. tweak Names
         "🌏 Worldwide | ...") is NOT obfuscated and is left as-is.
         Decoded surrogate pairs are combined into the real emoji
         code point.
       * "u8:" + Base64 (message fields)
       * "VCCR1.<b64url(IV 12 B)>.<b64url(ct + tag 16 B)>" -> AES-256-GCM,
         key KEY_CRED, AAD = b"VCCR1." (credentials, UDP details,
         tweak Payloads)

Keys (public app-wide format constants, recovered from libfrkudp.so;
NOT account credentials). Each key is derived from a 32-byte .rodata
blob as key[i] = blob[i] XOR 0xa7 XOR ((base + 73*i) & 0xff):
  KEY_CONFIG3 (STGCM3 config): blob @ .rodata 0x44d30
      6c80189ce9c46ec50efece48e88de8fd35814c8ea3b40e1105908db1059be931, base 0x51
      -> 9abd5c173bddce3230bb429bf22c00c2730c9895015d3e568b459112efaa91be
  KEY_CRED (VCCR1 credential): blob @ .rodata 0x44d50
      a0e8020aff929a76dfd3894017496a8f402d921985c9d48cc1554f560496bd20, base 0x71
      -> 76f5a6e1cdeb1aa1c17665736dc8a290e6c0a6620700c42b2f6033d5ce87e5cf
  KEY_CONFIG2 (STGCM2 config, legacy variant, same envelope shape):
      blob @ .rodata 0x44d70
      7074d49143dea694ae2a0975e645c9f5b7c905367b83c81e0739f746844dea84, base 0x5d
      -> 8a759c0e65b3126fac63995288f035f6fd58dd59cd7ecc5595e097f17a48a617
The keys were derived by disassembling the three key-setup functions
in libfrkudp.so (0xd7224 base 0x51, 0xd7540 base 0x71, 0xd5850 base 0x5d)
and verified by pure-Python decryption of the shipped seed config
(zf1.l1I1Il1) and of the live catalog (GCM tags verify).

Live test (2026-11-14, --url): HTTP 200, 381,999 bytes,
SHA-256 fef0820b259d05feb31659aade9e2be5abc0c1d95c4c96892d8a60fa42c600ab,
catalog version 1.4, schema_version 2, config_revision 15,
minimum_app_version 79, force_update true, 19 servers
(19 PREMIUM, 0 free), 634 tweaks, 311 with Payload,
340 VCCR1 values, all decrypting (0 failures), 1,966 r95 values,
all decoding (0 failures).
Bundled seed config (zf1.l1I1Il1, the first-run config): version 0.1,
1 server, 1 tweak; used by --self-test.

File formats: the app opens .tgv files (VIEW intent-filter on
MainActivity, file/content schemes) — a .tgv file is a text file with
an STGCM2/STGCM3.VC. envelope, the same as the catalog body; see
VC_VPN_archivos.py. The app exports .vcv files
(Documents/<app name>/<name>.vcv) as
TekProtect.nEncryptUserConfig(JSON {"VCV_CONFIG": <profile>}); that
envelope lives in the native library behind libc++ std::string and
could NOT be solved offline (no real .vcv sample exists) — see
VC_VPN_archivos.py, which detects .vcv and reports VCV_PENDING.
Text links: the manifest declares NO custom scheme (only the .tgv
file VIEW filter). The catalog's servers contain standard
vless:// / hysteria2:// links as decrypted values; those protocols
are already covered by SP-DECODE.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import struct
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

MAX_BYTES = 5 * 1024 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
CATALOG_URL = "https://raw.githubusercontent.com/guruzgh-ed/conf/refs/heads/main/vc.js"
USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 14; Redmi 14C Build/UQ1A.240205.002)"
LIST_FIELDS = ("Servers", "Tweaks")

KEY_CONFIG3 = bytes.fromhex(
    "9abd5c173bddce3230bb429bf22c00c2730c9895015d3e568b459112efaa91be")
KEY_CONFIG2 = bytes.fromhex(
    "8a759c0e65b3126fac63995288f035f6fd58dd59cd7ecc5595e097f17a48a617")
KEY_CRED = bytes.fromhex(
    "76f5a6e1cdeb1aa1c17665736dc8a290e6c0a6620700c42b2f6033d5ce87e5cf")

# The app's shipped first-run seed config (gf1.I1l1Il1, STGCM3 envelope);
# a real test vector from the APK itself, used by --self-test.
SEED_BLOB = "STGCM3.VC.GbWNPkOQnP8pwcHZ._Nt7KDGEGpmssB1jRjcARxwlg8FVa__DCDPHxg1YXYuRa5W7ZpZ_yLlfZhGkYPiCV_Acz06IkppsqQVWa-jTnQewe44zo8q57JvPzsJUlWSR5jwuwqIGAnabyHMIw5eix7XiTfP9PX15AcigkplVAoTsZlFveDFzVHcgG5rW0NwIvJaXyGh3XwPJl0TTN5jNf6ahoSFr5dUYtAtFuPODUY3phIhSL4GT4S5xe4wPWrcqU9ofmPoTYli4L3RvV3ZCT_sUGxPQZcs6rJ__d2R4JDrsos06mGKGwm8-bMfdeiAGMTZ2ORgzY5yF4cQeIF0qMitipvPFt3700V10KJlI3jhJaYjTZxcTwcwN073zS_ZsNSYNbuteHiEjVUjglgpGRg2S_Ws17eDhSRjjU4NPW4kZ0dWp6gJIsHVkJIW_tm3xDNb4GOgUGyNtmxp67R_oYUnXipZXHd6kG5M0y99-Q_z7f-4-0N8e6ztsO3OyK2eKr0b5LsnwQ9BB9xMYK4Td_8ZOGIfFglPolkcATtckF0UopgaRRwu7vHh0IkbMpizv1rpxl4mEP_ciZmkxPYiqZKYut6ZnVe-qJKx_YgmQiGdxeh5YgDiQw__KUiqJsh-p6uQt6GyjLqkd8x7uEX0Uh0u5khUDjF06u13taUaRTa8leowZllcahfCR2Y5536-eQIeY5p7FNEVLA90BC8jxGnYF8R5bZIKe3CPTmh516OH8lvKl0ikT4AKeRIDmWuR9NCQ5OxMuRFntWDL0XYmPNY6QtnW-y6P98t5SDhZmZFLAyOsUjb1RWxCJc1Y6JPBRD_em7DdsijFAxBB3SUQUv5IVzR9SQEivEGR4wCV60gUQpKqxv-n_Qz135FO0lY58ni-uD6oy0RC0glABNRQxjAoJJ6HQSsstnSi8Um5cCQIkrg_tLCYhxvwEv6Ubfv0DjmBFhOeNHhkXgF-tJpxDqW-fQbS0_ctv5KflqsTzaKebmq9iEvEA29mt0Ly_kHiXm0ZRXMRDg6rXylw0_9_NuQEB1sfmhH-zo40zJvWfHwSlpGLoqtYldflu6vC-Qq6OA61a2Et43JoUJ3KAaGds2-qaJpPl564O9Ga0e6qkSzS_EuWvqGNJcT9sbWklzsj8uF49F4G4DpxcBAkJT0XBd1-km0lhJWZuUtnV4XJ_0AXXzrDWp4kz1t346QCyxphmchn2FNC_6lMblUOat-ruQS7OFLCzWh5GwmZWUfU-3p_ml2G4mlDKrx-RGuos0jOpItBiO7aBs21G41N9UhrVC0L9DD4z7CT2qn9AkzZ-1Gx-HHxGmLbFTwGfhsE-q5OkzLBuJrVyB78Lev-_qw19BjWULcc9JnzsqtLo1Lk-QxqJLafHkXf9_a7lB1dYDLtP-yMATbbyPGpkmpoe29F1n8Aru-VmBKIawxkSArREf8N78dVAYtbeZsHfEfbm3rqcsKWbr7oQX21_0CRmzGu2-D3T-rBYvGDMJLTn4MIDab2YBPmPnOTBeSWnROj2tFaY-V1QomLXwvSu423InxU9mVT03AqrCc4xO7OljbJ5HnLoXAoUAeEgEDb5vcNuPoOvvCsQ34T4kWoTrNHMFdT4SNRMp1mYa9sAnZyEhewmG_Pk"


class DecodeError(ValueError):
    """Error de descifrado con un código estable para SP-DECODE."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------- AES-256-GCM
# AES en Python puro (mismo núcleo verificado en E_SAN_VPN.py / RNV).
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
    Solo se usa para el round-trip de --self-test."""
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


# ------------------------------------------------------------- Envoltorios
def _b64url_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decrypt_envelope(text, prefix, key):
    """Abre STGCM2.VC./STGCM3.VC./VCCR1. y devuelve el texto plano."""
    if not text.startswith(prefix):
        raise DecodeError("WRONG_DOCUMENT", "El sobre no empieza por %s" % prefix)
    body = text[len(prefix):]
    try:
        iv_text, ct_text = body.split(".", 1)
        iv = _b64url_decode(iv_text)
        raw = _b64url_decode(ct_text)
    except (ValueError, Exception) as exc:
        raise DecodeError("DECRYPT_FAILED", "Sobre mal formado (%s)." % prefix) from exc
    if len(iv) != 12 or len(raw) < 16:
        raise DecodeError("DECRYPT_FAILED", "Sobre %s con IV o tag inválidos." % prefix)
    try:
        return _aes_gcm_decrypt(key, iv, raw[:-16], raw[-16:], aad=prefix.encode("ascii"))
    except ValueError as exc:
        raise DecodeError("DECRYPT_FAILED", "El tag GCM de %s no verifica." % prefix) from exc


def _encrypt_envelope(plain, prefix, key, iv=b"\x00" * 12):
    """Cifra un sobre (solo para el round-trip de --self-test)."""
    ct, tag = _aes_gcm_encrypt(key, iv, plain, aad=prefix.encode("ascii"))
    return "%s%s.%s" % (prefix, _b64url_encode(iv), _b64url_encode(ct + tag))


# ------------------------------------------------------------- r95 / valores
def _r95(text):
    """Ofuscación de MainActivity.j0 / r95.lI11Il1 (auto-inversa)."""
    out = []
    for i, ch in enumerate(text):
        c = ord(ch)
        m = i % 4
        if m == 0:
            c ^= 0x57712
        elif m == 1:
            c ^= 0x5a0c38d7
        elif m == 2:
            c ^= 0xA25A5826
        else:
            c = (~c) & 0xFFFF
        out.append(chr(c & 0xFFFF))
    return "".join(out)


def _is_obf_char(ch):
    o = ord(ch)
    return (0x3800 <= o <= 0x38FF) or (0x5800 <= o <= 0x58FF) \
        or (0x7000 <= o <= 0x7FFF) or (0xFF80 <= o <= 0xFFDF)


def _combine_surrogates(text):
    """Une pares sustitutos UTF-16 (emoji) en su punto de código real."""
    out = []
    i = 0
    while i < len(text):
        c = ord(text[i])
        if 0xD800 <= c <= 0xDBFF and i + 1 < len(text) \
                and 0xDC00 <= ord(text[i + 1]) <= 0xDFFF:
            out.append(chr(0x10000 + ((c - 0xD800) << 10) + (ord(text[i + 1]) - 0xDC00)))
            i += 2
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def _decode_value(value):
    """Decodifica un valor de cadena del catálogo (VCCR1. / u8: / r95)."""
    if not isinstance(value, str):
        return value
    if value.startswith("VCCR1."):
        try:
            return _combine_surrogates(
                _decrypt_envelope(value, "VCCR1.", KEY_CRED).decode("utf-8"))
        except (DecodeError, UnicodeDecodeError):
            return value
    if value.startswith("u8:"):
        try:
            return _combine_surrogates(base64.b64decode(value[3:]).decode("utf-8"))
        except Exception:
            return value
    if any(_is_obf_char(c) for c in value):
        decoded = _r95(value)
        if not any(_is_obf_char(c) for c in decoded):
            return _combine_surrogates(decoded)
    return value


def _decode_values(doc):
    if isinstance(doc, dict):
        return {k: _decode_values(v) for k, v in doc.items()}
    if isinstance(doc, list):
        return [_decode_values(v) for v in doc]
    return _decode_value(doc)


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
    if not isinstance(doc.get("version"), str) or not doc["version"]:
        raise DecodeError("WRONG_DOCUMENT", "El catálogo no trae una version válida.")
    if any(not isinstance(doc.get(k), list) for k in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "Faltan las listas Servers o Tweaks del catálogo.")
    if not any(doc[k] for k in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "El catálogo no trae servidores ni tweaks.")
    return _decode_values(doc)


def decode(data) -> dict:
    """API offline: descifra el catálogo completo y devuelve el dict.
    Acepta el cuerpo HTTP crudo (sobre STGCM3.VC. o STGCM2.VC.), o un
    JSON ya descifrado."""
    text = _text(data)
    if len(text) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El catálogo supera el tamaño máximo.")
    stripped = text.strip()
    if stripped.startswith("{"):
        return _catalog_json(stripped.encode("utf-8"))
    last_error = None
    for prefix, key in (("STGCM3.VC.", KEY_CONFIG3), ("STGCM2.VC.", KEY_CONFIG2)):
        if stripped.startswith(prefix):
            try:
                return _catalog_json(_decrypt_envelope(stripped, prefix, key))
            except DecodeError as exc:
                last_error = exc
    if last_error is not None:
        raise last_error
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
    """GET exactamente como la app en una primera descarga: sin
    autenticación ni parámetros; la app solo añade If-None-Match /
    If-Modified-Since cuando ya tiene un etag guardado."""
    _https_url(url)
    req = Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
    })
    with urlopen(req, timeout=timeout) as resp:
        return resp.read()


# ------------------------------------------------------------- CLI
def _self_test():
    """Vector real (seed del APK) + round-trips de los tres sobres y r95."""
    doc = decode(SEED_BLOB)
    assert doc["version"] == "0.1", doc.get("version")
    assert doc["url_updater"] == CATALOG_URL, doc.get("url_updater")
    assert len(doc["Servers"]) == 1, len(doc["Servers"])
    assert len(doc["Tweaks"]) == 1, len(doc["Tweaks"])
    s0 = doc["Servers"][0]
    assert s0["Name"] == "VC VPN", s0
    assert s0["Category"] == "PREMIUM", s0
    assert s0["SSHPort"] == "22", s0
    assert s0["UDPDetails"] == "edd.com#edd#edd", s0
    t0 = doc["Tweaks"][0]
    assert t0["Name"] == "VC VPN", t0
    assert t0["Mode"] == 6, t0
    # Round-trip STGCM3 + VCCR1 + r95 (r95 es auto-inverso).
    plain = json.dumps(doc, ensure_ascii=False).encode("utf-8")
    blob = _encrypt_envelope(plain, "STGCM3.VC.", KEY_CONFIG3)
    assert _decrypt_envelope(blob, "STGCM3.VC.", KEY_CONFIG3) == plain
    cred = _encrypt_envelope(b"testuser#testpass#1234", "VCCR1.", KEY_CRED)
    assert _decrypt_envelope(cred, "VCCR1.", KEY_CRED) == b"testuser#testpass#1234"
    legacy = _encrypt_envelope(plain, "STGCM2.VC.", KEY_CONFIG2)
    assert _decrypt_envelope(legacy, "STGCM2.VC.", KEY_CONFIG2) == plain
    sample = "VC VPN | Working Good \U0001F44D"
    # r95 opera por unidades UTF-16 (como en Java): el emoji es un par
    # sustituto, no un solo punto de código.
    raw16 = sample.encode("utf-16-be")
    units = "".join(chr(c) for c in struct.unpack(">%dH" % (len(raw16) // 2), raw16))
    assert _r95(_r95(units)) == units
    assert _combine_surrogates(_r95(_r95(units))) == sample
    assert _decode_value(_r95("22")) == "22"
    return ("self-test OK: seed version %s, %d servidor, %d tweak, "
            "VCCR1. decodificado, round-trip STGCM3/STGCM2/VCCR1/r95 OK"
            % (doc["version"], len(doc["Servers"]), len(doc["Tweaks"])))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Descifrador del catálogo de VC VPN (com.vc.vpn).")
    parser.add_argument("--url", nargs="?", const=CATALOG_URL, default=None,
                        help="Descarga el catálogo de la URL (por defecto %s)." % CATALOG_URL)
    parser.add_argument("--file", default=None,
                        help="Lee el catálogo de un archivo local (sobre o JSON).")
    parser.add_argument("--self-test", action="store_true",
                        help="Verifica el descifrado con el seed real del APK.")
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
