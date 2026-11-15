#!/usr/bin/env python3
"""Guruz VPN 18.4 (guruz.vpn.tunnel): catalog decoder, local or explicit HTTPS.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
See README.md here.

Method (verified against this APK, versionCode 184, versionName 18.4;
tekidoer framework; NO coverage in the SP-DECODE repo as of 2026-11-13;
this is a DIFFERENT app from guruz.vpn.tunnel / Guruz VPN 18.6,
which uses the same STGCM family with ".GT." / "GVCR1." suffixes and
its own keys -- do NOT reuse that app's method or icon here):

  GET https://raw.githubusercontent.com/guruzgh-ed/edd/refs/heads/main/gv.js
  (HTTPS GET, HttpURLConnection, connect timeout 15 s, read timeout 20 s;
  the app does NOT follow redirects automatically: it only follows a
  redirect whose Location is HTTPS, and it sends If-None-Match /
  If-Modified-Since only when it already has a cached etag / last
  modified value, so a first fetch is a plain GET with the default
  Dalvik User-Agent and no other headers; GitHub serves it for any
  User-Agent; verified byte-identical with a Dalvik UA and with curl;
  the app rejects bodies over 8 MiB)
  -> body is one line:  STGCM3.GV.<b64url(IV 12 B)>.<b64url(ct + tag 16 B)>
  -> AES-256-GCM, key KEY_CONFIG3, AAD = b"STGCM3.GV." (the 10-byte
     prefix, including the trailing dot)
  -> JSON with version, schema_version, config_revision, reset, message,
     url_updater, minimum_app_version, force_update, ad unit ids,
     Servers[] and Tweaks[] (the app calls them "Tweaks", other batches
     call them networks/payloads)
  -> every string value inside the JSON is itself encoded, one of:
       * r95 obfuscation (MainActivity.j0 -> r95.lI11Il1): per char index
         i, i%4==0 -> char XOR 0x57712; i%4==1 -> char XOR 0x5a0c38d7;
         i%4==2 -> char XOR 0xA25A5826; i%4==3 -> bitwise NOT char
         (all masked to 16 bits; self-inverse; same constants as
         Guruz VPN). Detected by the obfuscated alphabet
         (U+3800-U+38FF, U+5800-U+58FF, U+7000-U+7FFF, U+FF80-U+FFDF);
         accepted only if the decode leaves no such char. Plain text
         that merely contains an emoji (e.g. tweak Names
         "Worldwide | ...") is NOT obfuscated and is left as-is.
         Decoded surrogate pairs are combined into the real emoji
         code point.
       * "u8:" + Base64 (message fields)
       * "GVCR1.<b64url(IV 12 B)>.<b64url(ct + tag 16 B)>" -> AES-256-GCM,
         key KEY_CRED, AAD = b"GVCR1." (credentials, vmess/vless/
         wireguard/hysteria2 links, OpenVPN profiles, UDP details,
         tweak Payloads)

Keys (public app-wide format constants, recovered from libfrkudp.so;
NOT account credentials). Each key is derived from a 32-byte .rodata
blob as key[i] = blob[i] XOR 0xa7 XOR ((base + 73*i) & 0xff):
  KEY_CONFIG3 (STGCM3 config): blob @ .rodata 0x4d80c
      477911a22d5f29af1aeb22cb6e15eb18cdee128b59697685518fbf9ad4623e4b, base 0x51
      -> b1445529ff46895824aeae1874b403278b63c690fb8046c2df5aa3393e5346c4
  KEY_CRED (GVCR1 credential): blob @ .rodata 0x4d82c
      9f0954bad62502d88ec880ec14731a83a7ebe1cc7bbadecaff573f9577a2a08e, base 0x71
      -> 4914f051e45c820f906d6cdf6ef2d29c0106d5b7f973ce6d11624316bdb3f861
  KEY_CONFIG2 (STGCM2 config, legacy variant, same envelope shape):
      blob @ .rodata 0x4d84c
      8dca096d81c30165f31b47c41a7dfd4d7d241ea1b2554a6fa51addc5d01228e5, base 0x5d
      -> 77cb41f2a7aeb59ef152d7e374c8014e37b5c6ce04a84e2437c3bd722e176476
The keys were recovered by disassembling the three key-derivation
functions in libfrkudp.so (0xdbcf0 base 0x5d, 0xdcffc base 0x51,
0xdd318 base 0x71; same derivation shape as Guruz VPN, different
blobs/bases) and verified by pure-Python decryption of the shipped
seed config and of the live catalog (GCM tags verify).

Live test (2026-11-13, --url, repo guruzgh-ed/edd): HTTP 200, 601,866
bytes, SHA-256 51cadd312ab151b07029f10ab9b44f63e530ed8f804076b1f3add54bc8195ad4,
catalog version 0.7, config_revision 6, minimum_app_version 184,
force_update true, 49 servers (38 PREMIUM, 10 VIP, 1 PRIVATE, 0 free),
887 tweaks, 436 with Payload, 517 GVCR1. values, all decrypting
(0 failures). The older mirror guruzgh-ed/conf/gv.js serves the same
catalog at config_revision 4 (different body bytes; the two repos hold
different revisions; the app's own url_updater points to edd, so edd
is canonical).
Bundled seed config (md1 <clinit>, the first-run config stored in
system.db): version 0.1, config_revision 1, 1 server, 1 tweak; used
by --self-test. Note the seed's url_updater still points to the old
conf repo -- the app replaces it with the edd URL from the downloaded
config.

The app has no own importable config file format (no ACTION_VIEW file
filter, no own extension, no file picker and no custom URI scheme in
the manifest; the only "import" paths belong to the generic V2Ray ANG
library and handle standard vmess/vless/trojan/ss links and V2Ray
JSON, already covered by SP-DECODE), so there is no
Guruz_VPN_archivos.py. The saved configuration lives encrypted
(STGCM3.GV. blob) in the app's SQLite database system.db,
table spkmoder_table (ID, DATA) -- not in a user file -- and the app
re-downloads it ("re-import") when it cannot be read. Text links: the
manifest declares NO custom scheme and no App Links (only
MAIN/LAUNCHER on SplashActivity). The catalog's servers do contain
standard vmess://, trojan://, wireguard:// and hysteria2:// links as
decrypted values; those protocols are already covered by SP-DECODE.
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
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler

MAX_BYTES = 8 * 1024 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
CATALOG_URL = "https://raw.githubusercontent.com/guruzgh-ed/edd/refs/heads/main/gv.js"
# URL que trae el seed incluido en el APK (el seed es anterior al cambio
# de repo conf -> edd; la app la sustituye por la del catálogo descargado).
SEED_URL = "https://raw.githubusercontent.com/guruzgh-ed/conf/refs/heads/main/gv.js"
USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 14)"
LIST_FIELDS = ("Servers", "Tweaks")

KEY_CONFIG3 = bytes.fromhex(
    "b1445529ff46895824aeae1874b403278b63c690fb8046c2df5aa3393e5346c4")
KEY_CONFIG2 = bytes.fromhex(
    "77cb41f2a7aeb59ef152d7e374c8014e37b5c6ce04a84e2437c3bd722e176476")
KEY_CRED = bytes.fromhex(
    "4914f051e45c820f906d6cdf6ef2d29c0106d5b7f973ce6d11624316bdb3f861")

# The app's shipped first-run seed config (gf1.I1l1Il1, STGCM3 envelope);
# a real test vector from the APK itself, used by --self-test.
SEED_BLOB = "STGCM3.GV.tGsfcne-LvNVPvJk.aZASjagqN_SV3BXDrw3xJ0C45tZe96mDn7soHkbo40lO5cKwvc9f5cmj-Zyv5b4rhmQTwbPSnb8eBKvJHMVWe7eyB50npjhW6uamjs5hHy15PfVMnJeI8YkhaRysK15eMWAlumSABZZOx5bYdUvu6whpuzKPIvZ5hnAu9QxZy3ug7sTpjyujTgse42bDb-uRnNCO4ae83n16JVa3O6SFV77ru9arSwUc9AIC2yNHFL0vOQFHf66m1bqzrh8oX3d_7tO802hHQKiBOVsixb5CK5wczAY8hznjFNcO1Ep9nT_tb96u6oUbmBWF0txPvozMlTFcXTyxMGue3_1FDLXuXlNDaZyV8kjte6pHusqnnVSB34FFlAlTM7VOCcpiaA87GJjVbg8sQ_Hijuf-lxXzF_gYf8v5rOI22udLeJ39qc0EJEBcY8z6-TEp4s6G87OnZeAaQfZX2tPp2KdJlQEok0k5yPpnqaE3JYag8wZux1gGfdx2REsE6Ljmj9nl6K2CBMXr2K5Y80g05QJ0elZPtcr7lL77O4qKXdfyed9QmY5_M3U2ok8j7IBfuo5vm4Tzu9aZ8qMgaQ9qa5UIH-2bzF5dBs2MkcK2fvX6FEWGjQKUsEdsLMxgi9DSxb143_p301MeNY5MIFT6HBiEhbpikr6I1bCxoVLyHI1eFHT8XDISv92QC6UmwYLAIc7Onjs_dTXc-CaaFQnNoZZNOUJu2HZQzwPRvTL4OajOiXT-kW1hNfNpBFt_-x1IYePCsNFEVTSVG25Q5Tfcq0RXmd1Z4p9RSaBT0jLyig0MdNDyrYay8U6dXijcudzpDIb0buLz0cznH_Z9QD049T8FZWx-lJABS54y7kke2GPS-W_vXnbYxrtW_MMv2TYJ_r1IHLQx33_uB86Ebo_vkRL7-8atKVoosDp_zZryng4TrT2QFohxh7s_pb0ZXDhxcM2S9rFbv4hMeswG0NvR6Fuw42oEpBecdiBSU33SMJQbHjxoz5sunX0-1j-KlVrS4Se51r3u-7FAJKYjvQczFMfR9wOb6nFvNJ9e-25I46FRAzdizzyCyWBjmO4X_OX9jKkNglgy9NM9HdwaaVcQLjBzdjI4ATnorQIMzRvc9f6GISQIVW9QPwhdGm6uYIi1fXxYKtPTZ1GlDCpSEwJxDuQg1tlWPBFgvz1C-TQGJ-Kir5QwimIflRnfZG-KFsLpfYC_ETS-OxdJjHPCh2dfbLJKeEM0kfBBCMJnuq_z89clcWzCwKoUQMYS6SKYHosIUMqBu5bC8Tyuvn8dAU6mTXtkgRSWVtCXWNY1XL13KQR07tyGSEwi-yOhHTqV6FN0Sgm-H6q5qEgFr2-ndaGNU3b2n81s3ouMITZzbB9SQgULvqvXbNiGCc0H-XDONvlDbKq9-O0u7PRCGFAEOicpq6nLS3GgT3KE7GoPJw-663Nr0o2MdLZt0TS_mIw9uduE_YTodYGy2Fdn6QOeSeexYzOI2ZcbhE36Ng9qNDCJwhj-45vAbsYTkMzeX7bEYBiLqbvJvISdsGFzgtVZrOJALFFgvXXVOwVBpHr-Wmod8froT4zpVyYWcYfuOf6g07TvxdmZnhqvBj-KvekVBDSEcVghWir6pz_sImzPdDJYNheqXx2MGfeM7PGg4TEKbarhx-MxHwA1rGRfinIsxdFVUFA6U6NVelI_jafGHAN76-zvycDtDhtYNCMP1A9OkBAomRZoqueKHxk73-f5HOxQNfBwRUlyP3hSIT19EoQw4E54UyPB62GWf5T8IdlQHMIqY5sVv3JlkdZy9Rr_A2n7OmA5e38ytmj0G7m66nxgFpw-ROowPNRw-F9b1cjuGXofTwoUzPXD9hjZcCqJgyKLK6r-7QINTl85GztSFHFaC1w8kdAcFgsLyI0uniKmO4FvybS4fkmMQs5doOFWWtQmWRieD6jBgExqdB4t43jrtGUjb54S8fa-VSde03J-qqV3Y0u_i1kc45TcccnDMbZYM4ZGVh5kzdijYUll5F8DE7Hv9CHbCQKu2LNEOzLb9iZ68jEENxKQvaAodWbVA6LRCNEnTd4wTUIL2io8Cp5UF6o9CXUjDIe1AlrGWZnRY_O-M_Zu-3D2dOE4WJtBEoDCNvSILEulpGgL71I2-z_t-lPLpysX7ue2GKdCWHoEjOfYaxXuDdM6fuKVWqG01vbQRJLC0OBNCGz3JwU76KaElEEo2DuA2Uj_HRhCnacoS-2upMy9jvV87J_LlgtfmZHm_9KCXwkH"


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
    """Abre STGCM2.GV./STGCM3.GV./GVCR1. y devuelve el texto plano."""
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
    """Decodifica un valor de cadena del catálogo (GVCR1. / u8: / r95)."""
    if not isinstance(value, str):
        return value
    if value.startswith("GVCR1."):
        try:
            return _combine_surrogates(
                _decrypt_envelope(value, "GVCR1.", KEY_CRED).decode("utf-8"))
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
    Acepta el cuerpo HTTP crudo (sobre STGCM3.GV. o STGCM2.GV.), o un
    JSON ya descifrado."""
    text = _text(data)
    if len(text) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El catálogo supera el tamaño máximo.")
    stripped = text.strip()
    if stripped.startswith("{"):
        return _catalog_json(stripped.encode("utf-8"))
    last_error = None
    for prefix, key in (("STGCM3.GV.", KEY_CONFIG3), ("STGCM2.GV.", KEY_CONFIG2)):
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


class _NoAutoRedirect(HTTPRedirectHandler):
    """La app NO sigue redirecciones automáticamente (bw0 usa
    setInstanceFollowRedirects(false)): solo sigue un Location HTTPS,
    y eso lo hace el bucle de fetch_catalog."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


FETCH_INFO = {}  # último ETag / Last-Modified / URL final de la descarga


def fetch_catalog(url=CATALOG_URL, timeout=20, etag=None, modified=None):
    """GET exactamente como la app (bw0.doInBackground): HttpURLConnection,
    método GET, connect timeout 15 s, read timeout 20 s (urllib usa un
    solo timeout de socket: 20 s), sin redirecciones automáticas (solo
    se sigue un Location HTTPS, máximo 5 saltos), sin autenticación ni
    parámetros. If-None-Match / If-Modified-Since solo se envían cuando
    el llamador ya tiene un etag / fecha guardados (la app los lee de
    SharedPreferences); una primera descarga es un GET plano con el
    User-Agent Dalvik por defecto y ninguna otra cabecera.
    Devuelve el cuerpo, o None si el servidor responde 304."""
    _https_url(url)
    # ProxyHandler() sin argumentos lee el proxy del entorno en cada
    # llamada (las credenciales del proxy rotan; nunca van cableadas).
    opener = build_opener(ProxyHandler(), _NoAutoRedirect)
    headers = {"User-Agent": USER_AGENT}
    if etag:
        headers["If-None-Match"] = etag
    if modified:
        headers["If-Modified-Since"] = modified
    current = url
    for _hop in range(6):
        req = Request(current, headers=headers)
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(MAX_BYTES + 1)
                if len(body) > MAX_BYTES:
                    raise DecodeError("SIZE_LIMIT",
                                      "La respuesta supera 8 MiB (la app la rechaza).")
                FETCH_INFO["url"] = current
                FETCH_INFO["etag"] = resp.headers.get("ETag")
                FETCH_INFO["modified"] = resp.headers.get("Last-Modified")
                return body
        except HTTPError as exc:
            if exc.code == 304:
                FETCH_INFO["url"] = current
                return None
            if exc.code in (301, 302, 303, 307, 308):
                location = exc.headers.get("Location") if exc.headers else None
                if not location:
                    raise DecodeError("HTTP_ERROR",
                                      "Redirección %d sin Location." % exc.code) from exc
                if urlsplit(location).scheme != "https":
                    raise DecodeError("INSECURE_REDIRECT",
                                      "La app rechaza redirigir a %s." % location) from exc
                current = location
                continue
            raise
    raise DecodeError("HTTP_ERROR", "Demasiadas redirecciones.")


def _summary(doc):
    servers = doc.get("Servers") or []
    tweaks = doc.get("Tweaks") or []
    cats = {}
    for s in servers:
        cats[s.get("Category", "?")] = cats.get(s.get("Category", "?"), 0) + 1
    with_payload = sum(1 for t in tweaks if t.get("Payload"))
    return ("versión %s (revisión %s), %d servidores %s, %d tweaks (%d con Payload)"
            % (doc.get("version"), doc.get("config_revision"),
               len(servers), cats, len(tweaks), with_payload))


# ------------------------------------------------------------- CLI
def _self_test():
    """Vector real (seed del APK) + round-trips de los tres sobres y r95."""
    doc = decode(SEED_BLOB)
    assert doc["version"] == "0.1", doc.get("version")
    assert doc["config_revision"] == 1, doc.get("config_revision")
    assert doc["url_updater"] == SEED_URL, doc.get("url_updater")
    assert len(doc["Servers"]) == 1, len(doc["Servers"])
    assert len(doc["Tweaks"]) == 1, len(doc["Tweaks"])
    s0 = doc["Servers"][0]
    assert s0["Name"] == "Guruz VPN ", s0
    assert s0["Category"] == "PREMIUM", s0
    assert s0["SSHPort"] == "22", s0
    assert s0["CloudFrontServer"] == "edd.com", s0
    assert s0["CloudFrontUser"] == "a", s0
    assert s0["CloudFrontPass"] == "a", s0
    t0 = doc["Tweaks"][0]
    assert t0["ServerMode"] == "cf", t0
    assert t0["Mode"] == 0, t0
    assert t0["Payload"] == ("GET / HTTP/1.1[crlf]Host: [cf] [crlf]Connection: Upgrade"
                             "[crlf]User-Agent: [ua][crlf]Upgrade: Websocket[crlf][crlf]"), t0
    # Round-trip STGCM3 + GVCR1 + r95 (r95 es auto-inverso).
    plain = json.dumps(doc, ensure_ascii=False).encode("utf-8")
    blob = _encrypt_envelope(plain, "STGCM3.GV.", KEY_CONFIG3)
    assert _decrypt_envelope(blob, "STGCM3.GV.", KEY_CONFIG3) == plain
    cred = _encrypt_envelope(b"testuser#testpass#1234", "GVCR1.", KEY_CRED)
    assert _decrypt_envelope(cred, "GVCR1.", KEY_CRED) == b"testuser#testpass#1234"
    legacy = _encrypt_envelope(plain, "STGCM2.GV.", KEY_CONFIG2)
    assert _decrypt_envelope(legacy, "STGCM2.GV.", KEY_CONFIG2) == plain
    sample = "Guruz VPN | Working Good \U0001F44D"
    # r95 opera por unidades UTF-16 (como en Java): el emoji es un par
    # sustituto, no un solo punto de código.
    raw16 = sample.encode("utf-16-be")
    units = "".join(chr(c) for c in struct.unpack(">%dH" % (len(raw16) // 2), raw16))
    assert _r95(_r95(units)) == units
    assert _combine_surrogates(_r95(_r95(units))) == sample
    assert _decode_value(_r95("22")) == "22"
    return ("self-test OK: seed version %s, %d servidor, %d tweak, "
            "GVCR1. decodificado, round-trip STGCM3/STGCM2/GVCR1/r95 OK"
            % (doc["version"], len(doc["Servers"]), len(doc["Tweaks"])))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Descifrador del catálogo de Guruz VPN (guruz.vpn.tunnel).")
    parser.add_argument("--url", nargs="?", const=CATALOG_URL, default=None,
                        help="Descarga el catálogo de la URL (por defecto %s)." % CATALOG_URL)
    parser.add_argument("--file", default=None,
                        help="Lee el catálogo de un archivo local (sobre o JSON).")
    parser.add_argument("--self-test", action="store_true",
                        help="Verifica el descifrado con el seed real del APK.")
    parser.add_argument("--etag", default=None,
                        help="Envía If-None-Match (como la app con su etag guardado).")
    parser.add_argument("--modified", default=None,
                        help="Envía If-Modified-Since (como la app con su fecha guardada).")
    parser.add_argument("--summary", action="store_true",
                        help="Imprime un resumen (versión, servidores, tweaks) en stderr.")
    parser.add_argument("-o", "--output", default=None,
                        help="Guarda el JSON descifrado en este archivo.")
    args = parser.parse_args(argv)

    if args.self_test:
        print(_self_test())
        return 0
    try:
        if args.url:
            raw = fetch_catalog(args.url, etag=args.etag, modified=args.modified)
            if raw is None:
                print("HTTP 304: sin cambios; usa el catálogo guardado.", file=sys.stderr)
                return 0
        elif args.file:
            with open(args.file, "rb") as fh:
                raw = fh.read()
        else:
            parser.error("usa --url, --file o --self-test")
            return 2
        out = run(raw)
        if out is None:
            raise DecodeError("DECRYPT_FAILED", "No se pudo descifrar el catálogo.")
        if args.summary:
            print(_summary(decode(raw)), file=sys.stderr)
            if FETCH_INFO.get("etag"):
                print("ETag: %s" % FETCH_INFO["etag"], file=sys.stderr)
            if FETCH_INFO.get("modified"):
                print("Last-Modified: %s" % FETCH_INFO["modified"], file=sys.stderr)
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
