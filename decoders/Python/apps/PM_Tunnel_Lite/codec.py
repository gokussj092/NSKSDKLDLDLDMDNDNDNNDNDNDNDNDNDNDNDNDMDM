#!/usr/bin/env python3
"""PM Tunnel Lite 1.0 (10) — standalone server catalog codec.

Package ``com.pmtunnel.app`` (KDIGITAL SOFTWARE DEVELOPMENT SERVICES),
a Renz-family v2rayNG fork. All catalog crypto lives in the native
``libovpn3.so`` (arm64 split only). The live catalog is a single-line
Base64 document fetched with a plain GET from:

    https://raw.githubusercontent.com/rajon-apps-2026/PM-Tunnel-Lite-Updater/refs/heads/main/update.js

Layers (all constants are fixed rodata in ``libovpn3.so``; no per-device
secret). Mode numbers are the app's own ``RenzUtils.decrypt`` dispatch:

  mode 0: Base64 -> AES-128-CBC(key=SHA256(salt)[0:16], iv=IV, PKCS7)
          -> XXTEA-decrypt(delta=0x7a56d3e1, rounds=6+52/n, length in
             last word) -> each byte minus 2.
          Whole document, Name/Subname/ports/flag, Network Name/Info/
          TLSVersion, ProxySettings.Squid/Port, ``pmtunnellite://``
          links, ``.js`` catalog files, ``custom_payload.json``.
  mode 1 (decryptSpecial): Base64 -> Threefish-256 decrypt, one
          32-byte block at a time, key = HKDF-SHA256(salt=FIXED_SALT,
          ikm=PASSWORD, info=b'', L=32), tweak = (block_index, 0)
          -> strip trailing zero bytes -> AES-128-CBC(key =
          HKDF-SHA256(salt=FIXED_SALT[:16], ikm=PASSWORD, info=b'',
          L=16), iv=IV, PKCS7).
          ServerIPHost, Networks[].SNIHost, Networks[].Payload.
          (Threefish-256 is the standard Skein construction; the C240
          key-schedule constant is 0x1BD11BDAA9FC1A22, validated
          byte-for-byte against the native encryptor run under Unicorn:
          encrypt(zeros) == 9bdf65be...66b4.)
  mode 2 (decryptSensitive): PBKDF2-HMAC-SHA256(password=PASSWORD,
          salt=FIXED_SALT, iter=100000, dklen=32); Base64 ->
          XXTEA-decrypt(key=PBKDF2[0:16]) -> AES-256-CBC(key=PBKDF2,
          iv=first 16 bytes of XXTEA output, PKCS7).
          Per-server Username/Password and the catalog top-level
          Username/Password. (No Java call site passes mode 2 in this
          build; the fields are nevertheless encrypted with this scheme
          by the catalog generator and decrypt to sensible values.)
  mode 3 (decryptDex, HKDF-32 + AES-256-CBC, IV = first 16 bytes) is
          used ONLY for the encrypted dex resource ``res/ae/drlb``
          (anti-tamper DEX). It is NOT a user format and is NOT
          integrated as one; :func:`decrypt_dex` is kept here only so
          the reversed crypto suite stays complete.

Why this codec is standalone (no ``decoders/Python/renz.py`` profile):
the structure and the XXTEA delta (0x7a56d3e1) match the shared RENZ
route, but the key material is DIFFERENT — PASSWORD, FIXED_SALT and IV
below do not equal any ``RENZ_KEYS`` entry (e.g. ``gcpvpn``). Reusing
the ``gcpvpn`` profile would silently fail, and registering a new
profile in ``renz.py`` is forbidden (it would break the Android
generator of 16 RENZ suffixes / 239 formats). So this module carries
its own logic, exactly as the task requires. Nothing under
``android/`` changes; PM Tunnel Lite stays online-only, no offline
port.

Live catalog (re-verified 2026-11-22 ~16:10 Tijuana, same bytes as the
04:10 fetch): HTTP 200, 140,224 B, SHA-256
``d09b5d7304ec70561a6871cd0ee6ca08f3a5ad6a713b77977c7c840e2698a82d``,
Version ``159``, 10 servers, 151 networks; 915/915 non-empty fields
decrypt (top-level mode 0: 694, mode 1: 155, mode 2: 14; nested
sections: 52), 0 undecrypted. The nested field-mode table below
(SlowDNS, V2Ray, UDPOptions) was established the same way as the GCP
SlowDNS correction: every live instance opens under exactly one mode
to plausible plaintext and fails under the other two — never guessed.
Unknown keys inside any section pass through verbatim, never dropped
(the top-level document keeps exactly the keys the live catalog has:
Version, Notes, Servers, Networks, Username, Password).

``decode_catalog`` returns the COMPLETE decrypted document by default
— the cloud worker contract (same as GCP/NETFLUX: the Android app
consumes hosts and credentials from it). Pass ``redact=True`` only
when writing a stored artifact (tests, reports); the redacted form
replaces hosts/usernames/passwords/custom certs with ``None`` and
never returns them. No live catalog bytes or decrypted credentials
are stored in Git.

These formats do not authenticate the ciphertext cryptographically.
Padding, length and structure validate the format, not its
authenticity. HMAC connection authentication: NOT_OBSERVED (see the
dossier ``MANIFEST.json``).
"""
from __future__ import annotations

import base64
import hashlib
import hmac as hmac_mod
import json
import struct

from Crypto.Cipher import AES

MAX_BYTES = 8 * 1024 * 1024
CATALOG_URL = ("https://raw.githubusercontent.com/rajon-apps-2026/"
               "PM-Tunnel-Lite-Updater/refs/heads/main/update.js")

# 32-byte rodata at libovpn3.so VA 0x206778 (also the PBKDF2 password
# and the HKDF input key material).
PASSWORD = bytes.fromhex(
    "3df2206048b6a96899c64cbd244ca4b94e4f63d816c9e61ab5af526181891e82")
# 32-byte rodata at VA 0x2067e4 (FIXED_SALT symbol).
FIXED_SALT = bytes.fromhex(
    "896a673b34f9c9832a3e0f63060fb990abafe2bffc58f5944747fcfdf63c697b")
# 16-byte IV rodata at VA 0x206798.
IV = bytes.fromhex("81cc11ecac729b67e54c9f087520e1d4")

K16 = hashlib.sha256(PASSWORD).digest()[:16]          # mode-0 AES key
XXTEA_DELTA = 0x7A56D3E1                                # custom btea delta
M32 = 0xFFFFFFFF
M64 = (1 << 64) - 1

_PBKDF2_KEY = None
_HKDF32_KEY = None
_HKDF16_KEY = None


class DecodeError(ValueError):
    pass


def _pbkdf2_key():
    global _PBKDF2_KEY
    if _PBKDF2_KEY is None:
        _PBKDF2_KEY = hashlib.pbkdf2_hmac(
            "sha256", PASSWORD, FIXED_SALT, 100000, 32)
    return _PBKDF2_KEY


def _hkdf(salt, length):
    """HKDF-SHA256 (RFC 5869), info empty."""
    prk = hmac_mod.new(salt, PASSWORD, hashlib.sha256).digest()
    out = b""
    t = b""
    i = 1
    while len(out) < length:
        t = hmac_mod.new(prk, t + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def _hkdf32_key():
    global _HKDF32_KEY
    if _HKDF32_KEY is None:
        _HKDF32_KEY = _hkdf(FIXED_SALT, 32)
    return _HKDF32_KEY


def _hkdf16_key():
    global _HKDF16_KEY
    if _HKDF16_KEY is None:
        _HKDF16_KEY = _hkdf(FIXED_SALT[:16], 16)
    return _HKDF16_KEY


# ------------------------------------------------------------------- XXTEA
def _xxtea_words(data):
    n = len(data) // 4
    return list(struct.unpack("<%dI" % n, data[:n * 4]))


def xxtea_decrypt(data, key16):
    """btea decrypt (length stored in last word), custom delta."""
    v = _xxtea_words(data)
    n = len(v)
    if n < 2:
        raise ValueError("xxtea: input too short")
    k = _xxtea_words(key16.ljust(16, b"\x00")[:16])
    rounds = 6 + 52 // n
    total = (rounds * XXTEA_DELTA) & M32
    y = v[0]
    s = total
    for _ in range(rounds):
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            mx = (((z >> 5) ^ ((y << 2) & M32)) +
                  ((y >> 3) ^ ((z << 4) & M32))) & M32
            mx ^= ((s ^ y) + (k[(p & 3) ^ e] ^ z)) & M32
            v[p] = (v[p] - mx) & M32
            y = v[p]
        z = v[n - 1]
        mx = (((z >> 5) ^ ((y << 2) & M32)) +
              ((y >> 3) ^ ((z << 4) & M32))) & M32
        mx ^= ((s ^ y) + (k[(0 & 3) ^ e] ^ z)) & M32
        v[0] = (v[0] - mx) & M32
        y = v[0]
        s = (s - XXTEA_DELTA) & M32
    out = struct.pack("<%dI" % n, *v)
    m = v[n - 1]
    if not (n * 4 - 7 <= m <= n * 4 - 4):
        raise ValueError("bad xxtea length word: m=%d n=%d" % (m, n))
    return out[:m]


def xxtea_encrypt(data, key16):
    """btea encrypt, exact inverse of xxtea_decrypt.

    The length word stores the ORIGINAL byte length (not the padded
    length); the last partial word is zero-padded. Verified against
    the app's real ciphertext: a 26-byte plaintext carries length 26.
    """
    orig_len = len(data)
    pad_len = (4 - orig_len % 4) % 4
    data = data + b"\x00" * pad_len
    v = _xxtea_words(data)
    v.append(orig_len)
    n = len(v)
    k = _xxtea_words(key16.ljust(16, b"\x00")[:16])
    rounds = 6 + 52 // n

    def mx(y, z, s, p, e):
        m = (((z >> 5) ^ ((y << 2) & M32)) +
             ((y >> 3) ^ ((z << 4) & M32))) & M32
        m ^= ((s ^ y) + (k[(p & 3) ^ e] ^ z)) & M32
        return m

    s = 0
    for _ in range(rounds):
        s = (s + XXTEA_DELTA) & M32
        e = (s >> 2) & 3
        z = v[n - 1]  # fresh each round: v[n-1] after the previous round
        for p in range(n - 1):
            y = v[p + 1]
            v[p] = (v[p] + mx(y, z, s, p, e)) & M32
            z = v[p]
        y = v[0]
        v[n - 1] = (v[n - 1] + mx(y, z, s, n - 1, e)) & M32
    return struct.pack("<%dI" % n, *v)


# --------------------------------------------------------------- Threefish
TF_C240 = 0x1BD11BDAA9FC1A22
TF_ROT = [(14, 16), (52, 57), (23, 40), (5, 37),
          (25, 33), (46, 12), (58, 22), (32, 32)]
TF_PERM = [0, 3, 2, 1]


def _rol64(x, r):
    return ((x << r) | (x >> (64 - r))) & M64


def _ror64(x, r):
    return ((x >> r) | (x << (64 - r))) & M64


def _tf_subkeys(kw, tw):
    sk = []
    for s in range(19):
        sk.append([
            kw[s % 5],
            (kw[(s + 1) % 5] + tw[s % 3]) & M64,
            (kw[(s + 2) % 5] + tw[(s + 1) % 3]) & M64,
            (kw[(s + 3) % 5] + s) & M64,
        ])
    return sk


def _tf_key_schedule(key32, tweak16):
    kw = list(struct.unpack("<4Q", key32))
    kw.append(TF_C240 ^ kw[0] ^ kw[1] ^ kw[2] ^ kw[3])
    tw = list(struct.unpack("<2Q", tweak16))
    tw.append(tw[0] ^ tw[1])
    return _tf_subkeys(kw, tw)


def threefish256_encrypt_block(key32, tweak16, block32):
    sk = _tf_key_schedule(key32, tweak16)
    v = list(struct.unpack("<4Q", block32))
    v = [(v[i] + sk[0][i]) & M64 for i in range(4)]
    for d in range(72):
        r0, r1 = TF_ROT[d % 8]

        def mix(x0, x1, r):
            y0 = (x0 + x1) & M64
            return y0, _rol64(x1, r) ^ y0

        v[0], v[1] = mix(v[0], v[1], r0)
        v[2], v[3] = mix(v[2], v[3], r1)
        v = [v[TF_PERM[i]] for i in range(4)]
        if (d + 1) % 4 == 0:
            s = (d + 1) // 4
            v = [(v[i] + sk[s][i]) & M64 for i in range(4)]
    return struct.pack("<4Q", *v)


def threefish256_decrypt_block(key32, tweak16, block32):
    sk = _tf_key_schedule(key32, tweak16)
    v = list(struct.unpack("<4Q", block32))
    for d in range(71, -1, -1):
        if (d + 1) % 4 == 0:
            s = (d + 1) // 4
            v = [(v[i] - sk[s][i]) & M64 for i in range(4)]
        inv = [0] * 4
        for i in range(4):
            inv[TF_PERM[i]] = v[i]
        v = inv
        r0, r1 = TF_ROT[d % 8]

        def inv_mix(y0, y1, r):
            x1 = _ror64(y1 ^ y0, r)
            return (y0 - x1) & M64, x1

        v[0], v[1] = inv_mix(v[0], v[1], r0)
        v[2], v[3] = inv_mix(v[2], v[3], r1)
    v = [(v[i] - sk[0][i]) & M64 for i in range(4)]
    return struct.pack("<4Q", *v)


# ------------------------------------------------------------- AES helpers
def _aes_cbc_decrypt(key, iv, data):
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


def _aes_cbc_encrypt(key, iv, data):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)


def _pkcs7_unpad(data):
    if not data:
        raise ValueError("empty AES output")
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad PKCS7 padding (pad byte %d)" % pad)
    return data[:-pad]


def _pkcs7_pad(data):
    pad = 16 - len(data) % 16
    return data + bytes([pad]) * pad


# -------------------------------------------------------------- mode 0/1/2
def decrypt_mode0(b64text):
    """Whole-document / field decrypt (AES-128 -> XXTEA -> bytes minus 2)."""
    raw = base64.b64decode(b64text)
    aes_out = _pkcs7_unpad(_aes_cbc_decrypt(K16, IV, raw))
    xx = xxtea_decrypt(aes_out, K16)
    return bytes((b - 2) & 0xFF for b in xx)


def encrypt_mode0(plain):
    """Inverse of decrypt_mode0 (used by the app's sh1.d and for links)."""
    shifted = bytes((b + 2) & 0xFF for b in plain)
    xx = xxtea_encrypt(shifted, K16)
    return base64.b64encode(_aes_cbc_encrypt(K16, IV, _pkcs7_pad(xx)))


def decrypt_special(b64text):
    """Mode 1: Threefish-256 per 32-byte block, strip zeros, AES-128."""
    if not b64text:
        return b""
    raw = base64.b64decode(b64text)
    out = bytearray()
    for off in range(0, len(raw), 32):
        blk = raw[off:off + 32]
        if len(blk) < 32:
            blk = blk + b"\x00" * (32 - len(blk))
        out += threefish256_decrypt_block(
            _hkdf32_key(), struct.pack("<2Q", off // 32, 0), blk)
    buf = bytes(out)
    while buf and buf[-1] == 0:
        buf = buf[:-1]
    return _pkcs7_unpad(_aes_cbc_decrypt(_hkdf16_key(), IV, buf))


def encrypt_special(plain):
    """Inverse of decrypt_special (deterministic: fixed IV, tweak=index)."""
    aes_out = _aes_cbc_encrypt(_hkdf16_key(), IV, _pkcs7_pad(plain))
    pad_len = (32 - len(aes_out) % 32) % 32
    buf = aes_out + b"\x00" * pad_len
    out = bytearray()
    for off in range(0, len(buf), 32):
        out += threefish256_encrypt_block(
            _hkdf32_key(), struct.pack("<2Q", off // 32, 0),
            buf[off:off + 32])
    return base64.b64encode(bytes(out))


def decrypt_sensitive(b64text):
    """Mode 2: PBKDF2 -> XXTEA -> AES-256 (IV = first 16 bytes)."""
    if not b64text:
        return b""
    key = _pbkdf2_key()
    raw = base64.b64decode(b64text)
    xx = xxtea_decrypt(raw, key[:16])
    iv, ct = xx[:16], xx[16:]
    return _pkcs7_unpad(_aes_cbc_decrypt(key, iv, ct))


def encrypt_sensitive(plain, iv=None):
    """Inverse of decrypt_sensitive (random IV unless given)."""
    import os as _os
    key = _pbkdf2_key()
    iv = iv if iv is not None else _os.urandom(16)
    ct = _aes_cbc_encrypt(key, iv, _pkcs7_pad(plain))
    return base64.b64encode(xxtea_encrypt(iv + ct, key[:16]))


def decrypt_dex(data):
    """Mode 3 (decryptDex): HKDF-32 + AES-256-CBC, IV = first 16 bytes.

    Used ONLY for the encrypted dex resource res/ae/drlb, not for
    catalog fields and not for any user format.
    """
    key = _hkdf32_key()
    return _pkcs7_unpad(_aes_cbc_decrypt(key, data[:16], data[16:]))


# ------------------------------------------------------------ catalog decode
def _unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise DecodeError("JSON ambiguo.")
        out[key] = value
    return out


def _invalid_constant(value):
    raise DecodeError("Constante JSON inválida.")


def open_outer(data: bytes) -> dict:
    """Mode-0 decrypt of the fetched document -> parsed JSON dict."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Entrada vacía o superior a 8 MiB.")
    try:
        text = decrypt_mode0(data.decode("ascii").strip())
    except Exception:
        raise DecodeError("Sobre exterior inválido para PM Tunnel Lite 1.0.") from None
    if not text:
        raise DecodeError("Sobre exterior inválido para PM Tunnel Lite 1.0.")
    try:
        doc = json.loads(text, object_pairs_hook=_unique,
                         parse_constant=_invalid_constant)
    except ValueError:
        raise DecodeError("Sobre exterior sin JSON válido.") from None
    if (not isinstance(doc, dict) or "Version" not in doc or
            not isinstance(doc.get("Servers"), list) or not doc["Servers"] or
            not isinstance(doc.get("Networks"), list) or not doc["Networks"]):
        raise DecodeError("Faltan secciones completas del catálogo.")
    return doc


# Fields of a server entry: (json key, mode) - mode 0/1/2 as above.
_SERVER_FIELDS = {
    "Name": 0, "Subname": 0, "OpenVPNTCPPort": 0, "OpenVPNSSLPort": 0,
    "flag": 0, "ServerIPHost": 1, "Username": 2, "Password": 2,
    "CloudfrontDNS": 0, "ServerHTTP": 0, "Obfs": 0, "CustomCert": 0,
}
_NETWORK_FIELDS = {
    "Name": 0, "Info": 0, "TLSVersion": 0, "SNIHost": 1, "Payload": 1,
    "DNSServerHost": 0, "DNSResolver": 0,
}
# Nested sections. Modes verified against EVERY live instance
# (2026-11-22, Version 159): each field opens under exactly its mode
# to plausible plaintext and fails under the other two modes.
#   SlowDNS.PubKey mode 0 -> 64-char hex (same as the GCP diagnosis);
#   V2RayHost/SNIHost/PATH mode 1 (host-like); UUID, UDPOptions and
#   NSNameServer mode 0 (UUID: 13-char token; UDPOptions: digits).
_SERVER_SLOWDNS_FIELDS = {"NSNameServer": 0, "PubKey": 0}
_SERVER_V2RAY_FIELDS = {"V2RayHost": 1, "UUID": 0, "PATH": 1}
_NETWORK_UDPOPTIONS_FIELDS = {"UpMbps": 0, "DlMbps": 0,
                              "RecvConnectionWindow": 0}
_NETWORK_V2RAY_FIELDS = {"SNIHost": 1, "CustomV2RAYConfig": 1}

_MODE_FN = {0: decrypt_mode0, 1: decrypt_special, 2: decrypt_sensitive}

# Fields whose decrypted value is a credential (host / username /
# password / custom cert). Redacted (None) when redact=True.
_CREDENTIAL_FIELDS = ("ServerIPHost", "Username", "Password", "CustomCert")


def _dec_field(value, mode):
    if value == "" or value is None:
        return ""
    return _MODE_FN[mode](value).decode("utf-8", "replace")


def _dec_entry_fields(entry, table, maybe_redact=None):
    """Decrypt the known encrypted fields of one entry dict in place.

    A field that does not open with its documented mode is served
    as-is (same policy as the GCP/NETFLUX recursive pass: the live
    catalog has 0 such fields). Unknown keys pass through untouched.
    """
    for key, mode in table.items():
        if key in entry and isinstance(entry[key], str) and entry[key] != "":
            try:
                value = _dec_field(entry[key], mode)
                entry[key] = maybe_redact(value) if maybe_redact else value
            except Exception:
                pass
    return entry


def _dec_section(section, table, maybe_redact=None):
    """Decrypt the known encrypted fields of a nested section dict.

    Unknown keys pass through verbatim; a field that does not open
    with its documented mode is served as-is.
    """
    if not isinstance(section, dict):
        return section
    for key, mode in table.items():
        if key in section and isinstance(section[key], str) and section[key] != "":
            try:
                value = _dec_field(section[key], mode)
                section[key] = maybe_redact(value) if maybe_redact else value
            except Exception:
                pass
    return section


def dec_server_entry(entry, maybe_redact=None):
    """Decrypt one server entry (link / custom-payload item) in place.

    Known top-level fields by their mode table, SlowDNS/V2Ray
    sections by theirs; every other key passes through verbatim.
    """
    if not isinstance(entry, dict):
        raise DecodeError("Entrada de servidor inválida.")
    _dec_entry_fields(entry, _SERVER_FIELDS, maybe_redact)
    if isinstance(entry.get("SlowDNS"), dict):
        _dec_section(entry["SlowDNS"], _SERVER_SLOWDNS_FIELDS, maybe_redact)
    if isinstance(entry.get("V2Ray"), dict):
        _dec_section(entry["V2Ray"], _SERVER_V2RAY_FIELDS, maybe_redact)
    if maybe_redact:
        for key in _CREDENTIAL_FIELDS:
            if key in entry and isinstance(entry[key], str):
                entry[key] = maybe_redact(entry[key])
    return entry


def dec_network_entry(entry, maybe_redact=None):
    """Decrypt one network entry in place (incl. ProxySettings)."""
    if not isinstance(entry, dict):
        raise DecodeError("Entrada de red inválida.")
    _dec_entry_fields(entry, _NETWORK_FIELDS, maybe_redact)
    squids = entry.get("ProxySettings")
    if isinstance(squids, dict):
        for key in ("Squid", "Port"):
            if key in squids and isinstance(squids[key], str) and squids[key] != "":
                try:
                    value = _dec_field(squids[key], 0)
                    squids[key] = maybe_redact(value) if maybe_redact else value
                except Exception:
                    pass
    if isinstance(entry.get("UDPOptions"), dict):
        _dec_section(entry["UDPOptions"], _NETWORK_UDPOPTIONS_FIELDS, maybe_redact)
    if isinstance(entry.get("V2Ray"), dict):
        _dec_section(entry["V2Ray"], _NETWORK_V2RAY_FIELDS, maybe_redact)
    return entry


def decode_catalog(data: bytes, redact: bool = False) -> dict:
    """Decrypt every field of a catalog document.

    Default (``redact=False``) returns the COMPLETE document, as the
    cloud worker contract requires (same as GCP/NETFLUX). With
    ``redact=True`` the credential values (server hosts, usernames,
    passwords, custom certs and the top-level account credentials) are
    replaced by ``None`` and never returned; any other field whose
    decrypted value happens to equal a credential value is redacted
    too, so no credential leaks through a non-credential field.
    """
    try:
        doc = open_outer(data)
    except DecodeError:
        raise
    except (ValueError, UnicodeError, KeyError, TypeError,
            RecursionError, OverflowError):
        raise DecodeError("Catálogo inválido o incompatible con PM Tunnel Lite 1.0.") from None

    creds = set()

    def _collect(value):
        if value:
            creds.add(value)
            for part in value.split(";"):
                if part.strip():
                    creds.add(part.strip())

    for srv in doc.get("Servers", []):
        for key in _CREDENTIAL_FIELDS:
            if isinstance(srv, dict) and srv.get(key):
                try:
                    _collect(_dec_field(srv[key], _SERVER_FIELDS[key]))
                except Exception:
                    pass
    for key in ("Username", "Password"):
        if doc.get(key):
            try:
                _collect(_dec_field(doc[key], 2))
            except Exception:
                pass
    creds.discard("")

    def _maybe_redact(value):
        return None if (redact and value in creds) else value

    import copy
    out = {"Version": doc.get("Version"), "Notes": doc.get("Notes"),
           "Servers": [], "Networks": []}
    for key, value in doc.items():
        if key not in ("Version", "Notes", "Servers", "Networks",
                       "Username", "Password"):
            out[key] = copy.deepcopy(value)
    for srv in doc.get("Servers", []):
        row = copy.deepcopy(srv)
        dec_server_entry(row, _maybe_redact if redact else None)
        if redact:
            for key in _CREDENTIAL_FIELDS:
                if key in row:
                    row[key] = None
        out["Servers"].append(row)
    for net in doc.get("Networks", []):
        row = copy.deepcopy(net)
        dec_network_entry(row, _maybe_redact if redact else None)
        out["Networks"].append(row)
    if redact:
        out["Username"] = None
        out["Password"] = None
    else:
        for key in ("Username", "Password"):
            if doc.get(key):
                try:
                    out[key] = _dec_field(doc[key], 2)
                except Exception:
                    out[key] = doc[key]
            else:
                out[key] = ""
    if (not isinstance(out.get("Servers"), list) or not out["Servers"] or
            not isinstance(out.get("Networks"), list) or not out["Networks"]):
        raise DecodeError("Faltan secciones completas del catálogo.")
    return out


def render(doc) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
