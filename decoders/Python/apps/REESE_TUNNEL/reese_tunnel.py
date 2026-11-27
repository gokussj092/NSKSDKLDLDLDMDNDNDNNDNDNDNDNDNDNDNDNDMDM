"""Reese Tunnel 3.23.28 (versionCode 146, com.johnreese.fsociety) -- .RT/.reese
file decoder and vmess:// / vless:// / trojan:// / V2Ray-JSON text import.

Reverse-engineered from the APK (librse5.so + Kotlin, Lb7/x, ReeseFile) and
verified byte-identical against the native oracle (Unicorn emulation of
rse5Seal/rse5Open with the PBKDF2 loop computed in C, see dbg6.py).

NO SERVER CATALOG EXISTS in this app (verified 2026-11-27): there is no
catalog URL, endpoint or bundled server list anywhere in the DEX, strings or
assets. The only network fetch is the update check
https://raw.githubusercontent.com/REESETUNNEL/REESE-TUNNEL/main/latest.json
(versionCode/versionName only). Reese Tunnel is a user-config client (like
HTTP Custom): the user types their own SSH host/user/password, payload, SNI
and proxy, or pastes V2Ray profiles. There is therefore no live catalog to
reproduce and no server data to decrypt; the deliverable for this app is the
fully verified .RT file decoder + text-link importers + the built-in payload
preset templates (see catalogo-completo.json / catalogo-redactado.json).

.RT / .reese file format (ReeseFile export/import):
    Envelope JSON  ->  raw DEFLATE (level 1)  ->  pad()  ->  RSE5 seal
    Envelope = {"meta": {...}, "config": {...}}
    pad(): [1B v = rand(0..255)] + rand(v+16 bytes) + BE32(innerLen)
           + data + rand trailing bytes, padded out to 262144..327679 bytes.
    unpad(): b = body[0]; innerLen = BE32 at b+17; data = body[b+21 : b+21+innerLen].

RSE5 envelope (librse5.so, rse5Seal 0x2696c / rse5Open 0x25e10):
    sealed = 34-byte header + ciphertext (len == plaintext) + 16-byte GCM tag
    header: [0..3]  magic a7 19 d2 4c
            [4]     version 0xc6
            [5]     flags: 1 = HWID only, 2 = password only, 3 = both
            [6..21] salt (16 B, /dev/urandom)
            [22..33] nonce (12 B, /dev/urandom)
    cipher: AES-256-GCM, AAD = full 34-byte header, nonce counter starts at 2.
    key:    T = PBKDF2-HMAC-SHA256(key, salt, 600000, 32)
            key = "REESE-CUSTOM/RSE5|" + HWID + "|" + PASSWORD
            HWID: trimmed (bytes 0x09-0x0D and 0x20) and UPPERCASED (a-z -> A-Z)
            PASSWORD: trimmed only, case preserved.
    open requires total length >= 51; validates magic + version 0xc6 + flags <= 3.
    Native return contract (JNI): [0x00] + plaintext on success, else 1 byte:
        0x01 bad format (bad magic/version, length < 51, flags > 3)
        0x02 password required but missing (flags&2, no password supplied)
        0x03 HWID required but missing (flags&1, no HWID supplied; HWID is
             checked before the password: a flags=3 file opened with
             neither credential returns 0x03)
        0x04 auth failure (wrong password / wrong HWID on a flags=2 or
             flags=3 file / bad GCM tag / extra password on an HWID-only file)
        0x05 seal with neither password nor HWID (seal only)
        0x06 wrong device: GCM failure on an HWID-only (flags=1) file opened
             with HWID only (no password supplied)
    Open key rule (probed): the HWID slot of the key is the supplied HWID
    only when flags&1, otherwise "" (an extra HWID on a password-only file
    is IGNORED -- the file still opens); the password slot is ALWAYS the
    supplied password, so an extra password on an HWID-only file breaks
    the key and returns 0x04.
    Kotlin import checks after open (ReeseFile.k): Meta.hwid (if non-blank)
    must equal the supplied HWID (trimmed, case-insensitive); Meta.expiresAt
    > 0 and now >= expiresAt -> expired; config.allowedHwids (if non-empty)
    must contain the supplied HWID (uppercased).

Text import (Lb7/x.j): trims, strips CR/LF; "{..." -> V2Ray JSON config;
vmess:// -> base64 JSON; vless:// / trojan:// -> URL form; otherwise
base64-decode and re-check for "{...". No custom URL scheme: the app has
no reese:// scheme; vmess/vless/trojan are paste-only. Manifest intent
filters: .RT / .rt / .reese files, MIME application/x-reese.

Dependencies: Python 3 stdlib + `cryptography` (AESGCM), with a
PyCryptodome fallback. No network access is needed by this script.

Legacy readers preserved from the 3.23.12 repo script (never drop old
versions): RSE5 C3/C4 variants (PBKDF2 32768, optional APK-signer
binding) and RSE1-RSE4 exports still open through decode() /
decode_rt_file(). The 3.23.28 app itself was verified only for RSE5
0xC6; the legacy paths are carried over byte-faithful from the repo
script, not re-verified against a real legacy file in this batch.
"""

import base64
import binascii
import getpass
import hashlib
import hmac
import json
import os
import random
import re
import struct
import sys
import time
import urllib.parse
import zlib

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover - fallback
    AESGCM = None

try:
    from Crypto.Cipher import AES as _AES
except ImportError:  # pragma: no cover - legacy CBC needs PyCryptodome
    _AES = None

MAGIC = bytes.fromhex("a719d24c")
VERSION = 0xC6
PBKDF2_ITERS = 600000
KEY_PREFIX = "REESE-CUSTOM/RSE5|"
TRIM_BYTES = set(b"\x09\x0a\x0b\x0c\x0d\x20")
PAD_MIN_TOTAL = 262144
PAD_MAX_TOTAL = 327679
# SHA-256 of the supplied APK's public signing certificate, not a private key.
# Used only to open RSE5 C3/C4 exports bound to the exporting APK (3.23.12).
APK_SIGNER_SHA256 = "D834BF8D60BFEA09A80A51CCD1A77DE3EF966E7833EBB2D0B8DC1F750E38BBA7"
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_LEGACY_BODY = 2 * 1024 * 1024

# ---------------------------------------------------------------------------
# Errors (native codes, see module docstring)
# ---------------------------------------------------------------------------

ERR_BAD_FORMAT = 1
ERR_PASSWORD_MISSING = 2
ERR_CREDENTIAL_MISSING = 3
ERR_AUTH = 4
ERR_NO_CREDENTIAL = 5
ERR_WRONG_DEVICE = 6


class RSE5Error(Exception):
    """RSE5 / .RT failure, carrying the native error code (1/3/4/5)."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# RSE5 envelope
# ---------------------------------------------------------------------------

def _trim(text):
    """Native trim helper (0x26404): bytes 0x09-0x0D and 0x20 only."""
    if text is None:
        return ""
    b = text.encode("utf-8") if isinstance(text, str) else bytes(text)
    i, j = 0, len(b)
    while i < j and b[i] in TRIM_BYTES:
        i += 1
    while j > i and b[j - 1] in TRIM_BYTES:
        j -= 1
    return b[i:j].decode("utf-8", "surrogateescape")


def _key_material(hwid="", password=""):
    """Return (derived-key-input string, flags) for SEALING. HWID
    trimmed+uppercased, password trimmed only. Flags: 1 = HWID, 2 = password."""
    h = _trim(hwid).upper()
    p = _trim(password)
    flags = (1 if h else 0) | (2 if p else 0)
    return KEY_PREFIX + h + "|" + p, flags


def _open_key(flags, hwid="", password=""):
    """Key input for OPENING a file with the given flags. The HWID slot is
    the supplied HWID only when flags&1 (an extra HWID on a password-only
    file is ignored); the password slot is always the supplied password."""
    h = _trim(hwid).upper() if (flags & 1) else ""
    p = _trim(password)
    return KEY_PREFIX + h + "|" + p


def _aesgcm_encrypt(key, nonce, plaintext, aad):
    if AESGCM is not None:
        return AESGCM(key).encrypt(nonce, plaintext, aad)
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return ct + tag


def _aesgcm_decrypt(key, nonce, ct_and_tag, aad):
    if AESGCM is not None:
        return AESGCM(key).decrypt(nonce, ct_and_tag, aad)
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ct_and_tag[:-16], ct_and_tag[-16:])


def rse5_seal(plaintext, hwid="", password="", salt=None, nonce=None):
    """Seal bytes with RSE5. Returns the sealed envelope. Raises RSE5Error(5)
    when neither a password nor an HWID is given (native returns [0x05]).
    salt/nonce are for tests only; normally random from os.urandom."""
    key_str, flags = _key_material(hwid, password)
    if flags == 0:
        raise RSE5Error(ERR_NO_CREDENTIAL,
                        "rse5Seal needs a password, an HWID, or both (native [0x05])")
    if salt is None:
        salt = os.urandom(16)
    if nonce is None:
        nonce = os.urandom(12)
    key = hashlib.pbkdf2_hmac("sha256", key_str.encode("utf-8"), salt,
                              PBKDF2_ITERS, 32)
    header = MAGIC + bytes([VERSION, flags]) + salt + nonce
    ct_tag = _aesgcm_encrypt(key, nonce, plaintext, header)
    return header + ct_tag


def rse5_open(sealed, hwid="", password=""):
    """Open an RSE5 envelope. Returns the plaintext. Raises RSE5Error with
    the native code: 1 bad format, 2 password missing, 3 HWID missing,
    4 auth failure, 6 wrong device (HWID-only file, wrong HWID, no pw)."""
    if sealed is None or len(sealed) < 51:
        raise RSE5Error(ERR_BAD_FORMAT,
                        "bad format: sealed data shorter than 51 bytes (native [0x01])")
    if sealed[0:4] != MAGIC or sealed[4] != VERSION:
        raise RSE5Error(ERR_BAD_FORMAT,
                        "bad format: bad magic or version (native [0x01])")
    flags = sealed[5]
    if flags > 3:
        raise RSE5Error(ERR_BAD_FORMAT,
                        "bad format: flags %d > 3 (native [0x01])" % flags)
    h = _trim(hwid)
    p = _trim(password)
    if (flags & 1) and not h:
        raise RSE5Error(ERR_CREDENTIAL_MISSING,
                        "HWID required to open this file (native [0x03])")
    if (flags & 2) and not p:
        raise RSE5Error(ERR_PASSWORD_MISSING,
                        "password required to open this file (native [0x02])")
    key_str = _open_key(flags, hwid, password)
    salt, nonce = sealed[6:22], sealed[22:34]
    key = hashlib.pbkdf2_hmac("sha256", key_str.encode("utf-8"), salt,
                              PBKDF2_ITERS, 32)
    try:
        return _aesgcm_decrypt(key, nonce, sealed[34:], sealed[:34])
    except Exception:
        if flags == 1 and not p:
            raise RSE5Error(ERR_WRONG_DEVICE,
                            "wrong device: this HWID-only file is bound to "
                            "another device (native [0x06])")
        raise RSE5Error(ERR_AUTH,
                        "auth failure: wrong password / wrong HWID / bad tag "
                        "(native [0x04])")


# ---------------------------------------------------------------------------
# Padding + raw DEFLATE (ReeseFile.g / ReeseFile.o, Deflater(1, true))
# ---------------------------------------------------------------------------

def pad(data, rng=None):
    """ReeseFile.g padding. First byte v = rand(0..255); then v+16 random
    bytes; then BE32(innerLen); then data; then trailing random bytes so
    the total padded length is drawn from 262144..327679 bytes."""
    rng = rng or random.SystemRandom()
    v = rng.randrange(256)
    head = bytes([v]) + bytes(rng.randrange(256) for _ in range(v + 16))
    target = rng.randrange(PAD_MIN_TOTAL, PAD_MAX_TOTAL + 1)
    trailing = max(0, target - (v + 21 + len(data)))
    tail = bytes(rng.randrange(256) for _ in range(trailing))
    return head + struct.pack(">I", len(data)) + data + tail


def unpad(body):
    """ReeseFile.o unpadding. Raises ValueError('bad padding'/'empty body')."""
    if not body:
        raise ValueError("empty body")
    b = body[0]
    if len(body) < b + 21:
        raise ValueError("bad padding")
    inner_len = struct.unpack(">I", body[b + 17:b + 21])[0]
    if inner_len < 0 or b + 21 + inner_len > len(body):
        raise ValueError("bad padding")
    return body[b + 21:b + 21 + inner_len]


def deflate_raw(data):
    co = zlib.compressobj(1, zlib.DEFLATED, -15)
    return co.compress(data) + co.flush()


def inflate_raw(data):
    return zlib.decompressobj(-15).decompress(data)


# ---------------------------------------------------------------------------
# Envelope JSON (field order = Kotlin constructor order, kotlinx)
# ---------------------------------------------------------------------------

META_FIELDS = ["name", "locked", "lockAll", "lockPayloadUnlockServer",
               "unlockUserPass", "lockRemoteProxy", "blockRoot", "password",
               "signer", "expiresAt", "hwid", "createdAt", "author"]
META_DEFAULTS = {"name": "config", "locked": False, "lockAll": False,
                 "lockPayloadUnlockServer": False, "unlockUserPass": False,
                 "lockRemoteProxy": False, "blockRoot": False, "password": "",
                 "signer": "", "expiresAt": 0, "hwid": "", "createdAt": 0,
                 "author": "REESE TUNNEL"}

CONFIG_FIELDS = ["profileName", "sshHost", "sshPort", "sshUdpGatewayPort",
                 "username", "password", "proxyHost", "proxyPort", "payload",
                 "sni", "dnsPrimary", "dnsSecondary", "usePayload",
                 "enhanced", "useSni", "useRemoteProxy", "useDnsResolver",
                 "autoReconnect", "v2rayMode", "tunnelMode", "slowDns",
                 "slowDnsResolver", "slowDnsNameserver", "slowDnsPublicKey",
                 "udpCustom", "udpCustomHost", "udpCustomUsername",
                 "udpCustomPassword", "lockConfig", "lockAll",
                 "lockPayloadUnlockServer", "unlockUserPass",
                 "lockRemoteProxy", "blockRoot", "blockApps",
                 "blockedHostnames", "allowedHwids", "importLocked", "vault",
                 "expiresAt", "boundHwid", "importedFrom", "authorSignature",
                 "note", "bannerImage", "bannerImageEnabled",
                 "customServerMessage", "customServerMessageEnabled",
                 "removeServerMessages", "v2rayProfiles", "v2rayIndex",
                 "pingHost", "pingPort", "autoPing", "pingIntervalSeconds",
                 "splitTunnelEnabled", "bypassedPackages"]
CONFIG_DEFAULTS = {"tunnelMode": "STREAM", "v2rayProfiles": [],
                   "blockApps": [], "blockedHostnames": [], "allowedHwids": [],
                   "bypassedPackages": []}

V2RAY_FIELDS = ["remark", "protocol", "host", "port", "id", "network",
                "path", "wsHost", "tls", "sni", "allowInsecure", "security",
                "flow", "realityPublicKey", "realityShortId", "spiderX",
                "fingerprint", "alpn", "transportKey", "rotateHosts",
                "rotateAddresses"]
V2RAY_DEFAULTS = {"remark": "", "protocol": "VMESS", "host": "", "port": 0,
                  "id": "", "network": "TCP", "path": "/", "wsHost": "",
                  "tls": False, "sni": "", "allowInsecure": False,
                  "security": "aes-128-gcm", "flow": "", "realityPublicKey": "",
                  "realityShortId": "", "spiderX": "", "fingerprint": "chrome",
                  "alpn": [], "transportKey": "", "rotateHosts": "",
                  "rotateAddresses": ""}


def _ordered(mapping, fields, defaults):
    out = {}
    for f in fields:
        if f in mapping:
            out[f] = mapping[f]
        elif f in defaults:
            out[f] = defaults[f]
        elif f in ("sshPort", "sshUdpGatewayPort", "proxyPort", "v2rayIndex",
                   "pingPort", "pingIntervalSeconds"):
            out[f] = 0
        elif f in ("usePayload", "enhanced", "useSni", "useRemoteProxy",
                   "useDnsResolver", "autoReconnect", "v2rayMode", "slowDns",
                   "udpCustom", "lockConfig", "lockAll",
                   "lockPayloadUnlockServer", "unlockUserPass",
                   "lockRemoteProxy", "blockRoot", "importLocked",
                   "bannerImageEnabled", "customServerMessageEnabled",
                   "removeServerMessages", "autoPing", "splitTunnelEnabled"):
            out[f] = False
        else:
            out[f] = ""
    for k, v in mapping.items():
        if k not in out:
            out[k] = v
    return out


def envelope_json(meta, config):
    """Serialize an Envelope dict the way kotlinx does (constructor order)."""
    return json.dumps(
        {"meta": _ordered(meta, META_FIELDS, META_DEFAULTS),
         "config": _ordered(config, CONFIG_FIELDS, CONFIG_DEFAULTS)},
        ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def seal_envelope(meta, config, hwid="", password=""):
    """Full export path: Envelope JSON -> raw DEFLATE(1) -> pad -> RSE5."""
    return rse5_seal(pad(deflate_raw(envelope_json(meta, config))),
                     hwid, password)


def open_envelope(sealed, hwid="", password="", check_import=True):
    """Full import path: RSE5 open -> unpad -> raw inflate -> Envelope JSON.
    Returns (meta, config) dicts. With check_import (default) the Kotlin
    import checks apply: Meta.hwid must match the supplied HWID, Meta
    expiry is enforced, and config.allowedHwids must contain the HWID."""
    plain = rse5_open(sealed, hwid, password)
    try:
        raw = inflate_raw(unpad(plain))
    except ValueError as e:
        raise RSE5Error(ERR_BAD_FORMAT, "bad padding/deflate: %s" % e)
    except zlib.error as e:
        raise RSE5Error(ERR_BAD_FORMAT, "bad deflate: %s" % e)
    try:
        env = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise RSE5Error(ERR_BAD_FORMAT, "inner JSON unreadable: %s" % e)
    meta = env.get("meta") or {}
    config = env.get("config") or {}
    if check_import:
        _check_import(meta, config, hwid)
    return meta, config


def _check_import(meta, config, hwid):
    h = _trim(hwid)
    meta_hwid = _trim(meta.get("hwid") or "")
    if meta_hwid:
        if not h or h.upper() != meta_hwid.upper():
            raise RSE5Error(ERR_AUTH,
                            "Meta.hwid does not match the supplied HWID")
    expires = meta.get("expiresAt") or 0
    if expires and int(time.time() * 1000) >= expires:
        raise RSE5Error(ERR_AUTH, "config expired (Meta.expiresAt reached)")
    allowed = config.get("allowedHwids") or []
    if allowed:
        allowed_up = {str(x).strip().upper() for x in allowed}
        if not h or h.upper() not in allowed_up:
            raise RSE5Error(ERR_AUTH,
                            "HWID not in config.allowedHwids")



# ---------------------------------------------------------------------------
# Legacy readers (3.23.12 and older exports) — preserved from the repo script.
# RSE5 C3/C4: same MAGIC, version byte 0xC3/0xC4, PBKDF2-HMAC-SHA256 32768
# iters, flags up to 7 (bit 4 = APK-signer binding), key material
# "REESE-CUSTOM/RSE5|<hwid>|<password>[|SIG:<signer>]".
# RSE1-RSE4: ASCII magic headers, HMAC + multi-layer (XOR stream, CBC,
# GCM) bodies. Error codes are mapped onto the native RSE5 codes above.
# ---------------------------------------------------------------------------

def _legacy_gcm(key, nonce, body, aad=b""):
    if len(body) < 16:
        raise RSE5Error(ERR_BAD_FORMAT, "legacy: missing GCM tag")
    try:
        return _aesgcm_decrypt(key, nonce, body, aad)
    except Exception:
        raise RSE5Error(ERR_AUTH,
                        "legacy: authentication failed; check credentials")


def _legacy_inflate(packed):
    try:
        inflater = zlib.decompressobj(-15)
        plain = inflater.decompress(packed, MAX_JSON_BYTES + 1)
    except zlib.error:
        raise RSE5Error(ERR_BAD_FORMAT, "legacy: not raw DEFLATE")
    if len(plain) > MAX_JSON_BYTES or inflater.unconsumed_tail:
        raise RSE5Error(ERR_BAD_FORMAT, "legacy: decompressed JSON too large")
    if not inflater.eof or inflater.unused_data:
        raise RSE5Error(ERR_BAD_FORMAT, "legacy: truncated DEFLATE stream")
    return plain


def _legacy_unpad(body, with_length):
    if not body:
        raise RSE5Error(ERR_BAD_FORMAT, "legacy: empty body")
    offset = body[0] + 17
    if offset > len(body):
        raise RSE5Error(ERR_BAD_FORMAT, "legacy: invalid random prefix")
    if not with_length:
        return body[offset:]
    if offset + 4 > len(body):
        raise RSE5Error(ERR_BAD_FORMAT, "legacy: missing payload length")
    size = struct.unpack_from(">i", body, offset)[0]
    offset += 4
    if size <= 0 or size > len(body) - offset:
        raise RSE5Error(ERR_BAD_FORMAT, "legacy: invalid payload length")
    return body[offset:offset + size]


def _legacy_modern(blob, hwid="", password="", signer=APK_SIGNER_SHA256):
    """Open an RSE5 C3/C4 export. Returns the raw DEFLATE-packed bytes."""
    if len(blob) < 5:
        raise RSE5Error(ERR_BAD_FORMAT, "legacy: missing RSE5 variant byte")
    variant = blob[4]
    if variant not in (0xC3, 0xC4):
        raise RSE5Error(ERR_BAD_FORMAT,
                        "legacy: expected RSE5 C3 or C4, got 0x%02X" % variant)
    if len(blob) < 50:
        raise RSE5Error(ERR_BAD_FORMAT, "legacy: missing RSE5 header/tag")
    flags = blob[5]
    if flags & ~(7 if variant == 0xC4 else 1):
        raise RSE5Error(ERR_BAD_FORMAT, "legacy: unknown RSE5 flags")
    h = _trim(hwid)
    p = _trim(password)
    if flags & 1 and not h:
        raise RSE5Error(ERR_CREDENTIAL_MISSING,
                        "legacy: this export requires its original HWID")
    password_used = variant == 0xC3 or bool(flags & 2)
    if variant == 0xC4 and password_used and not p:
        raise RSE5Error(ERR_PASSWORD_MISSING,
                        "legacy: this export requires its export password")
    signature_used = variant == 0xC4 and bool(flags & 4)
    if signature_used and not re.fullmatch(r"[0-9A-Fa-f]{64}", signer or ""):
        raise RSE5Error(ERR_BAD_FORMAT,
                        "legacy: signer-bound export needs the APK cert SHA-256")
    material = "REESE-CUSTOM/RSE5|" + (h.upper() if flags & 1 else "") + "|" + (p if password_used else "")
    if signature_used:
        material += "|SIG:" + signer.upper()
    key = hashlib.pbkdf2_hmac("sha256", material.encode("utf-8"),
                              blob[6:22], 32768, 32)
    clear = _legacy_gcm(key, blob[22:34], blob[34:], blob[:34])
    return _legacy_inflate(_legacy_unpad(clear, True))


def _legacy_stream(seed, size):
    return b"".join(hashlib.sha256(seed + struct.pack(">I", n)).digest()
                    for n in range((size + 31) // 32))[:size]


def _legacy_unshuffle(body, seed):
    indices = list(range(len(body)))
    stream = _legacy_stream(seed, len(body) * 4)
    offset = 0
    for index in range(len(body) - 1, 0, -1):
        selected = struct.unpack_from(">I", stream, offset)[0] % (index + 1)
        offset += 4
        indices[index], indices[selected] = indices[selected], indices[index]
    return bytes(body[index] for index in indices)


def _legacy_cbc(key, iv, body):
    if _AES is None:
        raise RSE5Error(ERR_BAD_FORMAT, "legacy CBC needs PyCryptodome")
    from Crypto.Util.Padding import unpad as _pkcs7_unpad
    try:
        return _pkcs7_unpad(_AES.new(key, _AES.MODE_CBC, iv=iv).decrypt(body), 16)
    except ValueError:
        raise RSE5Error(ERR_BAD_FORMAT, "legacy: invalid CBC padding")


def _legacy_open(blob, hwid="", password=""):
    """Open an RSE1-RSE4 export. Returns the raw DEFLATE-packed bytes."""
    version = blob[:4]
    header_size = 40 if version == b"RSE4" else 56 if version == b"RSE1" else 72
    tag_size = 16 if version == b"RSE4" else 32
    if len(blob) < header_size + tag_size:
        raise RSE5Error(ERR_BAD_FORMAT, "legacy: incomplete header/tag")
    selector = blob[header_size - 8:header_size - 4]
    if not re.fullmatch(rb"[0-9a-f]{4}", selector):
        raise RSE5Error(ERR_BAD_FORMAT, "legacy: invalid HWID selector")
    h = _trim(hwid)
    p = _trim(password)
    if selector != b"0000" and not h:
        raise RSE5Error(ERR_CREDENTIAL_MISSING,
                        "legacy: this export requires its original HWID")
    selected_hwid = h.upper() if selector != b"0000" else ""
    declared = struct.unpack_from(">i", blob, header_size - 4)[0]
    if declared <= 0:
        raise RSE5Error(ERR_BAD_FORMAT, "legacy: invalid body length")
    if version == b"RSE4":
        material = ("REESE-CUSTOM/RSE4|" + selected_hwid + "|" + p).encode("utf-8")
        key = hashlib.pbkdf2_hmac("sha256", material, blob[4:20], 600000, 32)
        clear = _legacy_gcm(key, blob[20:32], blob[40:], blob[:40])
        if declared > len(clear):
            raise RSE5Error(ERR_BAD_FORMAT, "legacy: declared body too long")
        packed = _legacy_unpad(clear, False)
    else:
        if declared > MAX_LEGACY_BODY:
            raise RSE5Error(ERR_BAD_FORMAT, "legacy: body exceeds 2 MiB")
        if header_size + declared + 32 != len(blob):
            raise RSE5Error(ERR_BAD_FORMAT, "legacy: body length mismatch")
        rounds, size = {b"RSE1": (80000, 128), b"RSE2": (140000, 192),
                        b"RSE3": (24000, 192)}[version]
        material = "REESE-CUSTOM/config-envelope/v1|" + selected_hwid
        if p:
            material += "|" + p
        keys = hashlib.pbkdf2_hmac("sha256", material.encode("utf-8"),
                                   blob[4:20], rounds, size)
        if not hmac.compare_digest(
                hmac.digest(keys[96:128], blob[:-32], "sha256"), blob[-32:]):
            raise RSE5Error(ERR_AUTH, "legacy: HMAC failed")
        body = blob[header_size:-32]
        if version != b"RSE1":
            body = _legacy_cbc(keys[128:160], blob[48:64],
                               _legacy_unshuffle(body, keys[160:192]))
        body = bytes(a ^ b for a, b in zip(body, _legacy_stream(keys[64:96], len(body))))
        clear = _legacy_gcm(keys[:32], blob[20:32],
                            _legacy_cbc(keys[32:64], blob[32:48], body))
        packed = _legacy_unpad(clear, False) if version != b"RSE1" else clear
    return _legacy_inflate(packed)


def _legacy_envelope(raw, hwid=""):
    """Parse an opened legacy envelope into (meta, config) with the Kotlin
    import checks applied. `raw` is the inflated Envelope JSON bytes."""
    try:
        env = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise RSE5Error(ERR_BAD_FORMAT, "legacy: inner JSON unreadable") from exc
    if not isinstance(env, dict) or not isinstance(env.get("meta"), dict) \
            or not isinstance(env.get("config"), dict):
        raise RSE5Error(ERR_BAD_FORMAT, "legacy: expected meta/config envelope")
    meta, config = env["meta"], env["config"]
    _check_import(meta, config, hwid)
    return meta, config


def decode_rt_file(path_or_bytes, hwid="", password=""):
    """Decode a .RT / .reese file (path or bytes). Returns (meta, config).

    RSE5 0xC6 (3.23.28) via open_envelope(); RSE5 C3/C4 and RSE1-RSE4
    via the preserved legacy readers above."""
    data = path_or_bytes
    if isinstance(data, (str, os.PathLike)):
        with open(data, "rb") as f:
            data = f.read()
    if isinstance(data, str):
        data = data.encode("utf-8")
    if data[:4] in (b"RSE1", b"RSE2", b"RSE3", b"RSE4"):
        return _legacy_envelope(_legacy_open(data, hwid, password), hwid)
    if data.startswith(MAGIC) and len(data) > 4 and data[4] in (0xC3, 0xC4):
        return _legacy_envelope(
            _legacy_modern(data, hwid, password, APK_SIGNER_SHA256), hwid)
    return open_envelope(data, hwid, password)


# ---------------------------------------------------------------------------
# Text import: vmess://, vless://, trojan://, V2Ray JSON, base64 blob (Lb7/x)
# ---------------------------------------------------------------------------

class LinkError(ValueError):
    pass


def _b64decode_text(text):
    """Lb7/x.b: trim, strip whitespace, pad '=' to a multiple of 4."""
    s = "".join(text.split())
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=False)
    except (binascii.Error, ValueError):
        raise LinkError("is not valid base64.")


def _q(obj, aliases):
    """Lb7/x.q: first non-blank alias value; the literal string "null"
    counts as blank; "" when none is present."""
    if not isinstance(obj, dict):
        return ""
    for a in aliases:
        v = obj.get(a)
        if v is None:
            continue
        s = v if isinstance(v, str) else str(v)
        if s.strip() and s != "null":
            return s
    return ""


def _digits_int(text):
    """Digits-only port parsing (Lb7/x.f and the vmess port code)."""
    digits = "".join(c for c in str(text) if c.isdigit())
    return int(digits) if digits else None


def _network(name):
    """Lb7/x.h network mapping (input lowercased)."""
    return {
        "splithttp": "XHTTP", "xhttp": "XHTTP", "quic": "QUIC",
        "mkcp": "MKCP", "kcp": "MKCP", "http": "TCP", "grpc": "GRPC",
        "ws": "WS", "websocket": "WS", "h2": "H2",
        "httpupgrade": "HTTPUPGRADE",
    }.get((name or "").lower(), "TCP")


def _cipher(name):
    """Lb7/x.i: 'chacha20-poly1305' stays, anything else -> 'aes-128-gcm'."""
    return "chacha20-poly1305" if name == "chacha20-poly1305" else "aes-128-gcm"


def _alpn(text):
    """Lb7/x.k: split on ',', trim each entry; [] when blank."""
    if not text or not text.strip():
        return []
    return [p.strip() for p in text.split(",") if p.strip()]


def _host_port(text):
    """Lb7/x.s: 'host:port' with [IPv6]:port support, digits-only port."""
    s = text.strip()
    if s.startswith("["):
        end = s.find("]")
        if end < 0:
            return None
        host = s[1:end]
        rest = s[end + 1:]
        if not rest.startswith(":"):
            return None
        port = _digits_int(rest[1:])
        return (host, port) if port is not None else None
    idx = s.rfind(":")
    if idx <= 0:
        return None
    host = s[:idx]
    port = _digits_int(s[idx + 1:])
    if not host or port is None:
        return None
    return (host, port)


def _query_params(query):
    """Lb7/x.n: '&'-split, first '=' splits key/value, URL-decoded."""
    out = {}
    for part in query.split("&"):
        if not part.strip():
            continue
        if "=" in part:
            k, v = part.split("=", 1)
        else:
            k, v = part, ""
        out[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)
    return out


def _v2ray_profile(**kw):
    prof = dict(V2RAY_DEFAULTS)
    prof.update(kw)
    return {f: prof.get(f, V2RAY_DEFAULTS.get(f, "")) for f in V2RAY_FIELDS}


def _profile_valid(prof):
    """V2RayProfile.N(): host non-blank, port > 0, id non-blank."""
    return bool(prof.get("host", "").strip()) and \
        isinstance(prof.get("port"), int) and prof["port"] > 0 and \
        bool(prof.get("id", "").strip())


def parse_vmess_link(body):
    """Lb7/x.p: base64 JSON -> V2RayProfile (protocol VMESS)."""
    try:
        raw = _b64decode_text(body)
    except LinkError:
        raise LinkError("The vmess link is not valid base64.")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise LinkError("The vmess link does not contain readable JSON.")
    if not isinstance(obj, dict):
        raise LinkError("The vmess link does not contain readable JSON.")
    host = _q(obj, ["add"])
    if not host:
        raise LinkError('The vmess link has no address ("add").')
    uid = _q(obj, ["id"])
    if not uid:
        raise LinkError('The vmess link has no UUID ("id").')
    port = _digits_int(_q(obj, ["port"]))
    if port is None:
        raise LinkError("The vmess link has no usable port.")
    tls_val = _q(obj, ["tls"]).lower()
    path = _q(obj, ["path"]) or "/"
    fp = _q(obj, ["fp"]) or "chrome"
    return _v2ray_profile(
        remark=_q(obj, ["ps", "remark"]),
        protocol="VMESS", host=host, port=port, id=uid,
        network=_network(_q(obj, ["net"])),
        path=path, wsHost=_q(obj, ["host"]),
        tls=tls_val in ("tls", "reality"),
        sni=_q(obj, ["sni", "peer"]),
        security=_cipher(_q(obj, ["scy", "security"]).lower()),
        flow=_q(obj, ["flow"]),
        realityPublicKey=_q(obj, ["pbk"]),
        realityShortId=_q(obj, ["sid"]),
        spiderX=_q(obj, ["spx"]),
        fingerprint=fp,
        alpn=_alpn(_q(obj, ["alpn"])),
        transportKey=_q(obj, ["key", "seed"]))


def parse_vless_trojan_link(body, protocol):
    """Lb7/x.o: vless://uuid@host:port?query#remark (or trojan://pass@...)."""
    if "@" not in body:
        raise LinkError("The %s link is missing the '@' between the "
                        "credential and the address."
                        % protocol.lower())
    cred, rest = body.split("@", 1)
    cred = urllib.parse.unquote_plus(cred)
    if not cred:
        raise LinkError("The %s link has no %s."
                        % (protocol.lower(),
                           "password" if protocol == "TROJAN" else "UUID"))
    remark = ""
    if "#" in rest:
        rest, remark = rest.split("#", 1)
        remark = urllib.parse.unquote_plus(remark)
    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)
    hp = _host_port(rest)
    if hp is None:
        raise LinkError('Could not read host and port from "%s".' % rest)
    host, port = hp
    params = _query_params(query)
    net = _network(params.get("type") or params.get("net") or "")
    sec = (params.get("security") or "").lower()
    path = params.get("path") or params.get("serviceName") or "/"
    fp = params.get("fp") or "chrome"
    return _v2ray_profile(
        remark=remark,
        protocol=protocol, host=host, port=port, id=cred,
        network=net, path=path, wsHost=params.get("host") or "",
        tls=sec in ("tls", "reality"),
        sni=params.get("sni") or params.get("peer") or "",
        # Lb7/x.o hardcodes the cipher: security is always "aes-128-gcm"
        # (the `security` query param only decides TLS); allowInsecure is
        # `params["allowInsecure"] != "0"` -- absent counts as True.
        allowInsecure=params.get("allowInsecure") != "0",
        security="aes-128-gcm",
        flow=params.get("flow") or "",
        realityPublicKey=params.get("pbk") or "",
        realityShortId=params.get("sid") or "",
        spiderX=params.get("spx") or "",
        fingerprint=fp,
        alpn=_alpn(params.get("alpn") or ""),
        transportKey=params.get("seed") or params.get("key") or "")


def _outbound_to_profile(outbound, protocol):
    """Lb7/x.r: one V2Ray `outbounds` entry -> V2RayProfile."""
    settings = outbound.get("settings") or {}
    stream = outbound.get("streamSettings") or {}
    if not isinstance(settings, dict):
        settings = {}
    if not isinstance(stream, dict):
        stream = {}
    address, port, cred = "", 0, ""
    if protocol == "TROJAN":
        servers = settings.get("servers") or []
        if servers and isinstance(servers[0], dict):
            srv = servers[0]
            address = _q(srv, ["address"])
            port = _digits_int(_q(srv, ["port"])) or 0
            users = srv.get("users") or []
            if users and isinstance(users[0], dict):
                cred = _q(users[0], ["password"])
    else:
        vnext = settings.get("vnext") or []
        if vnext and isinstance(vnext[0], dict):
            node = vnext[0]
            address = _q(node, ["address"])
            port = _digits_int(_q(node, ["port"])) or 0
            users = node.get("users") or []
            if users and isinstance(users[0], dict):
                user = users[0]
                cred = _q(user, ["id"])
    user0 = {}
    if protocol == "TROJAN":
        servers = settings.get("servers") or []
        if servers and isinstance(servers[0], dict):
            users = servers[0].get("users") or []
            if users and isinstance(users[0], dict):
                user0 = users[0]
    else:
        vnext = settings.get("vnext") or []
        if vnext and isinstance(vnext[0], dict):
            users = vnext[0].get("users") or []
            if users and isinstance(users[0], dict):
                user0 = users[0]
    net = _network(_q(stream, ["network"]))
    sec = _q(stream, ["security"]).lower()
    tls_settings = stream.get("tlsSettings") or {}
    reality_settings = stream.get("realitySettings") or {}
    if not isinstance(tls_settings, dict):
        tls_settings = {}
    if not isinstance(reality_settings, dict):
        reality_settings = {}
    sni = _q(tls_settings, ["serverName"]) or _q(reality_settings, ["serverName"])
    fp = _q(tls_settings, ["fingerprint"]) or \
        _q(reality_settings, ["fingerprint"]) or "chrome"
    alpn = tls_settings.get("alpn") or reality_settings.get("alpn") or []
    if isinstance(alpn, str):
        alpn = _alpn(alpn)
    # transport-specific path/host/key, keyed by network (Lb7/x.r switch)
    path, ws_host, transport_key = "/", "", ""
    net_settings = {
        "WS": stream.get("wsSettings") or {},
        "GRPC": stream.get("grpcSettings") or {},
        "MKCP": stream.get("kcpSettings") or {},
        "QUIC": stream.get("quicSettings") or {},
        "XHTTP": stream.get("xhttpSettings") or stream.get("splithttpSettings") or {},
        "HTTPUPGRADE": stream.get("httpupgradeSettings") or {},
        "H2": stream.get("httpSettings") or {},
        "TCP": stream.get("tcpSettings") or {},
    }.get(net, {})
    if not isinstance(net_settings, dict):
        net_settings = {}
    if net == "GRPC":
        path = _q(net_settings, ["serviceName"]) or "/"
    elif net in ("WS", "XHTTP", "HTTPUPGRADE", "H2"):
        path = _q(net_settings, ["path"]) or "/"
        ws_host = _q(net_settings, ["host"])
        headers = net_settings.get("headers")
        if not ws_host and isinstance(headers, dict):
            ws_host = _q(headers, ["Host", "host"])
    elif net == "MKCP":
        transport_key = _q(net_settings, ["seed"])
    elif net == "QUIC":
        transport_key = _q(net_settings, ["key"])
        sec_q = _q(net_settings, ["security"])
        if sec_q:
            sec = sec_q.lower()
    return _v2ray_profile(
        remark=_q(outbound, ["tag"]),
        protocol=protocol, host=address, port=port, id=cred,
        network=net, path=path, wsHost=ws_host,
        tls=sec in ("tls", "reality"),
        sni=sni,
        security=_cipher(_q(user0, ["security", "encryption"]).lower()),
        flow=_q(user0, ["flow"]),
        realityPublicKey=_q(reality_settings, ["publicKey"]),
        realityShortId=_q(reality_settings, ["shortId"]),
        spiderX=_q(reality_settings, ["spiderX"]),
        fingerprint=fp,
        alpn=list(alpn) if isinstance(alpn, list) else [],
        transportKey=transport_key)


def parse_v2ray_json(text):
    """Lb7/x.l: V2Ray JSON config -> first valid vmess/vless/trojan profile."""
    try:
        obj = json.loads(text)
    except ValueError:
        raise LinkError("That text is not a readable V2Ray JSON config.")
    if not isinstance(obj, dict) or not isinstance(obj.get("outbounds"), list):
        raise LinkError('The config has no "outbounds" array.')
    for outbound in obj["outbounds"]:
        if not isinstance(outbound, dict):
            continue
        protocol = _q(outbound, ["protocol"]).lower()
        if protocol not in ("vmess", "vless", "trojan"):
            continue
        prof = _outbound_to_profile(outbound, protocol.upper())
        if _profile_valid(prof):
            return prof
    raise LinkError("The config has no vmess, vless or trojan server in "
                    "its outbounds.")


def parse_text(text):
    """Lb7/x.j: the app's paste-box entry point. Returns a V2RayProfile
    dict. Raises LinkError with the app's own messages on bad input."""
    if text is None:
        raise LinkError("Nothing pasted.")
    s = text.strip().replace("\n", "").replace("\r", "")
    if not s:
        raise LinkError("Nothing pasted.")
    if s.startswith("{"):
        return parse_v2ray_json(s)
    low = s.lower()
    if low.startswith("vmess://"):
        return parse_vmess_link(s[len("vmess://"):])
    if low.startswith("vless://"):
        return parse_vless_trojan_link(s[len("vless://"):], "VLESS")
    if low.startswith("trojan://"):
        return parse_vless_trojan_link(s[len("trojan://"):], "TROJAN")
    raw = _b64decode_text(s)
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise LinkError("Unknown format. Paste vmess://, vless://, trojan:// "
                        "links or a JSON config")
    if decoded.strip().startswith("{"):
        return parse_v2ray_json(decoded)
    raise LinkError("Unknown format. Paste vmess://, vless://, trojan:// "
                    "links or a JSON config")



# ---------------------------------------------------------------------------
# Engine-compatible entry points (repo 3.23.12 signatures, kept so the
# cloud file worker can call this script as `reese_tunnel.py <file>`).
# decode() returns the full Envelope document {"meta": ..., "config": ...};
# bannerImage (display-only, often huge Base64) is stripped at any depth.
# A config with a device-local vault is refused: it needs the original
# Android Keystore, which the server does not have.
# ---------------------------------------------------------------------------

def _decode_input(data):
    """Binary export passthrough; plain JSON; or strict-Base64 armored text."""
    if isinstance(data, bytes) and data.startswith(
            (MAGIC, b"RSE1", b"RSE2", b"RSE3", b"RSE4")):
        return data
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8-sig")
        except UnicodeError:
            raise RSE5Error(ERR_BAD_FORMAT, "unknown binary header") from None
    else:
        text = data
    if not isinstance(text, str) or not text.strip():
        raise RSE5Error(ERR_BAD_FORMAT, "empty input")
    if len(text.encode("utf-8")) > 16 * 1024 * 1024:
        raise RSE5Error(ERR_BAD_FORMAT, "input exceeds 16 MiB")
    text = text.strip()
    if text.startswith("{"):
        return text.encode("utf-8")
    body = "".join(line.strip() for line in text.splitlines()
                   if line.strip() and not line.strip().startswith("-----")
                   and ": " not in line.strip())
    compact = re.sub(r"[ \t\r\n]", "", body)
    if not compact or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        raise RSE5Error(ERR_BAD_FORMAT, "invalid Base64 input")
    try:
        return base64.b64decode(compact + "=" * (-len(compact) % 4),
                                validate=True)
    except (ValueError, binascii.Error):
        raise RSE5Error(ERR_BAD_FORMAT, "invalid Base64 input") from None


def _strip_bannerimage(node):
    pending = [node]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            item.pop("bannerImage", None)
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)


def _parse_plain_json(raw):
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise RSE5Error(ERR_BAD_FORMAT, "not valid UTF-8 JSON") from exc
    if not isinstance(doc, dict):
        raise RSE5Error(ERR_BAD_FORMAT, "expected a REESE JSON object")
    return doc


def decode(data, *, hwid="", password="", signer_sha256=APK_SIGNER_SHA256,
           audit=None):
    """Return the Envelope document {"meta": ..., "config": ...}."""
    h = _trim(hwid).upper()
    p = _trim(password)
    blob = _decode_input(data)
    info = {}
    if blob.startswith(MAGIC) and len(blob) > 4 and blob[4] in (0xC3, 0xC4):
        meta, config = _legacy_envelope(
            _legacy_modern(blob, h, p, signer_sha256), h)
        info.update(format="RSE5-%02X" % blob[4], authenticated=True)
    elif blob[:4] in (b"RSE1", b"RSE2", b"RSE3", b"RSE4"):
        meta, config = _legacy_envelope(_legacy_open(blob, h, p), h)
        info.update(format=blob[:4].decode("ascii"), authenticated=True)
    elif blob.startswith(MAGIC):
        meta, config = open_envelope(blob, h, p)
        info.update(format="RSE5-C6", authenticated=True)
    elif blob.startswith(b"{"):
        doc = _parse_plain_json(blob)
        if "config" in doc or "meta" in doc:
            if not isinstance(doc.get("config"), dict) \
                    or not isinstance(doc.get("meta"), dict):
                raise RSE5Error(ERR_BAD_FORMAT, "expected meta/config objects")
            meta, config = doc["meta"], doc["config"]
        else:
            config = doc
            meta = {}
        info.update(format="plain-json", authenticated=False)
    else:
        raise RSE5Error(ERR_BAD_FORMAT, "unrecognized REESE file header")
    if config.get("vault"):
        raise RSE5Error(ERR_BAD_FORMAT,
                        "profile contains a device-local vault requiring "
                        "its original Android Keystore")
    result = {"meta": meta, "config": config}
    _strip_bannerimage(result)
    if audit is not None:
        audit.update(info)
    return result


def run(file_bytes, **kwargs):
    try:
        return json.dumps(decode(file_bytes, **kwargs),
                          ensure_ascii=False, indent=2) + "\n"
    except RSE5Error:
        return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _usage():
    print("usage: reese_tunnel.py <file.rt> [--hwid HWID] [--password-file F | --ask-password] [-o OUT]")
    print("       reese_tunnel.py file <file.rt> [--hwid HWID] [--password PW]")
    print("       reese_tunnel.py text <vmess://...|vless://...|trojan://...|json>")
    print("       reese_tunnel.py seal <envelope.json> <out.rt> [--hwid HWID] [--password PW]")
    print("       reese_tunnel.py selftest")
    return 2


def _stdin_credentials():
    """{"hwid": ..., "password": ...} on stdin (cloud worker contract).

    Only when stdin is piped; an interactive terminal is never read.
    """
    try:
        if sys.stdin.isatty():
            return {}
        import os
        import stat as _stat
        mode = os.fstat(sys.stdin.fileno()).st_mode
        if _stat.S_ISCHR(mode):
            # /dev/null or a terminal: no credentials will ever arrive.
            return {}
        raw = sys.stdin.buffer.read(8193)
    except (OSError, ValueError):
        return {}
    if not raw:
        return {}
    try:
        creds = json.loads(raw.decode("utf-8"))
    except ValueError:
        return {}
    return creds if isinstance(creds, dict) else {}


def main(argv):
    if len(argv) < 2:
        return _usage()
    cmd = argv[1]
    if cmd in ("file", "text", "seal", "selftest"):
        try:
            return _main(argv)
        except (RSE5Error, LinkError) as e:
            print("error: %s" % e, file=sys.stderr)
            return 1
    # Engine form: reese_tunnel.py <file> [--hwid HWID]
    # [--password-file F | --ask-password] [-o OUT]. Credentials may also
    # arrive as JSON on stdin (see _stdin_credentials).
    import argparse
    parser = argparse.ArgumentParser(
        description="Offline REESE TUNNEL .RT/.reese decoder (RSE5-C6, C3/C4, RSE1-RSE4)")
    parser.add_argument("file")
    parser.add_argument("-o", "--output")
    parser.add_argument("--hwid", default="")
    parser.add_argument("--signer-sha256", default=APK_SIGNER_SHA256)
    credentials = parser.add_mutually_exclusive_group()
    credentials.add_argument("--ask-password", action="store_true")
    credentials.add_argument("--password-file")
    args = parser.parse_args(argv[1:])
    try:
        stdin_creds = _stdin_credentials()
        hwid = args.hwid or stdin_creds.get("hwid", "")
        password = stdin_creds.get("password", "")
        if args.ask_password:
            password = getpass.getpass("Export password: ")
        elif args.password_file:
            with open(args.password_file, "rb") as handle:
                secret = handle.read(4097)
            if len(secret) > 4096:
                raise RSE5Error(ERR_BAD_FORMAT, "password file exceeds 4096 bytes")
            password = secret.decode("utf-8-sig")
        with open(args.file, "rb") as handle:
            raw = handle.read(16 * 1024 * 1024 + 1)
        result = json.dumps(decode(raw, hwid=hwid, password=password,
                                   signer_sha256=args.signer_sha256),
                            ensure_ascii=False, indent=2) + "\n"
        if args.output:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(result)
        else:
            sys.stdout.write(result)
        return 0
    except RSE5Error as error:
        # Engine credential contract (same as NadiaVPN / Sentinel): a
        # credential error is exit 3 with {"workerError": ...} on stdout,
        # so engine.decode_file() raises PASSWORD_REQUIRED /
        # HWID_REQUIRED / AUTH_FAILED instead of DECODE_FAILED. Native
        # RSE5 codes: 2 password missing, 3 HWID missing, 4 auth
        # failure, 6 wrong device (HWID-only file, wrong HWID).
        worker_error = {
            ERR_PASSWORD_MISSING: "PASSWORD_REQUIRED",
            ERR_CREDENTIAL_MISSING: "HWID_REQUIRED",
            ERR_AUTH: "AUTH_FAILED",
            ERR_WRONG_DEVICE: "AUTH_FAILED",
        }.get(error.code)
        if worker_error is not None:
            sys.stdout.write(json.dumps({"workerError": worker_error}))
            return 3
        print(json.dumps({"error": "DECODE_FAILED", "code": error.code,
                          "message": str(error)}), file=sys.stderr)
        return 1
    except (OSError, EOFError, UnicodeError):
        print(json.dumps({"error": "IO_ERROR",
                          "message": "Cannot read credentials/input or write the result."}),
              file=sys.stderr)
        return 2


def _main(argv):
    cmd = argv[1]
    if cmd == "file" and len(argv) >= 3:
        hwid, pw = "", ""
        args = argv[3:]
        for i, a in enumerate(args):
            if a == "--hwid" and i + 1 < len(args):
                hwid = args[i + 1]
            elif a == "--password" and i + 1 < len(args):
                pw = args[i + 1]
        meta, config = decode_rt_file(argv[2], hwid, pw)
        print(json.dumps({"meta": meta, "config": config}, indent=1,
                         ensure_ascii=False))
        return 0
    if cmd == "text" and len(argv) >= 3:
        prof = parse_text(argv[2])
        print(json.dumps(prof, indent=1, ensure_ascii=False))
        return 0
    if cmd == "seal" and len(argv) >= 4:
        hwid, pw = "", ""
        args = argv[4:]
        for i, a in enumerate(args):
            if a == "--hwid" and i + 1 < len(args):
                hwid = args[i + 1]
            elif a == "--password" and i + 1 < len(args):
                pw = args[i + 1]
        with open(argv[2], "r", encoding="utf-8") as f:
            env = json.load(f)
        data = seal_envelope(env.get("meta") or {}, env.get("config") or {},
                             hwid, pw)
        with open(argv[3], "wb") as f:
            f.write(data)
        print("sealed %d bytes -> %s" % (len(data), argv[3]))
        return 0
    if cmd == "selftest":
        _selftest()
        return 0
    return _usage()


def _selftest():
    # RSE5 round-trips (byte-identical oracle cross-checks live in
    # test_oracle.py; here: self-consistency + error codes).
    pt = b"HELLO-RSE5-TEST" * 4
    sealed = rse5_seal(pt, "abc-123", "test123")
    assert sealed[:4] == MAGIC and sealed[4] == VERSION and sealed[5] == 3
    assert rse5_open(sealed, "abc-123", "test123") == pt
    assert rse5_open(sealed, "ABC-123", "test123") == pt  # HWID case-insensitive
    for bad_h, bad_p in (("abc-123", "wrong"), ("other", "test123")):
        try:
            rse5_open(sealed, bad_h, bad_p)
            raise AssertionError("auth should have failed")
        except RSE5Error as e:
            assert e.code == ERR_AUTH, e.code
    try:
        rse5_open(sealed)
        raise AssertionError("missing creds should have failed")
    except RSE5Error as e:
        assert e.code == ERR_CREDENTIAL_MISSING, e.code
    try:
        rse5_open(b"garbage")
        raise AssertionError("bad magic should have failed")
    except RSE5Error as e:
        assert e.code == ERR_BAD_FORMAT, e.code
    # pad / deflate round-trip
    assert inflate_raw(deflate_raw(b"hello")) == b"hello"
    assert unpad(pad(b"hello world")) == b"hello world"
    # envelope round-trip
    meta = {"name": "t", "author": "REESE TUNNEL"}
    config = {"profileName": "p", "sshHost": "1.2.3.4", "sshPort": 22,
              "username": "u", "password": "pw", "payload": "GET / [protocol]"}
    blob = seal_envelope(meta, config, "MYHWID", "pw123")
    m2, c2 = open_envelope(blob, "MYHWID", "pw123")
    assert m2["name"] == "t" and c2["sshHost"] == "1.2.3.4"
    assert c2["payload"] == "GET / [protocol]"
    # links
    vm = "vmess://" + base64.b64encode(json.dumps(
        {"v": "2", "ps": "test", "add": "example.com", "port": "443",
         "id": "11111111-2222-3333-4444-555555555555", "aid": "0",
         "net": "ws", "type": "none", "host": "h.example.com",
         "path": "/ws", "tls": "tls", "sni": "s.example.com",
         "scy": "auto"}).encode()).decode()
    p = parse_text(vm)
    assert p["protocol"] == "VMESS" and p["host"] == "example.com"
    assert p["port"] == 443 and p["network"] == "WS" and p["tls"] is True
    p = parse_text("vless://11111111-2222-3333-4444-555555555555@example.com:443"
                   "?type=ws&security=tls&path=%2Fws&host=h.example.com#My%20VLESS")
    assert p["protocol"] == "VLESS" and p["path"] == "/ws"
    assert p["remark"] == "My VLESS" and p["tls"] is True
    p = parse_text("trojan://secret@example.com:443?security=tls#T")
    assert p["protocol"] == "TROJAN" and p["id"] == "secret"
    cfg = {"outbounds": [{"protocol": "vless",
                          "settings": {"vnext": [{"address": "x.example.com",
                                                  "port": 8443,
                                                  "users": [{"id": "uuid-1"}]}]},
                          "streamSettings": {"network": "tcp",
                                             "security": "tls",
                                             "tlsSettings": {"serverName": "s.example.com"}}}]}
    p = parse_text(json.dumps(cfg))
    assert p["protocol"] == "VLESS" and p["host"] == "x.example.com"
    assert p["port"] == 8443 and p["sni"] == "s.example.com"
    try:
        parse_text("")
        raise AssertionError("blank should have failed")
    except LinkError as e:
        assert str(e) == "Nothing pasted."
    print("selftest OK")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
