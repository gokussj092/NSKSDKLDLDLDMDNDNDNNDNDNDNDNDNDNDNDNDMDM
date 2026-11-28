#!/usr/bin/env python3
"""Surya Tunnel 1.6 (com.suryavpn.tunnel, versionCode 6) - .st file decoder
and SVPN text-share decoder.

Format (reverse-engineered from the app's own Go core, libgojni.so,
package github.com/xtls/libxray/suryacore, and the Kotlin import/export
code in j3/AbstractC1843b + j3/AbstractC1853l + f3/J + f3/Q):

  Binary .st file, no password (configEncryptRaw / configDecryptRaw):
    V3 (current, what the app writes today):
      "SPN1" + 0x03 + salt[16] + nonce[12] + AES-256-GCM(ciphertext)
      key = PBKDF2-HmacSHA256(password=b"SuryaVPN-ConfigLock-v1",
                              salt=salt, iterations=150000, dkLen=32)
      AAD = none. Plaintext = export JSON (see below).
    V2:
      "SPN1" + 0x02 + nonce[12] + AES-256-GCM(ciphertext)
      key = SHA-256(b"SuryaVPN-ConfigLock-v1")  (fixed, salt unused)
    V1 legacy (no magic; used when the data does not start with "SPN1"):
      iv[16] + AES-256-CBC(ciphertext, PKCS7 pad)
      key = SHA-256(b"SuryaVPN-ConfigLock-v1")

  Binary .st file, password-protected (f3/J + f3/Q, magic "SPW1"):
      "SPW1" + salt[16] + iv[12] + AES-256-GCM(ciphertext, AAD=b"SPW1")
      key = PBKDF2-HmacSHA256(password, salt, 120000, 256-bit)
      Plaintext = the SPN1 v2/v3 binary above.
    The import screen asks for the password only when the first 4 bytes
    are "SPW1" (and the file is longer than 48 bytes).

  Export JSON (what the plaintext is):
    {"app": "SuryaVPN", "format": "suryavpn-config", "version": 1,
     "exportedAt": <ms>, "exportName": ..., "exportNote": ...,
     "profiles": [ {profile}, ... ]}
    Profile fields (long names): host, port, username, password,
    modeIndex (5 = Xray, 0-4 = SSH variants), sni, payload, proxyHost,
    proxyPort, tlsVersion, useWebSocket, wsPath, proxyRawMode, xrayLink
    (raw vmess:// / vless:// / trojan:// link for modeIndex 5),
    customHeaders, ignoreCertErrors, dns1, dns2, accountName, note,
    expiresAt, tlsEnabled, proxyEnabled, payloadEnabled,
    enhancedEnabled, slowDnsEnabled, slowDnsNs, slowDnsPubKey,
    slowDnsResolver, slowDnsType, lockMode
    (NONE | LOCK_PAYLOAD_PROXY | LOCK_ALL).
    Locked profiles keep the protected fields in "_locked": base64 of
    another SPN1 v2/v3 binary whose JSON uses the same long names, or
    the short names (h, p, u, pw, m, s, pl, ph, pp, tv, ws, wp, pr, x,
    ch, ic, d1, d2, an, n, te, pe, ple, ee, se, sn, sk, sr, st, ea, en,
    ex, lm, _l) which this decoder expands.

  Text shares (AbstractC1843b.t):
    SVPN1:<base64>            base64 of a single profile JSON
    SVPN2:<base64>            base64 of an SPN1 v2/v3 binary (1 profile)
    SVPN3:<base64url-nopad>   encrypted single profile (see _svpn34_decrypt)
    SVPN4:<base64url-nopad>   encrypted export JSON (profiles array)
    bare base64               SPN1 v2/v3 binary, else JSON text
    bare JSON                 export JSON / single profile / array
    SVPN3/4 envelope:
      [flags:1][wrappedKeyLen:1][wrappedKey][salt:16 if flags&1]
      [iv:12][AES-256-GCM ciphertext, AAD = first 2 bytes]
      wrappedKey = SPN1 v3 binary of base64(nopad,nowrap) of the
      32-byte key material; key = key material, or when a password is
      present: SHA-256(keyMaterial || PBKDF2(password, salt, 120000)).
      Plaintext = raw-deflate of the JSON (inflate with wbits=-15,
      the app appends one trailing 0x00 byte before inflating).

  Cloud sync (j3/C1846e) - NOT a built-in catalog: the app ships with
  NO catalog URL (default cloud_url is ""). The user pastes any URL
  hosting an "Export All" JSON file; the app fetches it with:
    GET <url>, User-Agent: SuryaVPN-CloudSync/1.0,
    connect/read timeout 15 s, follow redirects, 5 MB cap, read as
    UTF-8 text. fetch_cloud_config() below replicates that request.

  This format is DIFFERENT from Sentinel Tunnel's .st (magic "STCF",
  XOR with ST_KEY, AES-GCM + HMAC). Only the ".st" suffix is shared.

Engine contract (same as the other SP-DECODE file decoders):
  run(data, password=None, hwid=None) -> str (JSON) or None
  CLI: surya_tunnel.py <file.st | file.txt | -> [--password PW]
       [--url URL] [--selftest]
  Missing password for a protected file -> stdout
  {"workerError": "PASSWORD_REQUIRED"} and exit code 3.
  Passwords never appear in logs, output JSON or error text.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac as hmac_mod
import json
import sys
import urllib.request
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"SPN1"
MAGIC_PW = b"SPW1"
LABEL = b"SuryaVPN-ConfigLock-v1"
KEY_V2 = hashlib.sha256(LABEL).digest()
MAX_BYTES = 8 * 1024 * 1024
CLOUD_UA = "SuryaVPN-CloudSync/1.0"
CLOUD_MAX_BYTES = 5 * 1024 * 1024

SHORT_KEYS = {
    "h": "host", "p": "port", "u": "username", "pw": "password",
    "m": "modeIndex", "s": "sni", "pl": "payload", "ph": "proxyHost",
    "pp": "proxyPort", "tv": "tlsVersion", "ws": "useWebSocket",
    "wp": "wsPath", "pr": "proxyRawMode", "x": "xrayLink",
    "ch": "customHeaders", "ic": "ignoreCertErrors", "d1": "dns1",
    "d2": "dns2", "an": "accountName", "n": "note", "te": "tlsEnabled",
    "pe": "proxyEnabled", "ple": "payloadEnabled",
    "ee": "enhancedEnabled", "se": "slowDnsEnabled", "sn": "slowDnsNs",
    "sk": "slowDnsPubKey", "sr": "slowDnsResolver", "st": "slowDnsType",
    "ea": "expiresAt", "en": "exportName", "ex": "exportNote",
    "lm": "lockMode", "_l": "_locked",
}


class SuryaDecodeError(Exception):
    """Decode failure with an engine worker ``code``."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def b64d(s, urlsafe=False):
    if isinstance(s, bytes):
        s = s.decode("ascii")
    s = "".join(str(s).split())
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    if urlsafe:
        return base64.urlsafe_b64decode(s)
    return base64.b64decode(s)


def _key_v3(salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", LABEL, salt, 150000, 32)


def _gcm_open(key: bytes, nonce: bytes, ct: bytes):
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        return None


def _cbc_decrypt(key: bytes, iv: bytes, ct: bytes):
    if len(ct) == 0 or len(ct) % 16:
        return None
    try:
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        pt = dec.update(ct) + dec.finalize()
    except Exception:
        return None
    if not pt:
        return None
    pad = pt[-1]
    if pad < 1 or pad > 16 or pt[-pad:] != bytes([pad]) * pad:
        return None
    return pt[:-pad]


def config_decrypt_raw(data: bytes):
    """Go suryacore.ConfigDecryptRaw: SPN1 v3/v2, else V1 legacy CBC."""
    if data is None:
        return None
    if len(data) >= 5 and data[:4] == MAGIC:
        ver = data[4]
        if ver == 3:
            if len(data) < 49:
                return None
            salt, nonce, ct = data[5:21], data[21:33], data[33:]
            return _gcm_open(_key_v3(salt), nonce, ct)
        if ver == 2:
            if len(data) < 33:
                return None
            nonce, ct = data[5:17], data[17:]
            return _gcm_open(KEY_V2, nonce, ct)
        return None
    # V1 legacy: iv[16] + AES-256-CBC, no magic
    if len(data) >= 32 and (len(data) - 16) % 16 == 0:
        return _cbc_decrypt(KEY_V2, data[:16], data[16:])
    return None


def config_encrypt_raw_v3(plaintext: bytes) -> bytes:
    """Go suryacore.ConfigEncryptRaw (V3 writer, for round-trip tests)."""
    import os
    salt = os.urandom(16)
    nonce = os.urandom(12)
    ct = AESGCM(_key_v3(salt)).encrypt(nonce, plaintext, None)
    return MAGIC + b"\x03" + salt + nonce + ct


def _expand_short(obj):
    if isinstance(obj, dict):
        return {SHORT_KEYS.get(k, k): _expand_short(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_short(v) for v in obj]
    return obj


def _unlock_profile(profile: dict) -> dict:
    """Merge a profile's "_locked" blob (base64 SPN1 binary) into it."""
    profile = dict(profile)
    locked = profile.get("_locked")
    if isinstance(locked, str) and locked:
        try:
            inner = config_decrypt_raw(b64d(locked))
        except Exception:
            inner = None
        if inner is not None:
            try:
                merged = _expand_short(json.loads(inner.decode("utf-8")))
            except Exception:
                merged = None
            if isinstance(merged, dict):
                for k, v in merged.items():
                    profile[k] = v
        profile.pop("_locked", None)
    return profile


def parse_export(obj):
    """Normalize export JSON / single profile / array into a result dict."""
    if isinstance(obj, list):
        profiles = [_unlock_profile(_expand_short(p)) if isinstance(p, dict) else p
                    for p in obj]
        return {"app": "SuryaVPN", "format": "suryavpn-config",
                "version": 1, "profiles": profiles}
    if isinstance(obj, dict):
        obj = _expand_short(obj)
        if isinstance(obj.get("profiles"), list):
            out = dict(obj)
            out["profiles"] = [_unlock_profile(p) if isinstance(p, dict) else p
                               for p in obj["profiles"]]
            return out
        return {"app": "SuryaVPN", "format": "suryavpn-config",
                "version": 1, "profiles": [_unlock_profile(obj)]}
    return None


def _svpn34_decrypt(text: str, password):
    """AbstractC1843b.R: SVPN3/SVPN4 envelope -> JSON string or None."""
    try:
        raw = b64d(text, urlsafe=True)
    except Exception:
        return None
    if len(raw) < 2:
        return None
    flags, wlen = raw[0], raw[1]
    pos = 2
    if len(raw) < pos + wlen:
        return None
    wrapped = raw[pos:pos + wlen]
    pos += wlen
    salt = None
    if flags & 1:
        if password:
            if len(raw) < pos + 16:
                return None
            salt = raw[pos:pos + 16]
            pos += 16
        else:
            raise SuryaDecodeError("PASSWORD_REQUIRED",
                                   "password-protected share text")
    if len(raw) < pos + 28:
        return None
    iv, ct = raw[pos:pos + 12], raw[pos + 12:]
    try:
        key_material_b64 = config_decrypt_raw(wrapped)
    except Exception:
        key_material_b64 = None
    if key_material_b64 is None:
        return None
    try:
        key_material = b64d(key_material_b64)
    except Exception:
        return None
    if password and salt is not None:
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                      salt, 120000, 32)
        key = hashlib.sha256(key_material + derived).digest()
    else:
        key = key_material
    try:
        pt = AESGCM(key).decrypt(iv, ct, bytes([flags, wlen]))
    except Exception:
        return None
    try:
        return zlib.decompressobj(-15).decompress(pt + b"\x00").decode("utf-8")
    except Exception:
        return None


def decode_text(text: str, password=None):
    """AbstractC1843b.t: SVPN1/2/3/4, bare base64, bare JSON -> result."""
    if text is None:
        return None
    s = text.strip()
    if not s:
        return None
    upper = s.upper()
    if upper.startswith("SVPN3:"):
        js = _svpn34_decrypt(s[6:], password)
        if js is None:
            return None
        try:
            return parse_export(json.loads(js))
        except Exception:
            return None
    if upper.startswith("SVPN4:"):
        js = _svpn34_decrypt(s[6:], password)
        if js is None:
            return None
        try:
            return parse_export(json.loads(js))
        except Exception:
            return None
    if upper.startswith("SVPN2:"):
        try:
            raw = config_decrypt_raw(b64d(s[6:]))
        except Exception:
            return None
        if raw is None:
            return None
        try:
            return parse_export(json.loads(raw.decode("utf-8")))
        except Exception:
            return None
    if upper.startswith("SVPN1:"):
        try:
            return parse_export(json.loads(b64d(s[6:]).decode("utf-8")))
        except Exception:
            return None
    # Bare base64 of an SPN1 binary, else JSON text.
    try:
        raw = config_decrypt_raw(b64d(s))
    except Exception:
        raw = None
    if raw is not None:
        try:
            return parse_export(json.loads(raw.decode("utf-8")))
        except Exception:
            return None
    try:
        return parse_export(json.loads(s))
    except Exception:
        return None


def decode_spw1(data: bytes, password):
    """f3/J: SPW1 password-protected .st file -> SPN1 binary plaintext."""
    if password is None:
        raise SuryaDecodeError("PASSWORD_REQUIRED",
                               "password-protected .st file")
    if len(data) <= 48 or data[:4] != MAGIC_PW:
        return None
    salt, iv, ct = data[4:20], data[20:32], data[32:]
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                              salt, 120000, 32)
    try:
        return AESGCM(key).decrypt(iv, ct, MAGIC_PW)
    except Exception:
        return None


def decode_file(data: bytes, password=None):
    """Full .st file decode -> result dict (or raises PASSWORD_REQUIRED)."""
    if data is None or len(data) == 0:
        return None
    if len(data) > 48 and data[:4] == MAGIC_PW:
        inner = decode_spw1(data, password)
        if inner is None:
            return None
        data = inner
    raw = config_decrypt_raw(data)
    if raw is not None:
        try:
            return parse_export(json.loads(raw.decode("utf-8")))
        except Exception:
            return None
    # Not binary: maybe the file holds share text / JSON.
    try:
        return decode_text(data.decode("utf-8", "replace"), password)
    except Exception:
        return None


def fetch_cloud_config(url: str) -> str:
    """j3/C1846e replica: GET, UA SuryaVPN-CloudSync/1.0, 15 s, 5 MB."""
    if not url.lower().startswith(("http://", "https://")):
        raise SuryaDecodeError("BAD_URL",
                               "URL must start with http:// or https://")
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": CLOUD_UA})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if not (200 <= resp.status < 300):
                raise SuryaDecodeError("HTTP_%d" % resp.status,
                                       "server returned HTTP %d" % resp.status)
            chunks = []
            total = 0
            while True:
                buf = resp.read(65536)
                if not buf:
                    break
                total += len(buf)
                if total > CLOUD_MAX_BYTES:
                    raise SuryaDecodeError("TOO_LARGE",
                                           "cloud config exceeds 5 MB")
                chunks.append(buf)
            return b"".join(chunks).decode("utf-8")
    except SuryaDecodeError:
        raise
    except Exception as e:
        raise SuryaDecodeError("FETCH_FAILED", "cloud fetch failed: %s" % e)


def run(data, password=None, hwid=None) -> str | None:
    """Engine contract: bytes -> JSON string result, or None."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if data is None or len(data) > MAX_BYTES:
        return None
    try:
        result = decode_file(data, password)
    except SuryaDecodeError:
        raise
    if result is None:
        return None
    return json.dumps(result, ensure_ascii=False)


def _svpn34_encrypt(plaintext: str, password=None) -> str:
    """AbstractC1843b.I writer (for --selftest round-trips only)."""
    import os
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    body = comp.compress(plaintext.encode("utf-8")) + comp.flush()
    key_material = os.urandom(32)
    # The app wraps base64(keyMaterial) with flags 3 (NO_PADDING|NO_WRAP).
    wrapped = config_encrypt_raw_v3(
        base64.b64encode(key_material).decode("ascii").rstrip("=").encode("utf-8"))
    if len(wrapped) >= 256:
        raise ValueError("wrapped key too long")
    flags = 1 if password else 0
    out = bytearray([flags, len(wrapped)])
    out += wrapped
    salt = None
    if password:
        salt = os.urandom(16)
        out += salt
    iv = os.urandom(12)
    if password and salt is not None:
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                      salt, 120000, 32)
        key = hashlib.sha256(key_material + derived).digest()
    else:
        key = key_material
    out += iv
    out += AESGCM(key).encrypt(iv, body, bytes([flags, len(wrapped)]))
    return base64.urlsafe_b64encode(bytes(out)).decode("ascii").rstrip("=")


def selftest() -> bool:
    import os
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS " if cond else "FAIL ") + name)
        ok = ok and bool(cond)

    profile = {"host": "example.test", "port": 22, "username": "u",
               "password": "p", "modeIndex": 0, "sni": "s",
               "payload": "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
               "slowDnsEnabled": True, "slowDnsNs": "ns.test",
               "slowDnsPubKey": "00" * 32, "slowDnsResolver": "8.8.8.8",
               "slowDnsType": "auto", "lockMode": "NONE"}
    export = {"app": "SuryaVPN", "format": "suryavpn-config", "version": 1,
              "exportedAt": 1795801352792, "profiles": [profile]}
    js = json.dumps(export, ensure_ascii=False)

    # V3 round-trip
    blob = config_encrypt_raw_v3(js.encode("utf-8"))
    check("V3 round-trip", decode_file(blob) == parse_export(export))
    # V2 round-trip (synthetic writer per decryptV2 layout)
    nonce = os.urandom(12)
    v2 = MAGIC + b"\x02" + nonce + AESGCM(KEY_V2).encrypt(
        nonce, js.encode("utf-8"), None)
    check("V2 round-trip", decode_file(v2) == parse_export(export))
    # V1 legacy round-trip (synthetic writer per decryptV1Legacy layout)
    iv = os.urandom(16)
    pad = 16 - (len(js.encode("utf-8")) % 16)
    raw = js.encode("utf-8") + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(KEY_V2), modes.CBC(iv)).encryptor()
    v1 = iv + enc.update(raw) + enc.finalize()
    check("V1 legacy round-trip", decode_file(v1) == parse_export(export))
    # SPW1 password file round-trip
    salt = os.urandom(16)
    siv = os.urandom(12)
    key = hashlib.pbkdf2_hmac("sha256", b"secret", salt, 120000, 32)
    spw1 = MAGIC_PW + salt + siv + AESGCM(key).encrypt(siv, blob, MAGIC_PW)
    try:
        decode_file(spw1)
        check("SPW1 without password -> PASSWORD_REQUIRED", False)
    except SuryaDecodeError as e:
        check("SPW1 without password -> PASSWORD_REQUIRED",
              e.code == "PASSWORD_REQUIRED")
    check("SPW1 with password",
          decode_file(spw1, "secret") == parse_export(export))
    # _locked merge (LOCK_ALL profile, short keys inside)
    locked_inner = {"h": "ns.test", "p": 80, "u": "uu", "pw": "pp",
                    "se": True, "sn": "ns.test"}
    locked_blob = config_encrypt_raw_v3(
        json.dumps(locked_inner).encode("utf-8"))
    locked_profile = {"modeIndex": 0, "useWebSocket": True,
                      "accountName": "t", "lockMode": "LOCK_ALL",
                      "_locked": base64.b64encode(locked_blob).decode()}
    merged = parse_export({"profiles": [locked_profile]})["profiles"][0]
    check("_locked short-key merge",
          merged.get("host") == "ns.test" and merged.get("port") == 80
          and "_locked" not in merged)
    # SVPN4 / SVPN3 round-trips
    check("SVPN4 round-trip",
          decode_text("SVPN4:" + _svpn34_encrypt(js)) == parse_export(export))
    check("SVPN3 round-trip",
          decode_text("SVPN3:" + _svpn34_encrypt(
              json.dumps(profile)))["profiles"][0]["host"] == "example.test")
    check("SVPN4 with password round-trip",
          decode_text("SVPN4:" + _svpn34_encrypt(js, "pw123"),
                      "pw123") == parse_export(export))
    try:
        decode_text("SVPN4:" + _svpn34_encrypt(js, "pw123"))
        check("SVPN4 without password -> PASSWORD_REQUIRED", False)
    except SuryaDecodeError as e:
        check("SVPN4 without password -> PASSWORD_REQUIRED",
              e.code == "PASSWORD_REQUIRED")
    # SVPN2 / SVPN1
    check("SVPN2 round-trip",
          decode_text("SVPN2:" + base64.b64encode(blob).decode())
          == parse_export(export))
    check("SVPN1 round-trip",
          decode_text("SVPN1:" + base64.b64encode(
              json.dumps(profile).encode()).decode())
          ["profiles"][0]["host"] == "example.test")
    # Bare JSON
    check("bare JSON export",
          decode_text(js) == parse_export(export))
    # Real sample (path next to the script's test fixtures if present)
    return ok


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Surya Tunnel 1.6 (.st / SVPN text) decoder")
    ap.add_argument("file", nargs="?",
                    help=".st file, text file, or - for stdin")
    ap.add_argument("--password", default=None)
    ap.add_argument("--url", default=None,
                    help="Cloud Config URL to fetch (replicates the "
                         "app's Cloud Sync request)")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        sys.exit(0 if selftest() else 1)
    if args.url:
        try:
            text = fetch_cloud_config(args.url)
        except SuryaDecodeError as e:
            print(json.dumps({"workerError": e.code}), file=sys.stderr)
            return 2
        try:
            result = decode_text(text, args.password)
        except SuryaDecodeError as e:
            print(json.dumps({"workerError": e.code}))
            return 3
        if result is None:
            print(json.dumps({"workerError": "DECODE_FAILED"}),
                  file=sys.stderr)
            return 2
        print(json.dumps(result, ensure_ascii=False))
        return 0
    if not args.file:
        ap.error("file or --url or --selftest required")
    data = (sys.stdin.buffer.read() if args.file == "-"
            else open(args.file, "rb").read())
    try:
        out = run(data, args.password)
    except SuryaDecodeError as e:
        print(json.dumps({"workerError": e.code}))
        return 3
    if out is None:
        print(json.dumps({"workerError": "DECODE_FAILED"}), file=sys.stderr)
        return 2
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
