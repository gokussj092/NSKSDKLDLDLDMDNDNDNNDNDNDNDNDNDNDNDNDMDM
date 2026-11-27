#!/usr/bin/env python3
"""Sentinel Tunnel 4.0.0 (online.zarray.sentineltunnel) - .st file decoder.

STCF format (export W3/e.p / import W3/e.e), verified by round-trip for
all 7 config types, with and without a password (14/14):
  plain = b"STCF" + bytes([1]) + <ConfigExport JSON, UTF-8>
  file  = XOR with ST_KEY, then reverse the first 16 bytes of every
          32-byte block (only if i+16 < len).
ConfigExport: version, appSignature "SENTINEL_TUNNEL_CONFIG_V1",
configType (CUSTOM_SSH | CUSTOM_SSL | CUSTOM_SSL_OVPN | CUSTOM_OPENVPN |
CUSTOM_DNSTT | CUSTOM_HYSTERIA | CUSTOM_XRAY), name, isLocked,
isPasswordProtected, passwordHash, salt, notes, createdAt, expiresAt,
configData {iv, data, hmac, keySalt} (Base64 NO_WRAP).
Payload: AES-256-GCM (IV 12 B, tag 128 b) + HMAC-SHA256(iv||ciphertext)
verified before decrypt. Key: no password -> SHA-256(ST_KEY || salt);
with password -> PBKDF2-HmacSHA256(password, salt, 100000, 256-bit),
salt = ConfigExport.salt = configData.keySalt.

WHY THIS DECODER REPLACES THE C0 ROUTE (decoders/Python/sentinel.py):
that decoder's _derive_key uses base64(passwordHash) AS the data key
whenever passwordHash is present. Verified app bug (export LT3/D2):
passwordHash is PBKDF2(password, salt2) with a SECOND random salt that
is never stored, so it can never be the data key - every
password-protected .st fails its HMAC check and decodes to nothing.
This decoder ignores passwordHash and derives the key from the password
directly (HMAC proves the key). The no-password path is identical in
both decoders (SHA-256(ST_KEY || salt), same transform, same HMAC).

Engine contract (same as decoders/Python/apps/NadiaVPN/file_decoder.py):
  run(data, password=None, hwid=None) -> str (JSON) or None
  CLI: file_decoder.py <file.st> [--password PW]
       credentials may also arrive on stdin as JSON {"password": ...}
       (engine contract); missing password -> stdout
       {"workerError": "PASSWORD_REQUIRED"} and exit code 3.
  Passwords never appear in logs, output JSON or error text.
  --selftest runs the 14 round-trips + tamper check on synthetic data.

ST_KEY is the .st format key (32 bytes, from the app's own W3/e.a); it
is the legitimate decoding key for this format and lives only here.
No VPS key material (API key / HMAC key / AES key) is in this file:
the .st format does not use it.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac as hmac_mod
import json
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ST_KEY = b"SENTINEL_TUNNEL_CONFIG_KEY_V1_20"  # W3/e.a, 32 bytes
APP_SIGNATURE = "SENTINEL_TUNNEL_CONFIG_V1"
MAGIC = b"STCF"
MAX_BYTES = 8 * 1024 * 1024

CONFIG_TYPES = ["CUSTOM_SSH", "CUSTOM_SSL", "CUSTOM_SSL_OVPN",
                "CUSTOM_OPENVPN", "CUSTOM_DNSTT", "CUSTOM_HYSTERIA",
                "CUSTOM_XRAY"]


class SentinelDecodeError(Exception):
    """Decode failure with an engine worker ``code``."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def b64d(s):
    return base64.b64decode(s)


def b64e(b):
    return base64.b64encode(b).decode("ascii")


def _reverse_chunks(buf: bytes) -> bytes:
    lst = bytearray(buf)
    n = len(lst)
    last = ((n - 1) // 32) * 32 if n else -1
    i = 0
    while True:
        if i + 16 < n:
            end = min(i + 16, n)
            lst[i:end] = lst[i:end][::-1]
        if i == last:
            break
        i += 32
    return bytes(lst)


def st_deobfuscate(data: bytes) -> bytes:
    rev = _reverse_chunks(data)
    return bytes(b ^ ST_KEY[i % 32] for i, b in enumerate(rev))


def st_obfuscate(plain: bytes) -> bytes:
    xored = bytes(b ^ ST_KEY[i % 32] for i, b in enumerate(plain))
    return _reverse_chunks(xored)


def parse_st(data: bytes):
    try:
        plain = st_deobfuscate(data)
    except Exception:
        return None
    if len(plain) < 5 or plain[0:4] != MAGIC or plain[4] != 1:
        return None
    try:
        export = json.loads(plain[5:].decode("utf-8"))
    except Exception:
        return None
    if export.get("appSignature") != APP_SIGNATURE:
        return None
    return export


def _pbkdf2(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=100000)
    return kdf.derive(password.encode("utf-8"))


def decrypt_payload(enc: dict, key: bytes) -> str:
    iv = b64d(enc["iv"])
    ct = b64d(enc["data"])
    want_hmac = b64d(enc["hmac"])
    got_hmac = hmac_mod.new(key, iv + ct, hashlib.sha256).digest()
    if not hmac_mod.compare_digest(want_hmac, got_hmac):
        raise ValueError("HMAC verification failed - data may be tampered")
    return AESGCM(key).decrypt(iv, ct, None).decode("utf-8")


def decode_st_file(data: bytes, password: str | None = None) -> dict:
    """Full .st decode. Returns {export, payload, payload_raw, key_method}."""
    export = parse_st(data)
    if export is None:
        raise SentinelDecodeError(
            "DECODE_FAILED",
            "not a valid Sentinel Tunnel .st file "
            "(bad STCF magic, version or signature)")
    enc = export.get("configData") or {}
    if not enc.get("keySalt") or not enc.get("iv") or not enc.get("data"):
        raise SentinelDecodeError("DECODE_FAILED",
                                  ".st file is missing its configData")
    if export.get("isPasswordProtected") and password is None:
        raise SentinelDecodeError(
            "PASSWORD_REQUIRED",
            "This .st export is password-protected.")
    if password is not None:
        candidates = []
        for salt_b64 in (export.get("salt"), enc.get("keySalt")):
            if salt_b64:
                candidates.append(("pbkdf2(password, export/keySalt)",
                                   _pbkdf2(password, b64d(salt_b64))))
    else:
        candidates = [("sha256(ST_KEY||keySalt)",
                       hashlib.sha256(ST_KEY + b64d(enc["keySalt"])).digest())]
    last_err = None
    for name, key in candidates:
        try:
            payload = decrypt_payload(enc, key)
            return {"export": export, "payload": json.loads(payload),
                    "payload_raw": payload, "key_method": name}
        except Exception as ex:  # noqa: BLE001 - try next candidate
            last_err = ex
    raise SentinelDecodeError(
        "AUTH_FAILED" if password is not None else "DECODE_FAILED",
        "payload decryption failed (%s)" % (last_err,))


def run(data: bytes, password: str | None = None,
        hwid: str | None = None) -> str | None:
    """Engine/bot entry point: .st bytes -> decoded JSON string or None."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 8:
        return None
    if len(data) > MAX_BYTES:
        return None
    try:
        res = decode_st_file(bytes(data), password=password)
    except SentinelDecodeError as exc:
        if exc.code in ("PASSWORD_REQUIRED", "AUTH_FAILED"):
            raise
        return None
    except (ValueError, KeyError, TypeError):
        return None
    return json.dumps({"export": res["export"], "payload": res["payload"],
                       "key_method": res["key_method"]},
                      ensure_ascii=False, indent=2)


def _encode_for_selftest(export: dict, payload: dict,
                         password: str | None = None) -> bytes:
    """Build a .st file exactly like the app export (synthetic self-test)."""
    import os

    payload_json = json.dumps(payload, ensure_ascii=False,
                              separators=(",", ":"))
    if password is not None:
        salt1 = os.urandom(32)
        key = _pbkdf2(password, salt1)
        key_salt_b64 = b64e(salt1)
        # App bug reproduced faithfully: passwordHash uses a second random
        # salt that is discarded, so the app's own check can never verify
        # it. Kept so self-test files match the app's export structure.
        salt2 = os.urandom(32)
        pw_hash = b64e(_pbkdf2(password, salt2))
        export = dict(export)
        export["isPasswordProtected"] = True
        export["passwordHash"] = pw_hash
        export["salt"] = key_salt_b64
    else:
        salt1 = os.urandom(32)
        key = hashlib.sha256(ST_KEY + salt1).digest()
        key_salt_b64 = b64e(salt1)
        export = dict(export)
        export["isPasswordProtected"] = False
        export["passwordHash"] = None
        export["salt"] = None
    export.setdefault("version", 1)
    export.setdefault("appSignature", APP_SIGNATURE)
    export.setdefault("configType", "CUSTOM_SSH")
    export.setdefault("name", "Sentinel Tunnel config")
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, payload_json.encode("utf-8"), None)
    tag_hmac = hmac_mod.new(key, iv + ct, hashlib.sha256).digest()
    export["configData"] = {"iv": b64e(iv), "data": b64e(ct),
                            "hmac": b64e(tag_hmac), "keySalt": key_salt_b64}
    plain = MAGIC + bytes([1]) + json.dumps(
        export, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return st_obfuscate(plain)


_SAMPLE_PAYLOADS = {
    "CUSTOM_SSH": {"sshHost": "203.0.113.10", "sshPort": 22,
                   "username": "testuser", "password": "testpass",
                   "payload": "GET / HTTP/1.1[crlf]Host: example.com[crlf][crlf]",
                   "isLocked": False},
    "CUSTOM_SSL": {"sshHost": "203.0.113.11", "sshPort": 443,
                   "username": "ssluser", "password": "sslpass",
                   "sniHost": "sni.example.com", "isLocked": False},
    "CUSTOM_SSL_OVPN": {"remoteHost": "203.0.113.12", "remotePort": 1194,
                        "username": "ovpnuser", "password": "ovpnpass",
                        "ovpnContent": "client\ndev tun\nproto tcp\nremote 203.0.113.12 1194\n",
                        "isLocked": False},
    "CUSTOM_OPENVPN": {"remoteHost": "203.0.113.13", "remotePort": 1194,
                       "ovpnContent": "client\ndev tun\nproto udp\nremote 203.0.113.13 1194\n",
                       "isLocked": False},
    "CUSTOM_DNSTT": {"sshHost": "203.0.113.14", "sshPort": 22,
                     "username": "dnsuser", "password": "dnspass",
                     "dnsttDomain": "dnstt.example.com", "isLocked": False},
    "CUSTOM_HYSTERIA": {"serverHost": "203.0.113.15", "serverPort": "443",
                        "authPassword": "hy2pass", "sni": "hy.example.com",
                        "isLocked": False},
    "CUSTOM_XRAY": {"serverHost": "203.0.113.16", "serverPort": 443,
                    "protocol": "VLESS",
                    "uuid": "550e8400-e29b-41d4-a716-446655440000",
                    "network": "ws", "security": "tls",
                    "sni": "sni.example.com", "isLocked": False},
}


def selftest() -> int:
    ok = True
    for ctype in CONFIG_TYPES:
        for password in (None, "test-password-123"):
            export = {"configType": ctype, "name": "selftest-%s" % ctype,
                      "notes": "", "createdAt": 1764250000000,
                      "expiresAt": None}
            blob = _encode_for_selftest(export, _SAMPLE_PAYLOADS[ctype],
                                        password=password)
            res = decode_st_file(blob, password=password)
            same = res["payload"] == _SAMPLE_PAYLOADS[ctype]
            sig = res["export"]["configType"] == ctype
            print("%-16s pw=%-5s round-trip payload match: %s  type match: %s"
                  % (ctype, bool(password), same, sig))
            ok = ok and same and sig
            if password is None:
                bad = bytearray(blob)
                bad[len(bad) // 2] ^= 1
                try:
                    decode_st_file(bytes(bad))
                    print("  TAMPER NOT DETECTED!")
                    ok = False
                except (ValueError, SentinelDecodeError):
                    pass
    # Missing-password must ask, not silently fail.
    blob = _encode_for_selftest(
        {"configType": "CUSTOM_SSH", "name": "selftest-pw"},
        _SAMPLE_PAYLOADS["CUSTOM_SSH"], password="test-password-123")
    try:
        decode_st_file(blob)
        print("PASSWORD_REQUIRED NOT RAISED!")
        ok = False
    except SentinelDecodeError as exc:
        print("password-protected without password -> %s: %s"
              % (exc.code, ok and "OK" or "FAIL"))
        ok = ok and exc.code == "PASSWORD_REQUIRED"
    print("SELFTEST:", "ALL OK" if ok else "FAILURES")
    return 0 if ok else 1


def main() -> int:
    p = argparse.ArgumentParser(description="Sentinel Tunnel .st decoder")
    p.add_argument("file", nargs="?", help=".st file to decode")
    p.add_argument("--password", default=None,
                   help="password for protected .st files")
    p.add_argument("--selftest", action="store_true")
    args = p.parse_args()
    if args.selftest:
        return selftest()
    if not args.file:
        p.print_help()
        return 2
    try:
        with open(args.file, "rb") as stream:
            data = stream.read(MAX_BYTES + 1)
    except OSError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    password = args.password
    # Credentials arrive on stdin as JSON (engine contract) when a file
    # path is given; never read a tty.
    if password is None and not sys.stdin.isatty():
        raw_credentials = sys.stdin.buffer.read(8193)
        if raw_credentials:
            try:
                credentials = json.loads(raw_credentials)
            except ValueError:
                credentials = None
            if isinstance(credentials, dict):
                password = credentials.get("password")
    try:
        output = run(data, password=password)
    except SentinelDecodeError as exc:
        if exc.code in ("PASSWORD_REQUIRED", "AUTH_FAILED"):
            sys.stdout.write(json.dumps({"workerError": exc.code}))
            return 3
        return 1
    if output is None:
        print("Unable to decode configuration", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
