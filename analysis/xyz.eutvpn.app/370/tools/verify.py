#!/usr/bin/env python3
"""EUT VPN — synthetic round-trip verifier for this dossier.

Stdlib only (+ tools/crypto_pure.py in this directory). No network, no
secrets: every key below is a SYNTHETIC test key generated in this file.
It proves the implemented layers round-trip; it does NOT prove compatibility
with a real app file (that needs the operational script and a real sample).
Run: python3 tools/verify.py
"""
import base64
import hashlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto_pure import (  # noqa: E402
    aes_cbc_decrypt, aes_cbc_encrypt, aes_gcm_decrypt, aes_gcm_encrypt,
    threefish256_decrypt_block, threefish256_encrypt_block,
    xxtea_decrypt, xxtea_encrypt,
)

TEST_KEY = hashlib.sha256(b"TEST-ONLY-SYNTHETIC-KEY -- never a real key").digest()
TEST_KEY16 = TEST_KEY[:16]
TEST_IV = b"TEST-IV-16-BYTES"


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        raise SystemExit(1)
    return cond


SZA_KEY_STR = "TEST-ONLY-SYNTHETIC-KEY-STRING"
SZA_IV_STR = "TEST-ONLY-IV-16!"
PT = json.dumps({"qr_expiration": "1111-11-11 11:11:11",
                 "type": "custom_payload"}, ensure_ascii=False).encode("utf-8")


def _b64_default(raw):
    b64 = base64.b64encode(raw).decode()
    return "\n".join(b64[i:i + 76] for i in range(0, len(b64), 76))


def sza_encrypt(key_str, iv_str, pt):
    key = key_str[:16].encode("iso-8859-1")
    iv = iv_str.encode("iso-8859-1")[:16]
    ct = aes_cbc_encrypt(key, iv, pt)
    return _b64_default(ct) + ":" + _b64_default(iv)


def sza_decrypt(key_str, blob):
    ct_b64, iv_b64 = blob.split(":")
    ct = base64.b64decode("".join(ct_b64.split()))
    iv = base64.b64decode("".join(iv_b64.split()))
    key = key_str[:16].encode("iso-8859-1")
    return aes_cbc_decrypt(key, iv, ct)


def seal_payload_v1(obj, password=b"TEST-ONLY-SYNTHETIC-PASSWORD"):
    raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    salt = bytes(range(16))
    nonce = bytes(range(12))
    key = hashlib.pbkdf2_hmac("sha256", password, salt, 120000, 32)
    ct, tag = aes_gcm_encrypt(key, nonce, raw)
    blob = b"\x01" + salt + nonce + ct + tag
    return "eut-payload://" + base64.urlsafe_b64encode(blob).decode().rstrip("=")


def open_payload_v1(link, password=b"TEST-ONLY-SYNTHETIC-PASSWORD"):
    if not link.startswith("eut-payload://"):
        raise ValueError("not an eut-payload:// link")
    blob = base64.urlsafe_b64decode(link[len("eut-payload://"):] + "=" * (-len(link[len("eut-payload://"):]) % 4))
    if blob[0] != 0x01:
        raise ValueError("unsupported payload version: %d" % blob[0])
    salt, nonce = blob[1:17], blob[17:29]
    key = hashlib.pbkdf2_hmac("sha256", password, salt, 120000, 32)
    return json.loads(aes_gcm_decrypt(key, nonce, blob[29:-16], blob[-16:]).decode("utf-8"))


def main():
    blob = sza_encrypt(SZA_KEY_STR, SZA_IV_STR, PT)
    check("sza round-trip (AES-128-CBC, key=first 16 chars, Base64(ct):Base64(iv))",
          sza_decrypt(SZA_KEY_STR, blob) == PT)
    check("sza output uses Android Base64.DEFAULT 76-char wrap",
          "\n" in blob or len(blob.split(":")[0]) <= 76)
    obj = {"v": 1, "type": "custom_payload", "config": {"name": "TEST PAYLOAD"},
           "app_version_code": 370}
    link = seal_payload_v1(obj)
    check("eut-payload:// v1 round-trip (PBKDF2-HMAC-SHA256 120k + AES-256-GCM)",
          open_payload_v1(link) == obj)
    try:
        open_payload_v1(link.replace("eut-payload://", "eut-payload://A", 1))
        check("negative: tampered payload rejected", False)
    except Exception:
        check("negative: tampered payload rejected", True)
    try:
        open_payload_v1("eut-payload://" + base64.urlsafe_b64encode(b"\x02" + bytes(40)).decode())
        check("negative: wrong version byte rejected", False)
    except Exception:
        check("negative: wrong version byte rejected", True)
    print("VERIFY OK")


if __name__ == "__main__":
    main()
