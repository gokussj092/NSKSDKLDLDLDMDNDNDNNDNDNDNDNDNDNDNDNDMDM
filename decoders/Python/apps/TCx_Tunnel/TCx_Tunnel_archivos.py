#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TCx Tunnel Plus (org.tcx.tunnel.plus) 1.0.15 / build 115 — file decoder
for SP-DECODE.

File format: ``.tcx``
----------------------
A ``.tcx`` file is a TEXT file whose whole content is::

    tcxtunnelplus://<mode-0 cipher>

where the mode-0 cipher is Base64( XXTEA( AES-128-CBC( profile JSON ) ) )
with the same key/seed as the catalog (see TCx_Tunnel.py: seed = the APK
signing certificate SHA-256 fingerprint, lowercase hex; AES key =
SHA-256(seed)[:16], IV = 16 zero bytes, PKCS#7; XXTEA delta 0x9E3779B9).

Import path in the app (TCxTunnelPlusMain): the file intent filter is
``file`` scheme pathPattern ``.*\\.tcx`` + ``content`` scheme.  On open
the app checks the name ends with ``.tcx``, shows a confirmation dialog,
reads the file, requires it to start with ``tcxtunnelplus://`` (else
"Invalid configuration format"), strips the prefix, decrypts with
RenzUtils.decrypt, parses the JSON, handles ``isSetExpiry`` / ``Expiry``
/ PIN (NetworkPinCode dialog) and saves the profile into
``custom_payload.json`` in filesDir — NOTE: that file is written via
RenzUtils.encrypt, i.e. the on-disk ``custom_payload.json`` holds the
ENCRYPTED form (a bare mode-0 cipher, no ``tcxtunnelplus://`` prefix)
of a JSON ARRAY of profiles.

Text scheme: ``tcxtunnelplus://`` — paste import (the app shows
"Error! format must start tcxtunnelplus://").  There is NO
intent-filter for the scheme in the manifest, so it is import-by-paste
only, not by opening a link from another app.

What this script does
---------------------
* ``--file file.tcx`` — decrypt a .tcx file and print the profile JSON.
* ``--text 'tcxtunnelplus://...'`` — decrypt a pasted link/text.
* ``--file custom_payload.json`` — decrypt the app's on-disk
  custom_payload.json (bare mode-0 cipher of a JSON array).
* ``--self-test`` — round-trip test: build a synthetic .tcx with the
  (validated) encrypt pipeline, decrypt it back, compare.

The profile JSON is printed as-is (pretty-printed).  Known top-level
fields the app reads: ``isSetExpiry`` (bool), ``Expiry`` (date/string),
``PIN`` / ``NetworkPinCode`` (string).  The VPN profile itself follows
the RENZ family shape (servers / networks / payload / SNI); because no
real exported .tcx exists yet, the exact field names of a real profile
are NOT asserted here — the decrypted JSON is shown verbatim.

No real .tcx sample exists yet (pending: a real file exported by the
app, or a real tcxtunnelplus:// link).  The synthetic sample in
``sample.tcx`` was produced with the encrypt pipeline that the native
``renz_decrypt`` (libovpn3.so, Unicorn) opens byte-for-byte — see
README.md.

Pure Python standard library only (imports the decrypt primitives
from TCx_Tunnel.py, which must sit next to this file).
"""

import argparse
import base64
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from TCx_Tunnel import (AES_IV, AES_KEY, XXTEA_DELTA, _SBOX, _aes_key_expand,
                        _b64_clean, _gf_mul, _prepare_xxtea_key,
                        _xxtea_decrypt, _aes128_cbc_decrypt, decode as _catalog_decode)

SCHEME = "tcxtunnelplus://"
_M32 = 0xFFFFFFFF


# ------------------------------------------------------- encrypt (for tests)
# Pure-Python AES-128-CBC encrypt + XXTEA encrypt, mirroring the native
# RenzUtils.encrypt.  Validated: the native renz_decrypt (Unicorn) opens
# bodies produced by these functions, and the AES encrypt matches
# PyCryptodome byte-for-byte (see README.md).

def _aes_encrypt_block(rk, block):
    s = bytearray(block)
    for c in range(4):
        for r in range(4):
            s[4 * c + r] ^= (rk[c] >> (24 - 8 * r)) & 0xFF
    for rnd in range(1, 10):
        # SubBytes + ShiftRows
        t = bytearray(16)
        for r in range(4):
            for c in range(4):
                t[4 * c + r] = _SBOX[s[4 * ((c + r) % 4) + r]]
        s = t
        # MixColumns
        t = bytearray(16)
        for c in range(4):
            a0, a1, a2, a3 = s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]
            t[4 * c] = _gf_mul(a0, 2) ^ _gf_mul(a1, 3) ^ a2 ^ a3
            t[4 * c + 1] = a0 ^ _gf_mul(a1, 2) ^ _gf_mul(a2, 3) ^ a3
            t[4 * c + 2] = a0 ^ a1 ^ _gf_mul(a2, 2) ^ _gf_mul(a3, 3)
            t[4 * c + 3] = _gf_mul(a0, 3) ^ a1 ^ a2 ^ _gf_mul(a3, 2)
        s = t
        # AddRoundKey
        for c in range(4):
            for r in range(4):
                s[4 * c + r] ^= (rk[4 * rnd + c] >> (24 - 8 * r)) & 0xFF
    # final round: SubBytes + ShiftRows + AddRoundKey
    t = bytearray(16)
    for r in range(4):
        for c in range(4):
            t[4 * c + r] = _SBOX[s[4 * ((c + r) % 4) + r]]
    s = t
    for c in range(4):
        for r in range(4):
            s[4 * c + r] ^= (rk[40 + c] >> (24 - 8 * r)) & 0xFF
    return bytes(s)


def aes128_cbc_encrypt(data, key=AES_KEY, iv=AES_IV):
    pad = 16 - (len(data) % 16)
    data = data + bytes([pad]) * pad
    rk = _aes_key_expand(key)
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[off:off + 16], prev))
        enc = _aes_encrypt_block(rk, block)
        out.extend(enc)
        prev = enc
    return bytes(out)


def xxtea_encrypt(data, key16=AES_KEY):
    k = _prepare_xxtea_key(key16)
    n = (len(data) + 3) // 4
    v = list(struct.unpack("<%dI" % n, data + b"\x00" * (n * 4 - len(data))))
    v.append(len(data))
    n = len(v)
    if n > 1:
        rounds = 6 + 52 // n
        total = 0
        z = v[n - 1]
        for _ in range(rounds):
            total = (total + XXTEA_DELTA) & _M32
            e = (total >> 2) & 3
            for p in range(n - 1):
                y = v[p + 1]
                mx = ((((z >> 5) ^ ((y << 2) & _M32)) + ((y >> 3) ^ ((z << 4) & _M32)))
                      ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z))) & _M32
                v[p] = (v[p] + mx) & _M32
                z = v[p]
            y = v[0]
            mx = ((((z >> 5) ^ ((y << 2) & _M32)) + ((y >> 3) ^ ((z << 4) & _M32)))
                  ^ ((total ^ y) + (k[((n - 1) & 3) ^ e] ^ z))) & _M32
            v[n - 1] = (v[n - 1] + mx) & _M32
            z = v[n - 1]
    return struct.pack("<%dI" % n, *v)


def encrypt_profile(profile_json):
    """profile_json (bytes/str/dict) -> 'tcxtunnelplus://<b64>' text."""
    if isinstance(profile_json, dict):
        raw = json.dumps(profile_json, ensure_ascii=False).encode("utf-8")
    elif isinstance(profile_json, str):
        raw = profile_json.encode("utf-8")
    else:
        raw = profile_json
    aes_ct = aes128_cbc_encrypt(raw)
    xx = xxtea_encrypt(aes_ct)
    return SCHEME + base64.b64encode(xx).decode("ascii")


# -------------------------------------------------------------- decrypt

def decrypt_body(b64_text):
    """Decrypt a bare mode-0 cipher (Base64 text) -> profile JSON (dict/list).
    Raises ValueError on undecryptable input."""
    raw = base64.b64decode(_b64_clean(b64_text), validate=False)
    xxtea_plain, _ = _xxtea_decrypt(raw)
    if not xxtea_plain:
        raise ValueError("XXTEA layer failed (bad key or bad body)")
    plain = _aes128_cbc_decrypt(xxtea_plain)
    if not plain:
        raise ValueError("AES layer failed (bad key/padding or bad body)")
    try:
        return json.loads(plain.decode("utf-8"))
    except Exception as exc:
        raise ValueError("decrypted body is not JSON: %s" % exc)


def decrypt_text(text):
    """Decrypt a 'tcxtunnelplus://...' text (or a bare cipher) -> JSON."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "ignore")
    text = text.strip()
    if text.startswith(SCHEME):
        text = text[len(SCHEME):]
    if text.startswith("{") or text.startswith("["):
        # Already-decrypted JSON (e.g. a plain profile).
        return json.loads(text)
    return decrypt_body(text)


def decrypt_file(path):
    """Decrypt a .tcx file or a custom_payload.json (bare cipher)."""
    with open(path, "rb") as fh:
        content = fh.read()
    return decrypt_text(content)


def _summarize(profile):
    """One-line summary of a decrypted profile for the console."""
    if isinstance(profile, list):
        return "%d profile(s) in array" % len(profile)
    if not isinstance(profile, dict):
        return repr(profile)[:120]
    bits = []
    for key in ("Name", "name", "ServerIPHost", "Server", "host", "Protocol",
                "protocol", "Username", "user", "Expiry", "isSetExpiry", "PIN"):
        if key in profile and profile[key] not in ("", None):
            bits.append("%s=%s" % (key, profile[key]))
    return "; ".join(bits) if bits else "(JSON object, %d keys)" % len(profile)


# ------------------------------------------------------------- self-test

_SELFTEST_PROFILE = {
    "Name": "TCx Test Server",
    "ServerIPHost": "203.0.113.10",
    "Protocol": "SSH",
    "Username": "testuser",
    "Password": "testpass",
    "isSetExpiry": False,
    "Expiry": "",
    "PIN": "",
    "Notes": "self-test",
}


def _self_test():
    # 1) Round-trip: encrypt a synthetic profile, decrypt it back.
    text = encrypt_profile(_SELFTEST_PROFILE)
    assert text.startswith(SCHEME), text[:40]
    back = decrypt_text(text)
    assert back == _SELFTEST_PROFILE, back
    # 2) The same body opens through the catalog decoder's field path
    #    (the cipher is identical to the catalog's mode 0).
    b64 = text[len(SCHEME):]
    assert decrypt_body(b64) == _SELFTEST_PROFILE
    # 3) custom_payload.json form: bare cipher of a JSON array.
    array_raw = json.dumps([_SELFTEST_PROFILE], ensure_ascii=False).encode("utf-8")
    array_b64 = base64.b64encode(xxtea_encrypt(aes128_cbc_encrypt(array_raw))).decode()
    assert decrypt_body(array_b64) == [_SELFTEST_PROFILE]
    print("self-test OK: .tcx round-trip + tcxtunnelplus:// + custom_payload.json form")
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="TCx Tunnel Plus (.tcx / tcxtunnelplus://) file decoder")
    ap.add_argument("--file", help=".tcx file or custom_payload.json to decrypt")
    ap.add_argument("--text", help="tcxtunnelplus://... text (or bare cipher) to decrypt")
    ap.add_argument("--self-test", action="store_true",
                    help="run the built-in round-trip tests")
    ap.add_argument("--json", action="store_true",
                    help="print the decrypted profile as JSON")
    ap.add_argument("--out", help="write the decrypted JSON to this file")
    args = ap.parse_args(argv)

    if args.self_test:
        _self_test()
        return 0

    if args.file:
        profile = decrypt_file(args.file)
        src = args.file
    elif args.text:
        profile = decrypt_text(args.text)
        src = "(text)"
    else:
        ap.error("give --file or --text (or --self-test)")
        return 2

    print("TCx Tunnel Plus — %s" % src)
    print("Perfil: %s" % _summarize(profile))
    if isinstance(profile, dict):
        for key in ("isSetExpiry", "Expiry", "PIN"):
            if key in profile:
                print("  %s: %s" % (key, profile[key]))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(profile, fh, indent=1, ensure_ascii=False)
        print("Guardado en %s" % args.out)
    if args.json or not args.out:
        print(json.dumps(profile, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
