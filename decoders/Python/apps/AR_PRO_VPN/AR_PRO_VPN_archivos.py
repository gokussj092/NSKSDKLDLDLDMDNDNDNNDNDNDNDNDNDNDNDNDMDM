#!/usr/bin/env python3
"""AR PRO VPN 1.0 (noob.arpro.vpn): .ar profile files.

Standalone Python 3.10+, standard library only, no network access.
For catalogs use AR_PRO_VPN.py. See README.md in this directory.

Method (verified against this APK, versionCode 1, versionName 1.0;
import path ARTunnelMain.P(), export path ExportActivity.r()):
  file content = Base64(AES/CBC/PKCS7Padding(UTF-8 JSON, key =
  SHA-256(master key), IV = 16 zero bytes))
  master key = AbstractC0858Qk.i(): AES/CBC/PKCS7Padding decrypt of the
  hardcoded Base64 ciphertext "lQ+t8x63PO1wN4B7vFjgfA==" with key
  SHA-256("C3sNbUKg92mKwhxQObxKpA==") and IV 16 zero bytes.
The profile JSON has 28 fields (PSInstall, DeviceID, RootBlock,
MobileData, ExpireDate, isMsg, CFGMessage, isPassON, MyPass, Payload,
WSPayload, SNIHost, BUGHost, DNSHost, ProxySet, UDPhost, UDPobfs,
UDPauth, V2Ejson, v2Esni, isUri, isEreverse, EwgConf, TunnelType,
isWSProxy, isWS, Server, NoobDev).

STATUS: method verified against the app's own code (P() decrypt and R()
encrypt are exact inverses; the master-key derivation was computed and
gives a sensible key; a synthetic round-trip encrypt -> decrypt passes
with --self-test). PENDING end-to-end confirmation with a real .ar file
exported by the app: no .ar sample exists in the APK assets.
No .sks support (excluded by request).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import math
from pathlib import Path
import re
import sys

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
# Master-key derivation constants from AbstractC0858Qk.i() (format
# constants baked into the app, not user passwords).
_MASTER_KEY_B64 = "C3sNbUKg92mKwhxQObxKpA=="
_MASTER_CIPHER_B64 = "lQ+t8x63PO1wN4B7vFjgfA=="
ZERO_IV = bytes(16)
PROFILE_FIELDS = (
    "PSInstall", "DeviceID", "RootBlock", "MobileData", "ExpireDate",
    "isMsg", "CFGMessage", "isPassON", "MyPass", "Payload", "WSPayload",
    "SNIHost", "BUGHost", "DNSHost", "ProxySet", "UDPhost", "UDPobfs",
    "UDPauth", "V2Ejson", "v2Esni", "isUri", "isEreverse", "EwgConf",
    "TunnelType", "isWSProxy", "isWS", "Server", "NoobDev",
)


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- AES (pure python, stdlib only)

_SBOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
)
_INV_SBOX = (
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d,
)
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)


def _xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff


def _mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _key_expansion(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = [_SBOX[t[1]] ^ _RCON[i // nk - 1], _SBOX[t[2]],
                 _SBOX[t[3]], _SBOX[t[0]]]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w, nr


def _add_rk(s, w, rnd):
    for c in range(4):
        for r in range(4):
            s[4 * c + r] ^= w[4 * rnd + c][r]


def _sub(s, inv=False):
    box = _INV_SBOX if inv else _SBOX
    for i in range(16):
        s[i] = box[s[i]]


def _shift(s, inv=False):
    for r in range(1, 4):
        row = [s[4 * c + r] for c in range(4)]
        sh = (4 - r) if inv else r
        row = row[sh:] + row[:sh]
        for c in range(4):
            s[4 * c + r] = row[c]


def _mix(s, inv=False):
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        if inv:
            s[4 * c + 0] = _mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9)
            s[4 * c + 1] = _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13)
            s[4 * c + 2] = _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11)
            s[4 * c + 3] = _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)
        else:
            s[4 * c + 0] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
            s[4 * c + 1] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
            s[4 * c + 2] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
            s[4 * c + 3] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)


def _aes_encrypt_block(key, block):
    w, nr = _key_expansion(key)
    s = list(block)
    _add_rk(s, w, 0)
    for rnd in range(1, nr):
        _sub(s)
        _shift(s)
        _mix(s)
        _add_rk(s, w, rnd)
    _sub(s)
    _shift(s)
    _add_rk(s, w, nr)
    return bytes(s)


def _aes_decrypt_block(key, block):
    w, nr = _key_expansion(key)
    s = list(block)
    _add_rk(s, w, nr)
    for rnd in range(nr - 1, 0, -1):
        _sub(s, True)
        _shift(s, True)
        _add_rk(s, w, rnd)
        _mix(s, True)
    _sub(s, True)
    _shift(s, True)
    _add_rk(s, w, 0)
    return bytes(s)


def _aes_cbc(key, iv, data, decrypt=True):
    if len(data) % 16:
        raise ValueError("ciphertext length must be a multiple of 16")
    block_fn = _aes_decrypt_block if decrypt else _aes_encrypt_block
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        if decrypt:
            dec = block_fn(key, blk)
            out += bytes(a ^ b for a, b in zip(dec, prev))
            prev = blk
        else:
            enc = block_fn(key, bytes(a ^ b for a, b in zip(blk, prev)))
            out += enc
            prev = enc
    return bytes(out)


def _pkcs7_pad(data):
    pad = 16 - len(data) % 16
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data):
    if not data:
        raise ValueError("empty data")
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad PKCS#7 padding")
    return data[:-pad]


# ---------------------------------------------------------------- helpers

def _sha256(data):
    import hashlib
    return hashlib.sha256(data).digest()


def _text(data):
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "Se esperaba texto o bytes UTF-8.")
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    try:
        value = data.decode("utf-8-sig") if isinstance(data, bytes) else data.removeprefix("\ufeff")
        if len(value.encode("utf-8")) > MAX_BYTES:
            raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    except UnicodeError as exc:
        raise DecodeError("FORMAT_ERROR", "La entrada no es UTF-8 válido.") from exc
    return value.strip()


def _base64(text):
    compact = re.sub(r"[ \t\r\n]", "", text)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) or len(compact) % 4 == 1:
        raise DecodeError("FORMAT_ERROR", "Se esperaba Base64 estándar del archivo .ar.")
    try:
        return base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR", "Base64 inválido.") from exc


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
        raise DecodeError("WRONG_DOCUMENT", "El perfil debe contener un objeto JSON.")
    return _validate(doc)


# ---------------------------------------------------------------- .ar

def master_key():
    """AbstractC0858Qk.i(): decrypt the hardcoded ciphertext -> master key."""
    try:
        raw = base64.b64decode(_MASTER_CIPHER_B64)
        plain = _pkcs7_unpad(_aes_cbc(_sha256(_MASTER_KEY_B64.encode()), ZERO_IV, raw))
        return plain.decode("utf-8")
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise DecodeError("DECRYPT_FAILED", "No se pudo derivar la clave maestra .ar.") from exc


def encrypt_profile(doc):
    """ExportActivity.r(): JSON -> AES/CBC -> Base64 (used by --self-test)."""
    key = _sha256(master_key().encode())
    data = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(_aes_cbc(key, ZERO_IV, _pkcs7_pad(data), decrypt=False)).decode("ascii")


def decrypt_profile_bytes(data):
    """ARTunnelMain.P(): Base64 -> AES/CBC -> JSON bytes."""
    key = _sha256(master_key().encode())
    raw = _base64(_text(data))
    if not raw or len(raw) % 16:
        raise DecodeError("TRUNCATED", "El archivo .ar no contiene bloques AES completos.")
    try:
        return _pkcs7_unpad(_aes_cbc(key, ZERO_IV, raw))
    except ValueError as exc:
        raise DecodeError("DECRYPT_FAILED", "El archivo .ar no descifra con la clave de AR PRO VPN 1.0.") from exc


def protections(doc):
    """Protection flags the app checks after decrypting (P())."""
    return {
        "password": bool(doc.get("isPassON")),
        "root_block": bool(doc.get("RootBlock")),
        "device_id": bool(doc.get("DeviceID")),
        "expiry": doc.get("ExpireDate"),
        "play_store_check": bool(doc.get("PSInstall")),
    }


def decode(data):
    """Offline API: decrypt a .ar file and return its profile dict."""
    doc = _json(decrypt_profile_bytes(data))
    doc["_protections"] = protections(doc)
    return doc


def run(file_bytes):
    """Offline API: profile JSON or None; never a partial profile."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


def _read(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def _self_test():
    """Round-trip: encrypt a sample profile with R(), decrypt with decode()."""
    sample = {
        "PSInstall": True, "DeviceID": "test-device", "RootBlock": False,
        "MobileData": True, "ExpireDate": 0, "isMsg": False,
        "CFGMessage": "", "isPassON": True, "MyPass": "test",
        "Payload": "CONNECT [host_port] [protocol][crlf][crlf][crlf]",
        "WSPayload": "", "SNIHost": "example.com", "BUGHost": "",
        "DNSHost": "1.1.1.1", "ProxySet": False, "UDPhost": "",
        "UDPobfs": "", "UDPauth": "", "V2Ejson": "", "v2Esni": "",
        "isUri": False, "isEreverse": False, "EwgConf": "",
        "TunnelType": "SSH", "isWSProxy": False, "isWS": False,
        "Server": "Auto Select Server", "NoobDev": 1,
    }
    encoded = encrypt_profile(sample)
    decoded = decode(encoded)
    decoded.pop("_protections", None)
    if decoded != sample:
        raise DecodeError("SELF_TEST", "El round-trip .ar no reproduce el perfil.")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path, help="Archivo .ar de AR PRO VPN")
    parser.add_argument("--self-test", action="store_true", help="Round-trip sintético (sin archivo real)")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON; por defecto stdout")
    args = parser.parse_args(argv)
    if args.self_test:
        try:
            _self_test()
        except DecodeError as exc:
            print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
            return 1
        print(json.dumps({"self_test": "OK", "fields": len(PROFILE_FIELDS)}, ensure_ascii=False))
        return 0
    if args.file is None:
        parser.error("se necesita un archivo .ar o --self-test")
    try:
        result = decode(_read(args.file))
        rendered = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
