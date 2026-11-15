#!/usr/bin/env python3
"""XUI Tunnel VPN 6.0 (com.xui_tunnel): decodificador de archivos .xui.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
See README.md here.

Method (verified against this APK, versionCode 6, versionName 6.0;
the SP-DECODE repo already covers .xui as a file format --
decoders/Python/xui.py + _noobcrypt.py -- and this script adds the
app-name prefix check and the field list the app actually applies):

  A .xui file is one line of standard Base64. Base64-decode it:
  IV = first 16 bytes, ciphertext = the rest.
  Plaintext = AES-256-CBC decrypt, key KEY_FIELD, PKCS#7 padding
  (NoobCrypt.b(content, 1, false)).
  The plaintext must start with the app name "XUI Tunnel VPN"
  (XUITunnelMain.H checks strI.startsWith(getString(R.string.app_name))
  and shows "Invalid config: does not belong to this app" otherwise);
  the JSON object follows the app name immediately, with no separator:
      "XUI Tunnel VPN" + {"ExpireDate": ..., "RootBlock": ..., ...}
  Fields the app applies (XUITunnelMain.H / G):
  ExpireDate (ms epoch, 0 = no expiry), RootBlock (bool: reject on a
  rooted device), DeviceID (string, ";"-separated device ids),
  MobileData (bool, default true), PSInstall (bool: require install
  from Google Play), isMsg (bool), CFGMessage (string), NoobDev (int),
  SNIHost, Payload, ProxyHost, ProxyPort, useOvpnServer (bool),
  useSshServer (bool, default true), serverDnsMode (int), TlSVersion
  (int), DNSHost, UDPhost, UDPobfs, UDPauth, UDPDownMbps, UDPUpMbps,
  isPassON (bool: ask for a config password before applying).

Key (public app-wide format constant, recovered from libovpn3.so;
NOT an account credential):
  KEY_FIELD (32 bytes, NoobCrypt index 1): the plain XOR of two
      .rodata chunks, verified byte-for-byte against the repo's
      decoders/Python/_noobcrypt.py KEYS["xui"]:
      file[0x21e240:0x21e250] ^ file[0x1c2b80:0x1c2b90] ||
      file[0x21e250:0x21e260] ^ file[0x1c2860:0x1c2870]
      -> 721d60cba2999a7e0f90e848d1ea31b7d06aa6be3654821fc4a5b388e70fc51c

How the app gets a .xui file: ImportActivity, ACTION_VIEW intent,
schemes content/file, mimeType */*, pathPattern .*\\.xui (the app
declares NO custom URI scheme). The file is read line by line and
the lines are concatenated without newlines (XUITunnelMain.T).

Status: the CBC method and the app-name prefix are verified from the
APK (decompiled Java + native NoobCrypt) and from a round-trip test
vector below, but NO real exported .xui file has been tested yet --
this decoder is marked UNVERIFIED against a real file. If you have a
real .xui, run:  python3 XUI_Tunnel_archivos.py --file file.xui
"""
from __future__ import annotations

import argparse
import base64
import json
import math
import struct
import sys

MAX_BYTES = 5 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
APP_NAME = "XUI Tunnel VPN"

KEY_FIELD = bytes.fromhex(
    "721d60cba2999a7e0f90e848d1ea31b7d06aa6be3654821fc4a5b388e70fc51c")

# Test vector: a real .xui file built with the verified CBC method
# (IV 00..0f, fixed for reproducibility), plaintext
# "XUI Tunnel VPN" + a profile JSON. Decrypts to ExpireDate
# 1798761600000, CFGMessage "Test config", SNIHost "example.com".
# Cross-checked with PyCryptodome at build time.
TEST_VECTOR = (
    "AAECAwQFBgcICQoLDA0ODwhYcgNHZSC6PHk7dkTnnHTD+IPfyWSQhx6rw+ar2cxXA2DuDLmbuaEWwFgMxKkmxDeEepSFFiMew2wrHlWXOaa+r7BGIuI4GAfYS/FGrqQS6k0NhCNi8tGK0BNcaY0LC9zvl9YodwLJaO363wsztWiRDcqNovi+NdpSKurKDW61hWpASTVkglTnc2jLKpRgx9gILYFFl3bYt2cwQQSpOAnLTfCu2MjcaT7yKBBftvNTuLZtI75eF/1SMEkrhabxXTr5GQVxKTA9mM6f7O3dZvrsaw8kVHKHvWTtfs5GnLbRzZoI39Ugmg3NBhCZu+X8Gp+yHhM5nNjfHit8OSiZh5qALRr+DuuarKpL/ZYB0cYWM0kHkNPsvh79FwGA+SjYbRG1X7Sg4DdA6w9WbauPg/Qo4kRbT4FD+CONiFyfz71NrIARYGEM40A94aH8R4+9h2TA2WXzXDy5VW/0iBBEiMLtD/IBSbXJ06HBGF/gKhQqx+FHUkh7cgOMJllpUgG89xheocfKecgcgyhfFrP1GSQuXVpbDUVSUR3P0AdJwEwUFSKI2IT1WjyxRbdftACCQZmT9P3mFl1zK0IjApEe0rks3Y98ht2RQzIuLDLl7CiR"
)


class DecodeError(ValueError):
    """Error de descifrado con un código estable para SP-DECODE."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------- AES-256 puro
# Núcleo AES (solo descifrado) en Python puro con T-tables, verificado
# contra PyCryptodome (vector FIPS-197 y 200 vectores aleatorios).
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
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _xtime(x):
    return ((x << 1) ^ (0x1b if x & 0x80 else 0)) & 0xff


def _mul(x, n):
    r = 0
    while n:
        if n & 1:
            r ^= x
        x = _xtime(x)
        n >>= 1
    return r


def _make_tables():
    Td0, Td1, Td2, Td3 = [], [], [], []
    for i in range(256):
        isb = _INV_SBOX[i]
        m9, m11, m13, m14 = _mul(isb, 9), _mul(isb, 11), _mul(isb, 13), _mul(isb, 14)
        Td0.append((m14 << 24) | (m9 << 16) | (m13 << 8) | m11)
        Td1.append((m11 << 24) | (m14 << 16) | (m9 << 8) | m13)
        Td2.append((m13 << 24) | (m11 << 16) | (m14 << 8) | m9)
        Td3.append((m9 << 24) | (m13 << 16) | (m11 << 8) | m14)
    return (Td0, Td1, Td2, Td3)


_Td0, _Td1, _Td2, _Td3 = _make_tables()


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
    return tuple(w)


def _inv_mix_columns_word(w):
    a0, a1, a2, a3 = (w >> 24) & 0xff, (w >> 16) & 0xff, (w >> 8) & 0xff, w & 0xff
    return ((_mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9)) << 24
            | (_mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13)) << 16
            | (_mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11)) << 8
            | (_mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14)))


_DKW_CACHE = {}


def _aes_decrypt_block(kw, block):
    # Claves de ronda 1..13 transformadas por InvMixColumns (cifrado
    # inverso equivalente); las rondas 0 y 14 se usan tal cual.
    dkw = _DKW_CACHE.get(kw)
    if dkw is None:
        dkw = tuple(kw[:4]) + tuple(_inv_mix_columns_word(w) for w in kw[4:56]) + tuple(kw[56:60])
        _DKW_CACHE[kw] = dkw
    s0, s1, s2, s3 = struct.unpack(">4I", block)
    s0 ^= kw[56]; s1 ^= kw[57]; s2 ^= kw[58]; s3 ^= kw[59]
    for rnd in range(13, 0, -1):
        k = dkw[4 * rnd:4 * rnd + 4]
        s0, s1, s2, s3 = (
            _Td0[s0 >> 24] ^ _Td1[(s3 >> 16) & 0xff] ^ _Td2[(s2 >> 8) & 0xff] ^ _Td3[s1 & 0xff] ^ k[0],
            _Td0[s1 >> 24] ^ _Td1[(s0 >> 16) & 0xff] ^ _Td2[(s3 >> 8) & 0xff] ^ _Td3[s2 & 0xff] ^ k[1],
            _Td0[s2 >> 24] ^ _Td1[(s1 >> 16) & 0xff] ^ _Td2[(s0 >> 8) & 0xff] ^ _Td3[s3 & 0xff] ^ k[2],
            _Td0[s3 >> 24] ^ _Td1[(s2 >> 16) & 0xff] ^ _Td2[(s1 >> 8) & 0xff] ^ _Td3[s0 & 0xff] ^ k[3])
    k = kw[0:4]
    s0, s1, s2, s3 = (
        (((_INV_SBOX[s0 >> 24] << 24) | (_INV_SBOX[(s3 >> 16) & 0xff] << 16) | (_INV_SBOX[(s2 >> 8) & 0xff] << 8) | _INV_SBOX[s1 & 0xff]) ^ k[0]),
        (((_INV_SBOX[s1 >> 24] << 24) | (_INV_SBOX[(s0 >> 16) & 0xff] << 16) | (_INV_SBOX[(s3 >> 8) & 0xff] << 8) | _INV_SBOX[s2 & 0xff]) ^ k[1]),
        (((_INV_SBOX[s2 >> 24] << 24) | (_INV_SBOX[(s1 >> 16) & 0xff] << 16) | (_INV_SBOX[(s0 >> 8) & 0xff] << 8) | _INV_SBOX[s3 & 0xff]) ^ k[2]),
        (((_INV_SBOX[s3 >> 24] << 24) | (_INV_SBOX[(s2 >> 16) & 0xff] << 16) | (_INV_SBOX[(s1 >> 8) & 0xff] << 8) | _INV_SBOX[s0 & 0xff]) ^ k[3]))
    return struct.pack(">4I", s0, s1, s2, s3)


def _unpad_pkcs7(data):
    if not data:
        raise ValueError("plaintext vacío")
    padding = data[-1]
    if padding < 1 or padding > 16 or data[-padding:] != bytes([padding]) * padding:
        raise ValueError("padding PKCS#7 inválido")
    return data[:-padding]


def _aes_cbc_decrypt(key, iv, ciphertext):
    """AES-256-CBC decrypt (NoobCrypt index 1), solo stdlib."""
    if len(iv) != 16 or len(ciphertext) % 16:
        raise ValueError("CBC con IV o longitud inválidos")
    kw = _aes_key_expand(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), 16):
        blk = ciphertext[i:i + 16]
        d = _aes_decrypt_block(kw, blk)
        out += bytes(a ^ b for a, b in zip(d, prev))
        prev = blk
    return _unpad_pkcs7(bytes(out))


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


def decode(data) -> dict:
    """API offline: descifra un archivo .xui y devuelve el dict del perfil."""
    text = _text(data)
    if len(text) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el tamaño máximo.")
    encoded = "".join(text.split())
    if not encoded:
        raise DecodeError("DECRYPT_FAILED", "El archivo está vacío.")
    encoded += "=" * ((4 - len(encoded) % 4) % 4)
    try:
        raw = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise DecodeError("DECRYPT_FAILED", "El archivo no es Base64 válido.") from exc
    if len(raw) < 32 or (len(raw) - 16) % 16:
        raise DecodeError("DECRYPT_FAILED", "El archivo tiene una longitud inválida.")
    try:
        plain = _aes_cbc_decrypt(KEY_FIELD, raw[:16], raw[16:])
    except ValueError as exc:
        raise DecodeError("DECRYPT_FAILED", "No se pudo descifrar el archivo (CBC).") from exc
    try:
        text_plain = plain.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError("DECRYPT_FAILED", "El texto descifrado no es UTF-8.") from exc
    if not text_plain.startswith(APP_NAME):
        raise DecodeError("WRONG_DOCUMENT",
                          "El archivo no pertenece a esta app (no empieza por %r)." % APP_NAME)
    return _json(text_plain[len(APP_NAME):].encode("utf-8"))


def run(file_bytes) -> str | None:
    """API offline: JSON del perfil o None; nunca un dict parcial."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


# ------------------------------------------------------------- CLI
def _self_test():
    """Vector real: un .xui construido con el método CBC verificado."""
    doc = decode(TEST_VECTOR)
    assert doc["ExpireDate"] == 1798761600000, doc.get("ExpireDate")
    assert doc["CFGMessage"] == "Test config", doc.get("CFGMessage")
    assert doc["SNIHost"] == "example.com", doc.get("SNIHost")
    assert doc["ProxyPort"] == "8080", doc.get("ProxyPort")
    assert doc["isPassON"] is False, doc.get("isPassON")
    return ("self-test OK: .xui de prueba descifrado "
            "(ExpireDate %d, CFGMessage %r, SNIHost %r)"
            % (doc["ExpireDate"], doc["CFGMessage"], doc["SNIHost"]))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Decodificador de archivos .xui de XUI Tunnel VPN (com.xui_tunnel).")
    parser.add_argument("--file", default=None,
                        help="Lee el archivo .xui (Base64, una línea).")
    parser.add_argument("--self-test", action="store_true",
                        help="Verifica el descifrado con un .xui de prueba real.")
    parser.add_argument("-o", "--output", default=None,
                        help="Guarda el JSON descifrado en este archivo.")
    args = parser.parse_args(argv)

    if args.self_test:
        print(_self_test())
        return 0
    try:
        if args.file:
            with open(args.file, "rb") as fh:
                raw = fh.read()
        else:
            parser.error("usa --file o --self-test")
            return 2
        out = json.dumps(decode(raw), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError as exc:
        print("error [%s]: %s" % (exc.code, exc), file=sys.stderr)
        return 1
    except Exception as exc:
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
