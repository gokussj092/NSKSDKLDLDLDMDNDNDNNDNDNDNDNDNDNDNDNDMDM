#!/usr/bin/env python3
"""Decodificador de enlaces nad://sec2: y nad://pw2: (NadiaVPN 1.4.6).

Uso:
    python3 nadiavpn-text.py 'nad://sec2:<base64>'
    python3 nadiavpn-text.py < sample-nad-sec2.txt
    python3 nadiavpn-text.py --password 'clave' 'nad://pw2:<base64>'

Imprime el JSON del perfil descifrado en stdout.

El sobre es AES-256-CBC + HMAC-SHA256 con clave derivada por
PBKDF2-HMAC-SHA256 (20000 iteraciones para sec2, 25000 para pw2).
La clave de trabajo depende del estado del dispositivo que exporto
el enlace; el script prueba los valores posibles y se queda con el
que verifica el HMAC.
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys

_K1_BASE = bytes.fromhex(
    "dddd6bfcd0b12811acc49b23561c240bd04a74a050154036c1e3281c49fbf5df"
)
_K2 = bytes.fromhex(
    "f37a67c56fa18437f12bf961cf36aaf73ec1a38bfa9f59cda0697ce45f090b9b"
)
_W19_CANDIDATES = (
    2, 1, 3, 5, 7, 9, 11, 13, 15,
    0x21, 0x23, 0x25, 0x27, 0x29, 0x2B, 0x2D, 0x2F,
    0x61, 0x63, 0x65, 0x67, 0x69, 0x6B, 0x6D, 0x6F,
)

try:
    from Crypto.Cipher import AES as _AES

    def _aes_cbc_decrypt(key, iv, data):
        return _AES.new(key, _AES.MODE_CBC, iv).decrypt(data)

except ImportError:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def _aes_cbc_decrypt(key, iv, data):
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return d.update(data) + d.finalize()


def _mangle(buf, w19):
    mask = 0xFFFFFFFF
    w9 = (w19 * 0x9E3779B9) & mask
    w9 ^= 0x85EBCA6B
    out = bytearray(buf)
    for i in range(32):
        w9 = (w9 * 0x19660D + 0x3C6EF35F) & mask
        out[i] ^= ((w19 ^ (w9 >> 16) ^ (w9 >> 24)) | 1) & 0xFF
    return bytes(out)


def _decrypt_v2(blob, password=None):
    if len(blob) < 80:
        raise ValueError("envelope demasiado corto (minimo 80 bytes)")
    salt, iv, tag, ct = blob[:16], blob[16:32], blob[32:64], blob[64:]
    if password is None:
        iters = 20000
        suffix = b""
    else:
        iters = 25000
        suffix = password.strip().encode("utf-8")
    salt_mac = hmac.new(_K2, salt, hashlib.sha256).digest()
    for w19 in _W19_CANDIDATES:
        info = _mangle(_K1_BASE, w19) + _K2 + suffix
        dk = hashlib.pbkdf2_hmac("sha256", info, salt_mac, iters, dklen=64)
        key, mac_key = dk[:32], dk[32:]
        calc = hmac.new(mac_key, salt + iv + ct, hashlib.sha256).digest()
        if hmac.compare_digest(calc, tag):
            pt = _aes_cbc_decrypt(key, iv, ct)
            pad = pt[-1]
            if not 1 <= pad <= 16 or pt[-pad:] != bytes([pad]) * pad:
                raise ValueError("relleno PKCS7 invalido")
            return pt[:-pad]
    raise ValueError("Error de integridad: Firma de archivo no coincide")


def decode(text):
    text = text.strip()
    if text.startswith("nad://sec2:"):
        blob = base64.b64decode(text[len("nad://sec2:"):])
        return json.loads(_decrypt_v2(blob).decode("utf-8"))
    if text.startswith("nad://pw2:"):
        raise ValueError("nad://pw2: requiere --password")
    if text.startswith("nad://"):
        return json.loads(text[len("nad://"):])
    raise ValueError("texto no reconocido (se espera nad://sec2:, nad://pw2: o nad://)")


def decode_pw2(text, password):
    text = text.strip()
    if not text.startswith("nad://pw2:"):
        raise ValueError("se espera nad://pw2:")
    blob = base64.b64decode(text[len("nad://pw2:"):])
    return json.loads(_decrypt_v2(blob, password).decode("utf-8"))


def main():
    ap = argparse.ArgumentParser(description="Decodifica enlaces nad://sec2: / nad://pw2:")
    ap.add_argument("text", nargs="?", help="enlace nad://... (si falta, se lee de stdin)")
    ap.add_argument("--password", default=None, help="contrasena para nad://pw2:")
    args = ap.parse_args()
    text = args.text
    if text is None:
        text = sys.stdin.read()
    try:
        if args.password is not None:
            obj = decode_pw2(text, args.password)
        else:
            obj = decode(text)
    except Exception as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    print(json.dumps(obj, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
