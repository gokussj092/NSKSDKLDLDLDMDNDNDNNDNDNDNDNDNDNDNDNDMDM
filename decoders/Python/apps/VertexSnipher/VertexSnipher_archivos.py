#!/usr/bin/env python3
"""VertexSnipher 0.1.46: decodificador de códigos de importación `snipher://`.

Python 3.10+, solo biblioteca estándar. AES-256-GCM en Python puro
(núcleo verificado de RoVPN.py / Fat_Tunnel_Lite.py, contra PyCryptodome
y vectores NIST).

App: codes.juanscript.vertexsnipher, versionCode 46, versionName 0.1.46,
minSdk 32. Versión pública de Google Play (0.1.46), descargada de APKPure
porque APKMirror no tenía listado. Sin cobertura previa en el repo de
SP-DECODE (86 carpetas revisadas; VIP_Snipher_Pro es otra app).

La app NO tiene formato propio de archivo de perfiles: los perfiles viven
en SharedPreferences (`mobiclient_profiles`, clave `profiles`, JSONArray) y
se comparten por código de texto `snipher://` (pegado en la app; NO es un
deep link registrado en el manifiesto). Los .ovpn son OpenVPN estándar y
SP-DECODE ya los cubre, así que no hay decodificador de archivos aquí:
este script es el decodificador del formato propio de la app.

Formato del código (vo3.g/h, t72.c, t01.j del DEX):

  snipher://<2:|3:><base64url_sin_relleno(sobre)>.<sha256_hex(base64)[:16]>

  sobre = BE32(16) || salt[16] || BE32(12) || nonce[12] || ct || tag(16)
  clave = PBKDF2-HmacSHA256(contraseña, salt, 120000 iter, 32 B)
  contraseña v2 = "rdxiNA3WXwfRAjdm@092898yue"
  contraseña v3 = "rdxiNA3WXwfRAjdm@092898yue|device-lock-v3"
  texto plano = GZIP(JSON del perfil)

  Formato heredado (sin prefijo 2:/3:):
  snipher://<base64url_sin_relleno(base64_std(sobre))>.<sha512_hex(base64)>
  El texto plano heredado es el JSON en claro (sin GZIP); si empieza por
  el magic de GZIP se descomprime igualmente.

El JSON del perfil es el mapa interno de la app (campos del perfil:
nombre, modo, servidor, puertos, payload, SNI, DNS, claves, etc., más
`allow_reshare`, `delete_on_import`, `access_password`,
`import_expires_at` y `allowed_device_ids` cuando aplica). Los perfiles
compartidos en la nube (`share_uri`) usan el mismo sobre; este script
también acepta el sobre en Base64 directamente.

Verificación: el ida y vuelta se probó con códigos sintéticos construidos
con este mismo script (v2, v3 y heredado); no había un código real de un
teléfono disponible, así que la confirmación de extremo a extremo con un
`snipher://` real sigue pendiente.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import hashlib
import io
import json
import re
import struct
import sys
import zlib
from pathlib import Path

MAX_BYTES = 8 * 1024 * 1024

PASSWORD_V2 = "rdxiNA3WXwfRAjdm@092898yue"
PASSWORD_V3 = "rdxiNA3WXwfRAjdm@092898yue|device-lock-v3"
PBKDF2_ITERATIONS = 120000


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------- AES-256-GCM
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
    """AES-256-GCM decrypt (pure stdlib). nonce: 12 bytes."""
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
    """AES-256-GCM encrypt (pure stdlib). Returns (ciphertext, tag)."""
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



def _b64url_decode(text: str) -> bytes:
    compact = re.sub(r"\s+", "", text)
    try:
        return base64.urlsafe_b64decode(compact + "=" * (-len(compact) % 4))
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("FORMAT_ERROR", "Base64 URL inválido.") from exc


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decrypt_envelope(envelope: bytes, password: str) -> bytes:
    """Descifra un sobre (t01.j): BE32(16)||salt||BE32(12)||nonce||ct+tag."""
    if len(envelope) < 52:
        raise DecodeError("FORMAT_ERROR", "Sobre demasiado corto (< 52 B).")
    buf = memoryview(envelope)
    salt_len = struct.unpack(">I", buf[0:4])[0]
    if salt_len != 16 or len(envelope) < 4 + salt_len + 4:
        raise DecodeError("FORMAT_ERROR", "Longitud de sal inválida (se esperaba 16).")
    salt = bytes(buf[4:20])
    nonce_len = struct.unpack(">I", buf[20:24])[0]
    if nonce_len != 12 or len(envelope) < 24 + nonce_len + 16:
        raise DecodeError("FORMAT_ERROR", "Longitud de nonce inválida (se esperaba 12).")
    nonce = bytes(buf[24:36])
    ct_tag = bytes(buf[36:])
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                              salt, PBKDF2_ITERATIONS, 32)
    try:
        return _aes_gcm_decrypt(key, nonce, ct_tag[:-16], ct_tag[-16:])
    except ValueError as exc:
        raise DecodeError("DECRYPT_FAILED",
                          "El tag GCM no verifica: contraseña o sobre incorrectos.") from exc


def _encrypt_envelope(plain: bytes, password: str,
                      salt: bytes | None = None,
                      nonce: bytes | None = None) -> bytes:
    """Construye un sobre (t72.c): BE32(16)||salt||BE32(12)||nonce||ct+tag."""
    import os
    salt = salt if salt is not None else os.urandom(16)
    nonce = nonce if nonce is not None else os.urandom(12)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                              salt, PBKDF2_ITERATIONS, 32)
    ct, tag = _aes_gcm_encrypt(key, nonce, plain)
    return struct.pack(">I", 16) + salt + struct.pack(">I", 12) + nonce + ct + tag


def _maybe_gunzip(raw: bytes) -> bytes:
    if raw[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(raw)
        except (OSError, EOFError, zlib.error) as exc:
            raise DecodeError("FORMAT_ERROR", "El cuerpo GZIP está corrupto.") from exc
    return raw


def decode_snipher(code: str) -> dict:
    """Descifra un código `snipher://` y devuelve el JSON del perfil."""
    if not isinstance(code, str):
        raise DecodeError("FORMAT_ERROR", "Se esperaba un código snipher:// como texto.")
    text = code.strip()
    if not text.lower().startswith("snipher://"):
        raise DecodeError("FORMAT_ERROR", "El código debe empezar por snipher://.")
    rest = text[len("snipher://"):]
    if "." not in rest:
        raise DecodeError("FORMAT_ERROR", "Falta el checksum '.<hex>' del código.")
    body, checksum = rest.rsplit(".", 1)
    checksum = checksum.strip().lower()
    if body.startswith("3:"):
        password = PASSWORD_V3
        payload_b64 = body[2:]
        if hashlib.sha256(payload_b64.encode("ascii")).hexdigest()[:16] != checksum:
            raise DecodeError("CHECKSUM_MISMATCH", "El checksum SHA-256 del código no coincide.")
        envelope = _b64url_decode(payload_b64)
        plain = _decrypt_envelope(envelope, password)
        return _json(_maybe_gunzip(plain))
    if body.startswith("2:"):
        password = PASSWORD_V2
        payload_b64 = body[2:]
        if hashlib.sha256(payload_b64.encode("ascii")).hexdigest()[:16] != checksum:
            raise DecodeError("CHECKSUM_MISMATCH", "El checksum SHA-256 del código no coincide.")
        envelope = _b64url_decode(payload_b64)
        plain = _decrypt_envelope(envelope, password)
        return _json(_maybe_gunzip(plain))
    # Formato heredado: base64url(base64_std(sobre)), checksum SHA-512 completo.
    if hashlib.sha512(body.encode("ascii")).hexdigest() != checksum:
        raise DecodeError("CHECKSUM_MISMATCH", "El checksum SHA-512 del código no coincide.")
    inner = _b64url_decode(body).decode("ascii")
    try:
        envelope = base64.b64decode(inner, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("FORMAT_ERROR", "La capa Base64 interna es inválida.") from exc
    plain = _decrypt_envelope(envelope, PASSWORD_V2)
    return _json(_maybe_gunzip(plain))


def encode_snipher(profile: dict, version: int = 2,
                   salt: bytes | None = None,
                   nonce: bytes | None = None) -> str:
    """Construye un código `snipher://` a partir de un perfil (ver decode_snipher)."""
    if version not in (2, 3):
        raise DecodeError("FORMAT_ERROR", "La versión del código debe ser 2 o 3.")
    password = PASSWORD_V2 if version == 2 else PASSWORD_V3
    plain = gzip.compress(json.dumps(profile, ensure_ascii=False).encode("utf-8"),
                          compresslevel=9, mtime=0)
    envelope = _encrypt_envelope(plain, password, salt=salt, nonce=nonce)
    payload_b64 = _b64url_encode(envelope)
    checksum = hashlib.sha256(payload_b64.encode("ascii")).hexdigest()[:16]
    return "snipher://%d:%s.%s" % (version, payload_b64, checksum)


def decode(data: bytes | str) -> dict:
    """Acepta un código snipher:// (texto) o un sobre Base64, y devuelve el perfil."""
    if isinstance(data, bytes):
        text = data.decode("utf-8-sig").strip()
    else:
        text = data.strip()
    if text.lower().startswith("snipher://"):
        return decode_snipher(text)
    # Sobre en Base64 directo (o JSON plano del perfil).
    if text.startswith("{"):
        return _json(text.encode("utf-8"))
    envelope = _b64url_decode(text)
    for password in (PASSWORD_V2, PASSWORD_V3):
        try:
            return _json(_maybe_gunzip(_decrypt_envelope(envelope, password)))
        except DecodeError:
            continue
    raise DecodeError("DECRYPT_FAILED",
                      "El sobre no abre con ninguna de las dos contraseñas de formato.")


def run(data: bytes | str) -> str:
    """Devuelve el perfil decodificado como JSON (texto)."""
    doc = decode(data)
    return json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


def _json(raw: bytes) -> dict:
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError("FORMAT_ERROR", "El texto plano no es JSON UTF-8.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("FORMAT_ERROR", "El perfil decodificado no es un objeto JSON.")
    return doc


# ---------------------------------------------------------------- self-test

def _self_test() -> dict:
    checks = {}
    profile = {"name": "TEST-PRUEBA", "mode": "SSH", "server": "test.example",
               "port": 443, "payload": "GET / HTTP/1.1", "sni": "example.com",
               "allow_reshare": True, "delete_on_import": False}
    fixed_salt = bytes(range(16))
    fixed_nonce = bytes(range(12))
    for version in (2, 3):
        code = encode_snipher(profile, version=version,
                              salt=fixed_salt, nonce=fixed_nonce)
        opened = decode_snipher(code)
        checks["roundtrip_v%d" % version] = opened == profile
        checks["prefix_v%d" % version] = code.startswith("snipher://%d:" % version)
    # Heredado: base64url(base64_std(sobre)), checksum SHA-512.
    plain = json.dumps(profile, ensure_ascii=False).encode("utf-8")
    envelope = _encrypt_envelope(plain, PASSWORD_V2, salt=fixed_salt, nonce=fixed_nonce)
    inner = base64.b64encode(envelope).decode("ascii")
    body = _b64url_encode(inner.encode("ascii"))
    legacy = "snipher://%s.%s" % (body, hashlib.sha512(body.encode("ascii")).hexdigest())
    checks["roundtrip_legacy"] = decode_snipher(legacy) == profile
    # Checksum alterado se rechaza.
    bad = encode_snipher(profile, version=2, salt=fixed_salt, nonce=fixed_nonce)
    head, tail = bad.rsplit(".", 1)
    bad_code = head + "." + ("0" if tail[0] != "0" else "1") + tail[1:]
    try:
        decode_snipher(bad_code)
        checks["bad_checksum_rejected"] = False
    except DecodeError as exc:
        checks["bad_checksum_rejected"] = exc.code == "CHECKSUM_MISMATCH"
    # Sobre alterado (tag GCM) se rechaza.
    code2 = encode_snipher(profile, version=2, salt=fixed_salt, nonce=fixed_nonce)
    body2, chk2 = code2[len("snipher://2:"):].rsplit(".", 1)
    raw = bytearray(_b64url_decode(body2))
    raw[-1] ^= 0x01
    tampered = "snipher://2:%s.%s" % (
        _b64url_encode(bytes(raw)),
        hashlib.sha256(_b64url_encode(bytes(raw)).encode("ascii")).hexdigest()[:16])
    try:
        decode_snipher(tampered)
        checks["tampered_rejected"] = False
    except DecodeError as exc:
        checks["tampered_rejected"] = exc.code == "DECRYPT_FAILED"
    # Prefijo inválido se rechaza.
    try:
        decode_snipher("https://example.com/x")
        checks["bad_prefix_rejected"] = False
    except DecodeError as exc:
        checks["bad_prefix_rejected"] = exc.code == "FORMAT_ERROR"
    # AES-256-GCM contra el vector cero (clave 256 bits, nonce cero).
    key256 = bytes(32)
    ct, tag = _aes_gcm_encrypt(key256, bytes(12), bytes(16))
    checks["gcm_nist_zero"] = (
        ct.hex() == "cea7403d4d606b6e074ec5d3baf39d18"
        and tag.hex() == "d0d1c8a799996bf0265b98b5d48ab919")
    checks["gcm_roundtrip"] = _aes_gcm_decrypt(key256, bytes(12), ct, tag) == bytes(16)
    return checks


# ---------------------------------------------------------------- CLI

def _read(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("code", nargs="?",
                        help="Código snipher://, sobre en Base64 o JSON del perfil")
    source.add_argument("--file", type=Path,
                        help="Archivo con el código snipher:// o el sobre")
    source.add_argument("--stdin", action="store_true",
                        help="Leer el código desde stdin")
    source.add_argument("--encode", type=Path, metavar="PERFIL_JSON",
                        help="Construir un código snipher:// desde un JSON de perfil")
    parser.add_argument("--version", type=int, choices=(2, 3), default=2,
                        help="Versión del código al codificar (2 o 3, por defecto 2)")
    parser.add_argument("-o", "--output", type=Path,
                        help="Guardar el resultado; por defecto stdout")
    parser.add_argument("--self-test", action="store_true",
                        help="Verifica el ida y vuelta v2/v3/heredado y el AES-GCM")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            result = _self_test()
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if all(result.values()) else 1
        if args.encode is not None:
            profile = _json(_read(args.encode))
            rendered = encode_snipher(profile, version=args.version) + "\n"
        elif args.stdin:
            rendered = run(sys.stdin.buffer.read(MAX_BYTES + 1))
        elif args.file is not None:
            rendered = run(_read(args.file))
        elif args.code is not None:
            rendered = run(args.code)
        else:
            parser.error("se requiere un código, --file, --stdin, --encode o --self-test")
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False),
              file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
