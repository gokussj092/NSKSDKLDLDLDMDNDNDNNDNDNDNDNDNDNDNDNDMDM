#!/usr/bin/env python3
"""Decodificador de archivos .sn de SN VPN (com.snnombre.snvpn) para SP-DECODE.

Formato verificado en el APK SN VPN 5.0.7 (clases SnSecureCodec y
SnFileImporter, desensamblado del DEX) y confirmado con el archivo real
esvin11_3_0mc8.sn que exporto la app:

    archivo .sn = texto de caracteres invisibles U+2000..U+200F
    Base64      = nibble(carrier)                        (SnSecureCodec::b)
    SNX2        = Base64, con esta estructura:
        bytes 0..3   "SNX2" (magia)
        byte  4      version (2)
        byte  5      flags: bit 0 = con contrasena, bit 1 = ligado a dispositivo
        bytes 6..21  salt (16 B)
        bytes 22..33 nonce (12 B)
        bytes 34..   AES-256-GCM (AAD = cabecera de 6 B) + tag (16 B)
    JSON        = zlib-inflate(AES-GCM)                  (SnSecureCodec::d)

Derivacion de la clave (SnSecureCodec::a):
    master[i] = B[i] ^ C[i] ^ ((i*31+7) & 0xFF)   (i = 0..31, constantes del DEX)
    k1 = HMAC-SHA256(master, b"SNVPN-FILE-KEY-v2" || salt)
    si hay contrasena:
        T  = PBKDF2-HmacSHA256(contrasena, salt, 12000 iteraciones, 32 B)
        k2 = HMAC-SHA256(k1, b"PWD" || T)
    si hay HWID:
        k3 = HMAC-SHA256(k2, b"HWID" || HWID en mayusculas, solo [A-Z0-9])
    La clave final es k1, k2 o k3 segun los flags. El HWID es
    "snvpn:" + SHA-256(android_id) (DeviceIdProvider); sin el dispositivo
    que exporto el archivo no se puede abrir un .sn ligado a dispositivo.

El archivo real de Pedro (flags = 0) abre sin contrasena y sin HWID, como
el dijo. Su perfil: "esvin11", protocolo BHTTP, host 192.6.154.99:8080,
usuario esvin11.

La app tambien acepta JSON en claro y enlaces estandar (vmess://, vless://,
trojan://, ss://, hysteria2://, hy2://, hysteria://) por pegado de texto;
este script acepta ademas el JSON en claro y el Base64 directo del SNX2.

Solo stdlib de Python (AES-256-GCM implementado aqui). Sin contrasenas de
usuario ni claves de dispositivo.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import re
import struct
import sys
import zlib
from pathlib import Path

MAX_BYTES = 4 * 1024 * 1024
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 200000

MAGIC = b"SNX2"
VERSION = 2
FLAG_PASSWORD = 0x01
FLAG_DEVICE = 0x02

# Constantes ofuscadas del DEX (SnSecureCodec::b y ::c, <clinit>).
_XOR_A = bytes.fromhex(
    "fc0d15f9a92be725e414f79d6181a5884ab02a5caffd4ed5fa4bbba27cdcf446")
_XOR_B = bytes.fromhex(
    "ec31b86c45f964ba5f45fcf698ade9b5ea37d3c13a81372adb067be2a43cb457")
MASTER = bytes(_XOR_A[i] ^ _XOR_B[i] ^ ((i * 31 + 7) & 0xFF) for i in range(32))
KEY_LABEL = b"SNVPN-FILE-KEY-v2"
PBKDF2_ITERATIONS = 12000

# Alfabeto del portador invisible: U+2000..U+200F, en orden.
_CARRIER = [chr(0x2000 + i) for i in range(16)]
_CARRIER_INDEX = {c: i for i, c in enumerate(_CARRIER)}


class DecodeError(ValueError):
    """El archivo .sn no se pudo decodificar. `code` clasifica el fallo."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------------ AES puro
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
                    aa = ((aa << 1) ^ (0x1b if aa & 0x80 else 0)) & 0xFF
                    bb >>= 1
                if p == 1:
                    inv = y
                    break
        s = inv ^ ((inv << 1) | (inv >> 7)) ^ ((inv << 2) | (inv >> 6)) \
            ^ ((inv << 3) | (inv >> 5)) ^ ((inv << 4) | (inv >> 4)) ^ 0x63
        sbox.append(s & 0xFF)
    return sbox


_SBOX = _make_sbox()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
_GCM_R = 0xE1000000000000000000000000000000


def _aes_key_expand(key):
    w = [x for grp in (struct.unpack(">4I", key[i:i + 16]) for i in range(0, 32, 16)) for x in grp]
    for i in range(8, 60):
        temp = w[i - 1]
        if i % 8 == 0:
            rot = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF
            sub = (_SBOX[(rot >> 24) & 0xFF] << 24) | (_SBOX[(rot >> 16) & 0xFF] << 16) \
                | (_SBOX[(rot >> 8) & 0xFF] << 8) | _SBOX[rot & 0xFF]
            temp = sub ^ (_RCON[i // 8 - 1] << 24)
        elif i % 8 == 4:
            temp = (_SBOX[(temp >> 24) & 0xFF] << 24) | (_SBOX[(temp >> 16) & 0xFF] << 16) \
                | (_SBOX[(temp >> 8) & 0xFF] << 8) | _SBOX[temp & 0xFF]
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
                b[4 * j + i] = _SBOX[(s[j] >> (24 - 8 * i)) & 0xFF]
        sb = bytearray(16)
        for r in range(4):
            for c in range(4):
                sb[4 * c + r] = b[4 * ((c + r) % 4) + r]

        def xtime(x):
            return ((x << 1) ^ (0x1B if x & 0x80 else 0)) & 0xFF
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
            b[4 * j + i] = _SBOX[(s[j] >> (24 - 8 * i)) & 0xFF]
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


# ------------------------------------------------------- derivacion de clave
def _hmac_chain(key, *parts):
    return hmac.new(key, b"".join(parts), hashlib.sha256).digest()


def derive_key(password=None, hwid=None, salt=None):
    """SnSecureCodec::a: clave de 32 B para un .sn.

    password: contrasena del archivo (None = el archivo no tiene, flags bit 0
    apagado). hwid: HWID del dispositivo (None = no ligado, flags bit 1
    apagado). salt: 16 B del sobre. Una cadena vacia se trata como ausente.
    """
    if salt is None or len(salt) != 16:
        raise DecodeError("FORMAT_ERROR", "El salt del .sn debe tener 16 bytes.")
    key = _hmac_chain(MASTER, KEY_LABEL, salt)
    if password:
        stretched = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                        salt, PBKDF2_ITERATIONS, dklen=32)
        key = _hmac_chain(key, b"PWD", stretched)
    if hwid:
        clean = "".join(c for c in hwid.upper() if c.isalnum()).encode("utf-8")
        key = _hmac_chain(key, b"HWID", clean)
    return key


def device_id(android_id):
    """HWID que usa la app: 'snvpn:' + SHA-256(android_id)."""
    return "snvpn:" + hashlib.sha256(android_id.encode("utf-8")).hexdigest()


# ------------------------------------------------------------- portador / SNX2
def carrier_decode(text):
    """Portador invisible U+2000..U+200F -> bytes del Base64 (SnSecureCodec::b)."""
    nibs = [_CARRIER_INDEX[c] for c in text if c in _CARRIER_INDEX]
    if len(nibs) < 2 or len(nibs) % 2:
        raise DecodeError("FORMAT_ERROR",
                          "El portador invisible no tiene un numero par de caracteres.")
    return bytes((nibs[i] << 4) | nibs[i + 1] for i in range(0, len(nibs), 2))


def carrier_encode(data: bytes) -> str:
    """Inverso de carrier_decode: bytes -> texto invisible U+2000..U+200F."""
    out = []
    for b in data:
        out.append(_CARRIER[b >> 4])
        out.append(_CARRIER[b & 0x0F])
    return "".join(out)


def _text(data):
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "Se esperaba texto o bytes UTF-8.")
    if isinstance(data, bytes):
        if len(data) > MAX_BYTES:
            raise DecodeError("SIZE_LIMIT", "La entrada supera el limite de tamano.")
        try:
            value = data.decode("utf-8-sig")
        except UnicodeError as exc:
            raise DecodeError("FORMAT_ERROR", "La entrada no es UTF-8 valido.") from exc
    else:
        value = data.removeprefix("\ufeff")
    if len(value.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el limite de tamano.")
    return value


def _validate(doc):
    pending, count = [(doc, 0)], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            raise DecodeError("SIZE_LIMIT", "El JSON supera el limite de complejidad.")
        if isinstance(value, dict):
            pending.extend((v, depth + 1) for v in value.values())
            pending.extend((k, depth + 1) for k in value)
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
    return doc


def _parse_json(plain: bytes) -> dict:
    if len(plain) > MAX_JSON_BYTES:
        raise DecodeError("SIZE_LIMIT", "El perfil descifrado supera el limite de tamano.")
    try:
        doc = json.loads(plain.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DecodeError("FORMAT_ERROR", "El perfil descifrado no es JSON.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("FORMAT_ERROR", "El perfil descifrado no es un objeto JSON.")
    return _validate(doc)


def decrypt_snx2(raw: bytes, password=None, hwid=None) -> dict:
    """Decodifica un sobre SNX2 (ya en bytes) y devuelve el perfil JSON."""
    if len(raw) < 50:
        raise DecodeError("FORMAT_ERROR", "El sobre SNX2 es demasiado corto.")
    if raw[:4] != MAGIC:
        raise DecodeError("FORMAT_ERROR", "Falta la magia SNX2.")
    version, flags = raw[4], raw[5]
    if version != VERSION:
        raise DecodeError("UNSUPPORTED_VERSION",
                          "Version SNX2 %d no soportada (se esperaba %d)." % (version, VERSION))
    if flags & FLAG_PASSWORD and not password:
        raise DecodeError("PASSWORD_REQUIRED",
                          "Este .sn tiene contrasena; pasa --password.")
    if flags & FLAG_DEVICE and not hwid:
        raise DecodeError("HWID_REQUIRED",
                          "Este .sn esta ligado a un dispositivo; pasa --hwid "
                          "(o --android-id del dispositivo que lo exporto).")
    header, salt, nonce = raw[:6], raw[6:22], raw[22:34]
    rest = raw[34:]
    if len(rest) < 17:
        raise DecodeError("FORMAT_ERROR", "El sobre SNX2 no trae ciphertext ni tag.")
    ciphertext, tag = rest[:-16], rest[-16:]
    key = derive_key(password=password, hwid=hwid, salt=salt)
    try:
        compressed = _aes_gcm_decrypt(key, nonce, ciphertext, tag, aad=header)
    except ValueError as exc:
        if flags & FLAG_PASSWORD:
            raise DecodeError("WRONG_PASSWORD",
                              "Contrasena del archivo incorrecta.") from exc
        if flags & FLAG_DEVICE:
            raise DecodeError("WRONG_HWID",
                              "Este archivo esta ligado a otro dispositivo.") from exc
        raise DecodeError("DECRYPT_FAILED",
                          "El tag GCM no verifica; el archivo no abre.") from exc
    try:
        plain = zlib.decompress(compressed)
    except zlib.error as exc:
        raise DecodeError("FORMAT_ERROR",
                          "El contenido descifrado no es zlib valido.") from exc
    return _parse_json(plain)


def decode(data, password=None, hwid=None, android_id=None) -> dict:
    """Decodifica un .sn (portador invisible), un Base64 SNX2 o JSON en claro."""
    if hwid is None and android_id:
        hwid = device_id(android_id)
    text = _text(data)
    stripped = text.strip()
    if stripped.startswith("{"):
        return _parse_json(stripped.encode("utf-8"))
    compact = re.sub(r"[ \t\r\n]", "", text)
    if set(compact) <= set(_CARRIER_INDEX):
        raw = base64.b64decode(carrier_decode(compact), validate=True)
    elif re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        try:
            raw = base64.b64decode(compact, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise DecodeError("FORMAT_ERROR", "Base64 invalido.") from exc
    else:
        raise DecodeError("FORMAT_ERROR",
                          "No es un .sn (portador invisible), ni Base64 SNX2, ni JSON.")
    if raw[:4] != MAGIC:
        raise DecodeError("FORMAT_ERROR", "Falta la magia SNX2.")
    return decrypt_snx2(raw, password=password, hwid=hwid)


def encrypt_snx2(doc: dict, password=None, hwid=None, salt=None, nonce=None) -> str:
    """Construye un .sn (texto invisible) desde un perfil JSON, como la app.

    Solo para pruebas de round-trip: salt/nonce aleatorios si no se dan.
    """
    import os
    if salt is None:
        salt = os.urandom(16)
    if nonce is None:
        nonce = os.urandom(12)
    flags = 0
    if password:
        flags |= FLAG_PASSWORD
    if hwid:
        flags |= FLAG_DEVICE
    header = MAGIC + bytes([VERSION, flags])
    key = derive_key(password=password, hwid=hwid, salt=salt)
    plain = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    compressed = zlib.compress(plain, 9)
    ciphertext, tag = _aes_gcm_encrypt(key, nonce, compressed, aad=header)
    blob = header + salt + nonce + ciphertext + tag
    return carrier_encode(base64.b64encode(blob))


def run(args=None):
    parser = argparse.ArgumentParser(
        prog="SN_VPN_archivos.py",
        description="Decodificador de archivos .sn de SN VPN.")
    parser.add_argument("--file", help="Archivo .sn a decodificar.")
    parser.add_argument("--stdin", action="store_true", help="Leer el .sn de stdin.")
    parser.add_argument("--password", help="Contrasena del archivo (si tiene).")
    parser.add_argument("--hwid", help="HWID del dispositivo que exporto el archivo.")
    parser.add_argument("--android-id", help="Android ID; se deriva el HWID de el.")
    parser.add_argument("--self-test", action="store_true", help="Pruebas internas.")
    parser.add_argument("--encode", metavar="JSON",
                        help="Construir un .sn desde un archivo JSON (pruebas).")
    parser.add_argument("-o", "--out", help="Guardar el perfil JSON en un archivo.")
    parser.add_argument("--json", action="store_true",
                        help="Imprimir el perfil como JSON de una linea.")
    ns = parser.parse_args(args)

    if ns.self_test:
        return 0 if _self_test() else 1

    if ns.encode:
        doc = json.loads(Path(ns.encode).read_text(encoding="utf-8"))
        hwid = ns.hwid or (device_id(ns.android_id) if ns.android_id else None)
        text = encrypt_snx2(doc, password=ns.password, hwid=hwid)
        if ns.out:
            Path(ns.out).write_text(text, encoding="utf-8")
        else:
            print(text)
        return 0

    if ns.file:
        raw = Path(ns.file).read_bytes()
    elif ns.stdin:
        raw = sys.stdin.buffer.read()
    else:
        parser.error("Falta --file o --stdin.")
    try:
        doc = decode(raw, password=ns.password, hwid=ns.hwid,
                     android_id=ns.android_id)
    except DecodeError as exc:
        print("ERROR [%s]: %s" % (exc.code, exc), file=sys.stderr)
        return 2
    if ns.out:
        Path(ns.out).write_text(json.dumps(doc, ensure_ascii=False, indent=2),
                                encoding="utf-8")
    if ns.json:
        print(json.dumps(doc, ensure_ascii=False))
        return 0
    data = doc.get("Data", doc)
    print("SN VPN - perfil .sn")
    print("Nombre: %s" % data.get("name", doc.get("Name", "?")))
    print("Protocolo: %s | Host: %s:%s" % (data.get("protocol", "?"),
                                            data.get("host", "?"),
                                            data.get("port", "?")))
    print("Usuario: %s" % data.get("username", "?"))
    if data.get("creator"):
        print("Creador: %s" % data["creator"])
    return 0


def _self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("OK  " if cond else "FAIL") + " " + name)
        ok = ok and bool(cond)

    # AES-256-GCM KAT (NIST McGrew-Viega, caso 1 y 2; verificado tambien
    # contra PyCryptodome): clave 0, nonce 0, vacio -> tag 530f8afb...;
    # 16 bytes cero -> ct cea7403d..., tag d0d1c8a7....
    kw = bytes(32)
    ct, tag = _aes_gcm_encrypt(kw, bytes(12), b"", aad=b"")
    check("AES-256-GCM KAT (vacio)",
          ct == b"" and tag.hex() == "530f8afbc74536b9a963b4f1c4cb738b")
    ct, tag = _aes_gcm_encrypt(kw, bytes(12), bytes(16), aad=b"")
    check("AES-256-GCM KAT (16 ceros)",
          ct.hex() == "cea7403d4d606b6e074ec5d3baf39d18"
          and tag.hex() == "d0d1c8a799996bf0265b98b5d48ab919")
    check("AES-256-GCM round-trip",
          _aes_gcm_decrypt(kw, bytes(12), ct, tag, aad=b"") == bytes(16))
    # Vector de derivacion del archivo real esvin11_3_0mc8.sn (flags 0):
    # salt de3dde06b2f8683422ff1a701ab3e88a -> clave 44e296b1...
    salt = bytes.fromhex("de3dde06b2f8683422ff1a701ab3e88a")
    check("derivacion clave (archivo real)",
          derive_key(salt=salt).hex()
          == "44e296b10b30894606c6b0f15dca007941afbb90412ad086580aabf1bf443421")
    # PBKDF2 de la derivacion coincide con hashlib (mismo algoritmo).
    t = hashlib.pbkdf2_hmac("sha256", b"secreto", salt, PBKDF2_ITERATIONS, dklen=32)
    k = _hmac_chain(MASTER, KEY_LABEL, salt)
    k2 = _hmac_chain(k, b"PWD", t)
    check("derivacion con contrasena",
          derive_key(password="secreto", salt=salt) == k2)
    check("derivacion con HWID",
          derive_key(hwid="snvpn:ABC123", salt=salt)
          == _hmac_chain(k, b"HWID", b"SNVPNABC123"))
    check("device_id",
          device_id("test") == "snvpn:" + hashlib.sha256(b"test").hexdigest())
    # Round-trip completo .sn (sin contrasena, con contrasena y con HWID).
    doc = {"Type": "CUSTOM", "Version": 2, "App": "SN VPN",
           "Data": {"name": "prueba", "protocol": "SSH", "host": "1.2.3.4",
                    "port": "22", "username": "u", "password": "p"}}
    check(".sn round-trip (sin proteccion)", decode(encrypt_snx2(doc)) == doc)
    check(".sn round-trip (contrasena)",
          decode(encrypt_snx2(doc, password="clave"), password="clave") == doc)
    try:
        decode(encrypt_snx2(doc, password="clave"), password="otra")
        check(".sn rechaza contrasena incorrecta", False)
    except DecodeError as exc:
        check(".sn rechaza contrasena incorrecta", exc.code == "WRONG_PASSWORD")
    check(".sn round-trip (HWID)",
          decode(encrypt_snx2(doc, hwid="snvpn:ABC123"), hwid="snvpn:ABC123") == doc)
    check("JSON en claro", decode('{"a": 1}') == {"a": 1})
    print("SELF-TEST: " + ("TODO OK" if ok else "FALLO"))
    return ok


if __name__ == "__main__":
    sys.exit(run())
