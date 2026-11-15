#!/usr/bin/env python3
"""DTunnel Mod / Fastiver Vpn Pro 4.2.5 — catálogo cifrado y enlaces vpn://.

Método verificado en vivo 2026-11-14 contra el endpoint del APK, con el
credentials.json de ESTE APK (paquete com.dtunnel.v2ray.pro, versionCode 9):

    GET https://dtmod.cloud/api/dtunnelmod
    User-Agent: DTunnelMod (@DTunnelMod, @DTunnelModGroup, @LightXVD)
    dtunnel-token: <user_id de credentials.json>
    dtunnel-update: app_config | app_layout | app_text

Cifrado (constante de formato embebida en el cliente, recuperada del
libLight.so nativo; NO es user_id ni token de una cuenta):
    seed = UTF-8("DTunnelModSecret-API-9c69a0b72b442ccac3e6aaaa7630d12f2b"
                 "351fe395e9fe667efa0907cde90da5")
    key  = SHA-256(seed)            # 32 bytes
    iv   = 16 bytes a cero
    cuerpo = Base64 estándar(respuesta HTTP)
    texto  = AES-256-CBC-PKCS#7(key, iv, cuerpo) -> JSON UTF-8

El catálogo no tiene campo de versión: es una lista plana de perfiles de
servidor (22 campos cada uno). El enlace vpn:// es Base64 estándar de un
objeto JSON UTF-8, sin cifrar.

Sin dependencias: stdlib puro (AES implementado aquí). Incluye el identificador
aportado y autorizado expresamente por el propietario. Los parámetros
--credentials-file y --request-id-file permiten sustituirlo. El valor
integrado solo se envía al endpoint original, sin redirecciones.

Uso:
    python3 DTunnel.py --url
    python3 DTunnel.py --url --credentials-file credentials.json
    python3 DTunnel.py --url --credentials-file credentials.json --kind layout
    python3 DTunnel.py --url --credentials-file credentials.json --kind texts
    python3 DTunnel.py respuesta_catalogo.txt
    python3 DTunnel.py --link 'vpn://BASE64_DEL_JSON'
    python3 DTunnel.py --self-test
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import re
import struct
import sys
from http.client import HTTPException
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_BYTES = 32 * 1024 * 1024
MAX_NODES = 1_000_000
MAX_DEPTH = 64
CATALOG_URL = "https://dtmod.cloud/api/dtunnelmod"
USER_AGENT = "DTunnelMod (@DTunnelMod, @DTunnelModGroup, @LightXVD)"
# Owner supplied and explicitly authorized this default on 2026-11-14.
# Used only for the fixed DTunnel updater, never public catalog metadata.
DEFAULT_REQUEST_ID = "3d61851c-7098-4c5f-8400-a581c3abd547"
# Constante de formato compartida del cliente (no es una credencial de cuenta).
CATALOG_SEED = (
    b"DTunnelModSecret-API-9c69a0b72b442ccac3e6aaaa7630d12f2b"
    b"351fe395e9fe667efa0907cde90da5"
)
CATALOG_KEY = hashlib.sha256(CATALOG_SEED).digest()
UPDATE_KINDS = {"catalog": "app_config", "layout": "app_layout", "texts": "app_text"}


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------- AES-256 (stdlib)
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
    for _ in range(8):
        if y & 1:
            z ^= x
        hi = x & 0x80
        x = (x << 1) & 0xff
        if hi:
            x ^= 0x1b
        y >>= 1
    return z


def _aes_decrypt_block(key_words, block):
    # state: bytearray de 16, state[4*c + r] (columna c, fila r)
    s = bytearray(block)
    rk = key_words

    def add_rk(rnd):
        for j in range(4):
            w = rk[4 * rnd + j]
            for i in range(4):
                s[4 * j + i] ^= (w >> (24 - 8 * i)) & 0xff

    def inv_shift_rows():
        t = bytearray(s)
        for r in range(4):
            for c in range(4):
                s[4 * c + r] = t[4 * ((c - r) % 4) + r]

    def inv_sub_bytes():
        for i in range(16):
            s[i] = _INV_SBOX[s[i]]

    def inv_mix_columns():
        for c in range(4):
            a0, a1, a2, a3 = s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]
            s[4 * c] = _gf_mul(a0, 14) ^ _gf_mul(a1, 11) ^ _gf_mul(a2, 13) ^ _gf_mul(a3, 9)
            s[4 * c + 1] = _gf_mul(a0, 9) ^ _gf_mul(a1, 14) ^ _gf_mul(a2, 11) ^ _gf_mul(a3, 13)
            s[4 * c + 2] = _gf_mul(a0, 13) ^ _gf_mul(a1, 9) ^ _gf_mul(a2, 14) ^ _gf_mul(a3, 11)
            s[4 * c + 3] = _gf_mul(a0, 11) ^ _gf_mul(a1, 13) ^ _gf_mul(a2, 9) ^ _gf_mul(a3, 14)

    add_rk(14)
    for rnd in range(13, 0, -1):
        inv_shift_rows()
        inv_sub_bytes()
        add_rk(rnd)
        inv_mix_columns()
    inv_shift_rows()
    inv_sub_bytes()
    add_rk(0)
    return bytes(s)


def _aes_cbc_decrypt(key, iv, data):
    if len(data) % 16:
        raise DecodeError("TRUNCATED", "El catálogo no contiene bloques AES completos.")
    kw = _aes_key_expand(key)
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 16):
        block = data[off:off + 16]
        plain = _aes_decrypt_block(kw, block)
        out += bytes(a ^ b for a, b in zip(plain, prev))
        prev = block
    if not out:
        raise DecodeError("DECRYPT_FAILED", "El catálogo descifrado está vacío.")
    pad = out[-1]
    if pad < 1 or pad > 16 or out[-pad:] != bytes([pad]) * pad:
        raise DecodeError("DECRYPT_FAILED", "Padding PKCS#7 inválido: no se pudo descifrar con este formato.")
    return bytes(out[:-pad])


def _aes_cbc_encrypt(key, iv, data):
    pad = 16 - (len(data) % 16)
    data = data + bytes([pad]) * pad
    kw = _aes_key_expand(key)
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[off:off + 16], prev))
        prev = _aes_encrypt_block(kw, block)
        out += prev
    return bytes(out)


# ------------------------------------------------------------- decodificación
def _text(data: bytes | str) -> str:
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "La entrada debe ser bytes o texto UTF-8.")
    if isinstance(data, bytes) and len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    try:
        text = data.decode("utf-8-sig") if isinstance(data, bytes) else data.removeprefix("\ufeff")
        if len(text.encode("utf-8")) > MAX_BYTES:
            raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    except UnicodeError as exc:
        raise DecodeError("FORMAT_ERROR", "La entrada no es UTF-8 válido.") from exc
    return text.strip()


def _base64(text: str) -> bytes:
    compact = re.sub(r"[ \t\r\n]", "", text)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) or len(compact) % 4 == 1:
        raise DecodeError("FORMAT_ERROR", "Se esperaba Base64 estándar.")
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


def _validate(doc: Any) -> Any:
    pending = [(doc, 0)]
    count = 0
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
            raise DecodeError("INVALID_JSON", "El JSON contiene un número no finito.")
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError as exc:
                raise DecodeError("INVALID_JSON", "El JSON contiene Unicode inválido.") from exc
    return doc


def _json(text: str) -> Any:
    try:
        doc = json.loads(text, object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (ValueError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON", "JSON inválido o con claves duplicadas.") from exc
    return _validate(doc)


def decrypt_catalog_text(data: bytes | str) -> str:
    """Devuelve el texto claro UTF-8 del catálogo cifrado (sin autenticación CBC)."""
    encrypted = _base64(_text(data))
    if not encrypted:
        raise DecodeError("TRUNCATED", "El catálogo no contiene bloques AES completos.")
    try:
        return _aes_cbc_decrypt(CATALOG_KEY, bytes(16), encrypted).decode("utf-8")
    except (DecodeError, UnicodeError) as exc:
        if isinstance(exc, DecodeError):
            raise
        raise DecodeError("DECRYPT_FAILED", "No se pudo descifrar el catálogo con este formato.") from exc


def decode_catalog(data: bytes | str, *, kind: str = "catalog") -> list[dict]:
    """Descifra la respuesta y devuelve cada perfil; se conservan todos los campos."""
    if kind not in UPDATE_KINDS:
        raise DecodeError("FORMAT_ERROR", "Tipo de actualización desconocido.")
    doc = _json(decrypt_catalog_text(data))
    if not isinstance(doc, list):
        raise DecodeError("WRONG_DOCUMENT", "La respuesta debe contener una lista JSON.")
    result = []
    for member in doc:
        item = _json(member) if isinstance(member, str) else member
        if not isinstance(item, dict):
            raise DecodeError("WRONG_DOCUMENT", "Cada miembro debe ser un objeto o su cadena JSON.")
        result.append(item)
    return _validate(result)


def decode_link(data: bytes | str) -> dict:
    """Descifra vpn://Base64(UTF-8 JSON); conserva los IDs y campos originales."""
    text = _text(data)
    if not text.startswith("vpn://"):
        raise DecodeError("FORMAT_ERROR", "Se esperaba un enlace vpn://.")
    try:
        plain = _base64(text[6:]).decode("utf-8")
    except UnicodeError as exc:
        raise DecodeError("FORMAT_ERROR", "El enlace no contiene UTF-8 válido.") from exc
    doc = _json(plain)
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El enlace debe contener un objeto JSON.")
    return doc


def decode(data: bytes | str, *, kind: str = "catalog") -> list[dict] | dict:
    text = _text(data)
    return decode_link(text) if text.startswith("vpn://") else decode_catalog(text, kind=kind)


def run(file_bytes: bytes | str, *, kind: str = "catalog") -> str | None:
    """Contrato offline del repo: JSON completo o None si falla."""
    try:
        return json.dumps(decode(file_bytes, kind=kind), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_catalog(url: str, request_id: str = DEFAULT_REQUEST_ID, *, kind: str = "catalog") -> bytes:
    """GET with the authorized default or an explicit caller ID; no redirects."""
    if not isinstance(request_id, str) or not re.fullmatch(r"[\x21-\x7e]{1,512}", request_id):
        raise DecodeError("CREDENTIALS_REQUIRED", "Se necesita un identificador válido sin espacios ni saltos de línea.")
    if kind not in UPDATE_KINDS:
        raise DecodeError("FORMAT_ERROR", "Tipo de actualización desconocido.")
    try:
        parts = urlsplit(url)
        if request_id == DEFAULT_REQUEST_ID and parts != urlsplit(CATALOG_URL):
            raise ValueError("default identity is restricted to the original updater")
        if parts.scheme != "https" or not parts.hostname or parts.username is not None or parts.password is not None or parts.fragment:
            raise ValueError("invalid URL")
        request = Request(url, headers={"User-Agent": USER_AGENT,
                          "dtunnel-token": request_id, "dtunnel-update": UPDATE_KINDS[kind]}, method="GET")
        with build_opener(_NoRedirect()).open(request, timeout=20) as response:
            data = response.read(MAX_BYTES + 1)
    except HTTPError as exc:
        if exc.code in (401, 403):
            raise DecodeError("ACCESS_DENIED", "El servicio rechazó el identificador de acceso.") from exc
        raise DecodeError("DOWNLOAD_FAILED", "El servicio no devolvió una respuesta válida; no se siguen redirecciones.") from exc
    except (OSError, ValueError, URLError, HTTPException) as exc:
        raise DecodeError("DOWNLOAD_FAILED", "No se pudo descargar el catálogo mediante HTTPS.") from exc
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La respuesta supera el límite de tamaño.")
    return data


def _read(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def _summarize(result, kind: str) -> None:
    if kind != "catalog" or not isinstance(result, list):
        print(f"Miembros: {len(result)}", file=sys.stderr)
        return
    from collections import Counter
    cats = Counter((i.get("category") or {}).get("name") for i in result)
    modes = Counter(i.get("mode") for i in result)
    payloads = sum(1 for i in result if i.get("config_payload"))
    print(f"Perfiles: {len(result)}", file=sys.stderr)
    print("Categorías: " + ", ".join(f"{k or '?'}: {v}" for k, v in cats.most_common()), file=sys.stderr)
    print("Modos: " + ", ".join(f"{k}: {v}" for k, v in modes.most_common()), file=sys.stderr)
    print(f"Con payload: {payloads} de {len(result)}", file=sys.stderr)


def _self_test() -> int:
    ok = 0

    def check(name, cond):
        nonlocal ok
        print(("OK   " if cond else "FAIL ") + name)
        if not cond:
            raise SystemExit(1)
        ok += 1

    # Vector FIPS-197 AES-256 (clave 000102...1f, texto 00112233...ff).
    kw = _aes_key_expand(bytes(range(32)))
    ct = _aes_encrypt_block(kw, bytes.fromhex("00112233445566778899aabbccddeeff"))
    check("AES-256 FIPS-197 cifrado", ct.hex() == "8ea2b7ca516745bfeafc49904b496089")
    pt = _aes_decrypt_block(kw, bytes.fromhex("8ea2b7ca516745bfeafc49904b496089"))
    check("AES-256 FIPS-197 descifrado", pt.hex() == "00112233445566778899aabbccddeeff")
    # Round-trip CBC con la clave del catálogo.
    plain = json.dumps([{"id": 1, "name": "prueba", "config_payload": "GET / HTTP/1.1\r\nHost: ejemplo.test\r\n\r\n"}],
                       ensure_ascii=False).encode()
    enc = base64.b64encode(_aes_cbc_encrypt(CATALOG_KEY, bytes(16), plain)).decode()
    dec = decode_catalog(enc)
    check("Catálogo sintético round-trip", dec[0]["name"] == "prueba" and "ejemplo.test" in dec[0]["config_payload"])
    # Enlace vpn:// sintético.
    profile = {"id": 7, "name": "perfil prueba", "mode": "SSL_DIRECT",
               "server": {"host": "ejemplo.test", "port": 443}}
    link = "vpn://" + base64.b64encode(json.dumps(profile, ensure_ascii=False).encode()).decode()
    check("Enlace vpn:// round-trip", decode_link(link) == profile)
    check("decode() detecta enlace", decode(link) == profile)
    # Miembro como cadena JSON (forma que devuelve el servidor en layout/texts).
    doc = _json(decrypt_catalog_text(enc))
    check("Miembro cadena JSON", isinstance(doc, list) and isinstance(doc[0], dict))
    # Errores honestos.
    try:
        decode_catalog("!!!no-base64!!!")
        check("Base64 inválido rechazado", False)
    except DecodeError:
        check("Base64 inválido rechazado", True)
    try:
        decode_catalog(base64.b64encode(b"\x00" * 32).decode())
        check("Cifrado con padding inválido rechazado", False)
    except DecodeError:
        check("Cifrado con padding inválido rechazado", True)
    try:
        decode_link("https://ejemplo.test/x")
        check("Enlace sin vpn:// rechazado", False)
    except DecodeError:
        check("Enlace sin vpn:// rechazado", True)
    print(f"SELF-TEST: TODO OK ({ok} pruebas)")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, help="Respuesta cifrada o enlace guardado en texto")
    source.add_argument("--link", help="Enlace vpn:// completo")
    source.add_argument("--url", nargs="?", const=CATALOG_URL, help="Descarga explícita; por defecto el endpoint del APK")
    source.add_argument("--self-test", action="store_true", help="Pruebas locales sin red")
    parser.add_argument("--kind", choices=UPDATE_KINDS, default="catalog", help="catalog: servidores; layout/texts: interfaz")
    auth = parser.add_mutually_exclusive_group()
    auth.add_argument("--credentials-file", type=Path, help="credentials.json original; usa user_id para la actualización normal")
    auth.add_argument("--request-id-file", type=Path, help="Identificador explícito UTF-8 para dtunnel-token")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; por defecto stdout")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if (args.credentials_file or args.request_id_file) and args.url is None:
        parser.error("Los identificadores se usan solamente con --url.")
    try:
        if args.url is not None:
            if args.credentials_file:
                credentials = _json(_text(_read(args.credentials_file, 16384)))
                request_id = credentials.get("user_id") if isinstance(credentials, dict) else None
            elif args.request_id_file:
                request_id = _read(args.request_id_file, 514).decode("utf-8").removesuffix("\n").removesuffix("\r")
            else:
                request_id = DEFAULT_REQUEST_ID
            result = decode_catalog(fetch_catalog(args.url, request_id, kind=args.kind), kind=args.kind)
        elif args.link is not None:
            result = decode_link(args.link)
        else:
            result = decode(_read(args.file, MAX_BYTES), kind=args.kind)
        rendered = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        _summarize(result, args.kind)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    except UnicodeError:
        print(json.dumps({"error": "FORMAT_ERROR", "message": "El identificador no es UTF-8 válido."}), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
