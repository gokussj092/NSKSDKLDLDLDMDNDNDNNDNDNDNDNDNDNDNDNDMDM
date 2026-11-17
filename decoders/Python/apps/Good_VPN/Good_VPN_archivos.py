#!/usr/bin/env python3
"""GOOD VPN (com.ovpnsevice.goodvpn, versionCode 30, versionName 3.0): cached catalog file (filesDir/profile.json).

Standalone Python 3.10+, standard library only, no network access.
For the live catalog use Good_VPN.py. GOOD VPN has no user file import
and no live custom text/link scheme (see README.md).

GOOD VPN does not import config files: the manifest has no VIEW
intent-filter for files, no activity handles ACTION_GET_CONTENT /
ACTION_OPEN_DOCUMENT, and the only file the app reads is its own cached
catalog, filesDir/profile.json. That file is written by ys case 2 with
od.g (XXTEA encrypt + Base64) and read back by xm0.a() with
an2.c(hc1.g(...)) — exactly the same encrypted format as the remote
catalog response. This script decodes that file (and any saved catalog
response) with the same algorithm:

  * Base64 (hand-rolled decoder hc1.g in the app; standard alphabet,
    newline-wrapped) -> XXTEA decrypt an2.c (delta 0x2E0BA747, key
    "goodvpn090529" from the native MainDetail.b() in libapi-good.so,
    zero-padded to 16 bytes, last-word length) -> JSON. The JSON is the
    full catalog document (Version, Message, Servers, Networks,
    setOpenVPN); the inner Base64 values of the fields the app decodes
    at use time (od.h) are decoded too, exactly like Good_VPN.py.
  * Encryption (od.g = an2.d + Base64) is implemented only for the
    --self-test round-trip; it mirrors the app's save path.
  * The format has no MAC; structural validation is not cryptographic
    authentication.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import math
import os
from pathlib import Path
import re
import struct
import sys

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
MASK = 0xFFFFFFFF
DELTA = 772515655  # XXTEA variant delta 0x2E0BA747 (an2.c / an2.d).
# Fixed format key from libapi-good.so (MainDetail.b), not an account
# credential. an2 pads/truncates it to 16 bytes with zeroes.
PROFILE_KEY = b"goodvpn090529"
# Catalog fields the app itself Base64-decodes at use time (od.h).
B64_FIELDS = frozenset({
    "ServerIP", "Username", "Password", "setOpenVPN", "V2Ray",
    "ServerDNS", "Cloudfront", "NameServer", "PublicKey", "UDPConfig",
    "Payload", "SquidProxy", "Sni",
})


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _text(data: bytes | str) -> str:
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


def _base64(text: str) -> bytes:
    compact = re.sub(r"\s+", "", text)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) or len(compact) % 4 == 1:
        raise DecodeError("FORMAT_ERROR", "Se esperaba Base64 estándar del archivo.")
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
        raise DecodeError("WRONG_DOCUMENT", "El documento debe contener un objeto JSON.")
    return _validate(doc)


def _mx(total, y, z, position, e, key):
    return (((total ^ y) + (key[(position & 3) ^ e] ^ z))
            ^ (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))) & MASK


def _words(data: bytes, include_length: bool) -> list[int]:
    count = (len(data) + 3) // 4
    values = [0] * (count + 1 if include_length else count)
    for i, byte in enumerate(data):
        values[i // 4] |= byte << ((i & 3) * 8)
    if include_length:
        values[-1] = len(data)
    return values


def _bytes_from_words(values, length: int | None) -> bytes:
    total = len(values) * 4
    if length is not None:
        total = length
    out = bytearray()
    for i in range(total):
        out.append((values[i // 4] >> ((i & 3) * 8)) & 0xFF)
    return bytes(out)


def decrypt_profile_bytes(data: bytes | str, *, key: bytes | None = None) -> bytes:
    """an2.c: Base64 -> XXTEA (last-word length) -> JSON bytes."""
    if key is None:
        key = PROFILE_KEY
    encrypted = _base64(_text(data))
    if len(encrypted) < 8 or len(encrypted) % 4:
        raise DecodeError("TRUNCATED", "El archivo no contiene palabras XXTEA completas.")
    values = list(struct.unpack("<" + "I" * (len(encrypted) // 4), encrypted))
    key = struct.unpack("<4I", key[:16].ljust(16, b"\0"))
    count = len(values)
    total = ((6 + 52 // count) * DELTA) & MASK
    y = values[0]
    while total:
        e = (total >> 2) & 3
        for position in range(count - 1, 0, -1):
            values[position] = (values[position] - _mx(total, y, values[position - 1], position, e, key)) & MASK
            y = values[position]
        values[0] = (values[0] - _mx(total, y, values[-1], 0, e, key)) & MASK
        y = values[0]
        total = (total - DELTA) & MASK
    length = values[-1]
    maximum = count * 4 - 4
    if not maximum - 3 <= length <= maximum:
        raise DecodeError("DECRYPT_FAILED", "La longitud interna XXTEA no es válida para esta aplicación.")
    return struct.pack("<" + "I" * (count - 1), *values[:-1])[:length]


def encrypt_profile_bytes(plain: bytes, *, key: bytes | None = None) -> bytes:
    """an2.d: XXTEA encrypt (appends the length as the last word)."""
    if key is None:
        key = PROFILE_KEY
    if not plain:
        return plain
    values = _words(plain, include_length=True)
    key = struct.unpack("<4I", key[:16].ljust(16, b"\0"))
    count = len(values)
    rounds = 6 + 52 // count
    total = 0
    z = values[-1]
    for _ in range(rounds):
        total = (total + DELTA) & MASK
        e = (total >> 2) & 3
        for position in range(count - 1):
            y = values[position + 1]
            values[position] = (values[position] + _mx(total, y, z, position, e, key)) & MASK
            z = values[position]
        y = values[0]
        values[-1] = (values[-1] + _mx(total, y, z, count - 1, e, key)) & MASK
        z = values[-1]
    return struct.pack("<" + "I" * count, *values)


def encrypt_profile_text(text: str) -> str:
    """od.g: XXTEA encrypt + Base64 (mirrors the app's save path)."""
    return base64.b64encode(encrypt_profile_bytes(text.encode("utf-8"))).decode("ascii")


def _try_b64(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 4 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) or len(compact) % 4 == 1:
        return None
    try:
        raw = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
        text = raw.decode("utf-8")
    except (ValueError, binascii.Error, UnicodeError):
        return None
    if not all(ch.isprintable() or ch in "\r\n\t" for ch in text):
        return None
    return text


def _decode_inner(doc: dict) -> list[str]:
    left = set()

    def walk(node):
        if isinstance(node, dict):
            for field, value in node.items():
                if isinstance(value, str) and field in B64_FIELDS and value.strip():
                    decoded = _try_b64(value)
                    if decoded is None:
                        left.add(field)
                    else:
                        node[field] = decoded
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(doc)
    return sorted(left)


def decode(data: bytes | str) -> dict:
    """Return the catalog document stored in profile.json, fully decoded."""
    doc = _json(decrypt_profile_bytes(data))
    if not any(field in doc for field in ("Servers", "Networks")):
        raise DecodeError("WRONG_DOCUMENT", "No hay listas de servidores o payloads en el archivo.")
    _decode_inner(doc)
    return doc


def run(file_bytes: bytes | str) -> str | None:
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


def _read(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def _write_output(path: Path, rendered: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, rendered.encode("utf-8"))
    finally:
        os.close(fd)


def _self_test() -> int:
    """Round-trip check (encrypt -> decrypt returns the input).

    Prints only pass/fail counts and field counts, never catalog values.
    Returns 0 when every synthetic document round-trips.
    """
    cases = [
        {"Version": "21.8", "Message": "Update", "Servers": [
            {"ServerName": "Thailand-01", "ServerFlag": "th",
             "ServerIP": "dGgxLmV4YW1wbGUuY29t\n", "Username": "dXNlcg==\n",
             "Password": "cGFzczA=\n", "TCPPort": "1194", "AutoLogIn": "true",
             "setOpenVPN": "Y2xpZW50CmRldiB0dW4K\n", "SelectType": "Default"}],
         "Networks": [
            {"PayloadName": "1_For_WiFi", "Payload": "R0VUIC8gSFRUUC8xLjEK\n",
             "SquidProxy": "d3d3LmV4YW1wbGUuY29t\n", "SquidPort": "80",
             "SelectedProtocal": "HTTP Proxy", "Protocal": "OVPN"}],
         "setOpenVPN": ""},
        {"Version": "1.0", "Servers": [], "Networks": []},
        {"Version": "2.5", "Message": "Café — ünïcode ✓", "Servers": [
            {"ServerName": "emoji \U0001F600", "ServerIP": "", "Username": ""}],
         "Networks": []},
    ]
    passed = 0
    for doc in cases:
        text = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
        encoded = encrypt_profile_text(text)
        expected = json.loads(text)
        _decode_inner(expected)  # decode() also decodes the inner values
        if decode(encoded) == expected:
            passed += 1
    print(json.dumps({"self_test": "pass" if passed == len(cases) else "fail",
                      "documents": len(cases), "passed": passed}, ensure_ascii=False))
    return 0 if passed == len(cases) else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, help="Archivo profile.json o respuesta del catálogo guardada")
    source.add_argument("--text", help="Contenido cifrado de un profile.json")
    source.add_argument("--self-test", action="store_true",
                        help="Round-trip sintético (cifrar -> descifrar); no usa archivos reales")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; no sobrescribe")
    parser.add_argument("--summary", action="store_true",
                        help="Solo claves y recuento de campos, sin valores descifrados")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    try:
        doc = decode(args.text if args.text is not None else _read(args.file))
        if args.summary:
            out = {"Version": doc.get("Version"), "sections": sorted(doc.keys())}
            for field in ("Servers", "Networks"):
                value = doc.get(field)
                out[field] = len(value) if isinstance(value, list) else None
            rendered = json.dumps(out, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        else:
            rendered = json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            _write_output(args.output, rendered)
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
