#!/usr/bin/env python3
"""Aura Net VPN AuraNet_v9 (19): catálogo y perfiles, sin root ni APK.

Standalone Python 3.10+; pip install argon2-cffi pycryptodome.
Only download()/the explicit CLI remote path access the fixed official source.
"""
from __future__ import annotations

import argparse
import base64
import json
import math
import os
from pathlib import Path
import re
import sys
from urllib.request import HTTPRedirectHandler, Request, build_opener

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES

MAX_BYTES = 8 * 1024 * 1024
MAX_FIELDS = 8192
# Constants in the provided build's Go Encrypt/decrypt and EO/DO respectively.
EXPORT_SECRET = b"mcW2R5coCkQCDQWnM7iHIpSrs16ZeCaE"
FIELD_SECRET = b"0wwSloVh9DWgmXVNMBkwDRnjVJJgkAgo"
SOURCE = "https://strongteam.co/api/kidvpn/v4/aurav1.txt"
USER_AGENT = "Aura Net VPN"
PROTECTED_FIELDS = frozenset({
    "DefOVPNUser", "DefOVPNPass", "HysteriaUser", "HysteriaOBFS", "DefaultOVPNCert",
    "ServerIPHost", "OVPNUser", "OVPNPass", "UDP_obfs", "UDP_user", "CustomCertificate",
    "SlowDNSHost", "SlowDNSKey", "V2rayUUID", "H2pass", "TrojanPass", "V2rayPath",
    "Payload", "CustomProxy", "SNI", "V2rayConfig", "BugDNS", "V2rayAddress",
    "V2rayHost", "V2raySNI", "Info", "URI",
})


class DecodeError(ValueError):
    pass


class EnvelopeError(DecodeError):
    """No supported authenticated envelope was opened; legacy may be tried."""


def input_text(data: bytes) -> str:
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("INVALID_INPUT")
    try:
        value = data.decode("utf-8-sig").strip()
    except UnicodeError as exc:
        raise DecodeError("INVALID_UTF8") from exc
    if not value:
        raise DecodeError("INVALID_INPUT")
    return value


def render(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, allow_nan=False)


def _pairs(items):
    obj = {}
    for key, value in items:
        if key in obj:
            raise DecodeError("DUPLICATE_JSON_KEY")
        obj[key] = value
    return obj


def parse_document(text):
    def invalid(_):
        raise DecodeError("INVALID_JSON")
    try:
        obj = json.loads(text, object_pairs_hook=_pairs, parse_constant=invalid)
        if not isinstance(obj, dict):
            raise DecodeError("INVALID_DOCUMENT")
        # Reject nonfinite numbers, escaped lone surrogates and extreme nesting.
        render(obj).encode("utf-8")
        return obj
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("INVALID_DOCUMENT") from exc


def open_envelope(text: str, *, exported=False) -> str:
    if not isinstance(text, str) or len(text) > MAX_BYTES:
        raise EnvelopeError("INVALID_ENVELOPE")
    if exported:
        # Go Encrypt inserts one ASCII letter at index 3 after Base64 encoding.
        if len(text) < 4 or text[3] not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ":
            raise EnvelopeError("INVALID_EXPORT_MARKER")
        text = text[:3] + text[4:]
    try:
        raw = base64.b64decode(text.replace("\r", "").replace("\n", ""), validate=True)
        if not 44 <= len(raw) <= MAX_BYTES:
            raise ValueError
        salt = raw[:16]
        key = hash_secret_raw(EXPORT_SECRET if exported else FIELD_SECRET, salt,
                              time_cost=3, memory_cost=8192, parallelism=1,
                              hash_len=32, type=Type.ID, version=19)
        cipher = AES.new(key, AES.MODE_GCM, nonce=raw[16:28])
        cipher.update(salt)
        clear = cipher.decrypt_and_verify(raw[28:-16], raw[-16:])
    except ValueError as exc:
        raise EnvelopeError("INVALID_AUTHENTICATED_ENVELOPE") from exc
    # Authenticated invalid UTF-8 is a document error, never a legacy fallback.
    try:
        return clear.decode("utf-8")
    except UnicodeError as exc:
        raise DecodeError("INVALID_DOCUMENT") from exc


def open_document(data: bytes):
    text = input_text(data)
    if text.startswith("{"):
        return parse_document(text)
    # The exported-file and remote wrappers use Encrypt; the asset uses EO.
    try:
        clear = open_envelope(text, exported=True)
    except EnvelopeError:
        clear = open_envelope(text)
    return parse_document(clear)


def decode_fields(obj):
    # Request-local cache: no recovered values survive this document.
    cache = {}
    nodes = 0

    def walk(value, key="", depth=0):
        nonlocal nodes
        nodes += 1
        if depth > 48 or nodes > 200000:
            raise DecodeError("JSON_LIMIT")
        if isinstance(value, dict):
            return {k: walk(v, k, depth+1) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v, "", depth+1) for v in value]
        if isinstance(value, float) and not math.isfinite(value):
            raise DecodeError("INVALID_JSON")
        if isinstance(value, str) and key in PROTECTED_FIELDS:
            packed = value.replace("\r", "").replace("\n", "")
            if len(packed) >= 60 and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", packed):
                if packed not in cache:
                    if len(cache) >= MAX_FIELDS:
                        raise DecodeError("FIELD_LIMIT")
                    cache[packed] = open_envelope(value)
                return cache[packed]
        return value

    return walk(obj)


def profile_document(obj):
    if not all(isinstance(obj.get(key), str) for key in ("Name", "TunnelType")):
        raise DecodeError("INVALID_AURA_PROFILE")
    return decode_fields(obj)


def decode_file(data: bytes):
    return profile_document(open_document(data))


def decode_catalog(data: bytes):
    obj = open_document(data)
    if (not isinstance(obj.get("Version"), str) or not obj["Version"] or
            not all(isinstance(obj.get(key), list) for key in ("Servers", "Networks")) or
            any(not isinstance(item, dict) for key in ("Servers", "Networks") for item in obj[key])):
        raise DecodeError("INVALID_AURA_CATALOG")
    return decode_fields(obj)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise DecodeError("REMOTE_REDIRECT_REJECTED")


def download():
    request = Request(SOURCE, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"})
    try:
        with build_opener(_NoRedirect()).open(request, timeout=25) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise DecodeError("INVALID_REMOTE_RESPONSE")
            data = response.read(MAX_BYTES+1)
    except OSError as exc:
        raise DecodeError("REMOTE_UNAVAILABLE") from exc
    if not data or len(data) > MAX_BYTES:
        raise DecodeError("INVALID_REMOTE_SIZE")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sources = parser.add_mutually_exclusive_group()
    sources.add_argument("--input", type=Path, help="Catálogo local cifrado")
    sources.add_argument("--file", type=Path, help="Perfil .aura de AuraNet_v9")
    sources.add_argument("--stdin", action="store_true", help="Catálogo cifrado por stdin")
    parser.add_argument("--summary", action="store_true", help="Solo recuentos del catálogo")
    parser.add_argument("--output", type=Path, help="JSON completo, archivo 0600 sin sobrescritura")
    args = parser.parse_args()
    try:
        if args.file is not None and args.summary:
            raise DecodeError("SUMMARY_REQUIRES_CATALOG")
        remote = args.file is None and args.input is None and not args.stdin
        path = args.input if args.input is not None else args.file
        if path is not None:
            with path.open("rb") as stream:
                data = stream.read(MAX_BYTES+1)
        elif args.stdin:
            data = sys.stdin.buffer.read(MAX_BYTES+1)
        else:
            data = download()
        obj = decode_file(data) if args.file is not None else decode_catalog(data)
        if args.summary:
            obj = {"provider": "aura-net-vpn", "version": obj["Version"],
                   "servers": len(obj["Servers"]), "networks": len(obj["Networks"]), "complete": True}
        result = render(obj).encode("utf-8")
        output = args.output or (Path("aura_net_catalogo.json") if remote and not args.summary else None)
        if output:
            fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(result)
            print(f"Guardado: {output}")
        else:
            sys.stdout.buffer.write(result)
        return 0
    except (ValueError, OSError, RecursionError):
        print("No se pudo leer Aura Net completo o guardar el resultado; comprueba conexión, entrada y destino.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
