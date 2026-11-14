#!/usr/bin/env python3
"""Rev Hunter 48 (com.hunter.net): .rev and .custom config files.

Standalone Python 3.10+, standard library only, no network access.
For catalogs use Hunter_VPN.py. The TSH1 decoder lives in Hunter_VPN.py
(same folder); this script imports it so the crypto is not duplicated.

File formats (ConfigImportFileActivity; manifest intent VIEW, schemes
content/file, pathPattern .*\\.rev and .*\\.custom; no custom text/link
URI scheme is registered):

  * .rev  — the same TSH1 envelope as the catalog (Base64 -> Base91 ->
    TSH1 -> ChaCha / xoshiro S-box / RC4 / nibble / dk.d -> gzip -> JSON).
    The app only accepts it when the JSON "AppVersion" equals the app
    versionCode (48) and "Version" is newer than the stored one; this
    decoder returns the JSON without enforcing that check.
  * .custom — Base64 -> UTF-8 JSON. Fields the app reads (k()):
    "method" (int 0-3, also stored as the "method" pref key) plus
    LIAPP-obfuscated server keys (returned as-is), and the cleartext
    "CUSTOM_AUTH" (bool), "USUARIO_CUSTOM" and "SENHA_CUSTOM" (only when
    CUSTOM_AUTH is true). Protections are checked by the app AFTER
    decoding; they are not part of the format.

No .sks files: the app has no .sks support.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from pathlib import Path

MAX_BYTES = 32 * 1024 * 1024

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from Hunter_VPN import DecodeError, decode as _decode_tsh1
except ImportError as exc:  # pragma: no cover
    raise SystemExit("Hunter_VPN_archivos.py needs Hunter_VPN.py in the same folder.") from exc


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


def _decode_custom(data: bytes | str) -> dict:
    """Base64 -> UTF-8 JSON (.custom)."""
    text = _text(data)
    compact = re.sub(r"[ \t\r\n]", "", text)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) or len(compact) % 4 == 1:
        raise DecodeError("FORMAT_ERROR", "Se esperaba Base64 estándar (.custom).")
    try:
        raw = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("FORMAT_ERROR", "El archivo .custom no es Base64 válido.") from exc
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise DecodeError("FORMAT_ERROR", "El archivo .custom no es JSON válido.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("FORMAT_ERROR", "El archivo .custom no es un objeto JSON.")
    return doc


def _sniff(data: bytes | str) -> str:
    """'rev' for a TSH1 envelope, 'custom' for Base64 JSON, else error."""
    text = _text(data)
    compact = re.sub(r"[ \t\r\n]", "", text)
    # A .custom file is Base64 whose payload starts with '{'.
    try:
        raw = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except (binascii.Error, ValueError):
        raw = b""
    if raw[:1] == b"{":
        return "custom"
    # A .rev file is Base64 whose Base91-decoded payload starts with TSH1.
    try:
        from Hunter_VPN import _b91_decode, _base64
        if _b91_decode(_base64(text).decode("utf-8"))[:4] == b"TSH1":
            return "rev"
    except (DecodeError, UnicodeError):
        pass
    raise DecodeError("FORMAT_ERROR", "No es un archivo .rev (TSH1) ni .custom válido.")


def decode(data: bytes | str) -> dict:
    """Offline API: decode a .rev (TSH1) or .custom file to its JSON."""
    kind = _sniff(data)
    if kind == "custom":
        return _decode_custom(data)
    return _decode_tsh1(data)


def run(file_bytes: bytes | str) -> str | None:
    """Offline API: file JSON or None; never a partial result."""
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


def _self_test() -> int:
    failures = []

    def check(name: str, cond: bool) -> None:
        print(("ok  " if cond else "FAIL") + f" {name}")
        if not cond:
            failures.append(name)

    # 1. .rev round-trip via the TSH1 encryptor (Hunter_VPN._encrypt_tsh1).
    from Hunter_VPN import _encrypt_tsh1
    obj = {
        "Version": "9.9.9", "AppVersion": "48",
        "Servers": [{"Name": "TEST 01", "ServerIP": "1.2.3.4", "ServerPort": 443}],
        "Networks": [{"Name": "TEST PAYLOAD", "Payload": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "Modo": "Proxy"}],
        "NetworksAuto": [], "ReleaseNotes": None,
    }
    blob = _encrypt_tsh1(obj, salt=b"\x01" * 16, nonce=b"\x02" * 12)
    check("rev round-trip", decode(blob) == obj)
    check("rev sniff", _sniff(blob) == "rev")
    # 2. .custom round-trip.
    custom = {"method": 1, "CUSTOM_AUTH": True, "USUARIO_CUSTOM": "usuario",
              "SENHA_CUSTOM": "clave", "server": "1.2.3.4"}
    custom_blob = base64.b64encode(
        json.dumps(custom, ensure_ascii=False).encode("utf-8")).decode()
    check("custom round-trip", decode(custom_blob) == custom)
    check("custom sniff", _sniff(custom_blob) == "custom")
    # 3. .custom without auth fields.
    custom2 = {"method": 0, "CUSTOM_AUTH": False}
    custom2_blob = base64.b64encode(json.dumps(custom2).encode()).decode()
    check("custom no-auth", decode(custom2_blob) == custom2)
    # 4. Bad input fails cleanly. ('e30=' is Base64 for '{}', a valid
    #    if empty .custom object, so it decodes to {} instead of failing.)
    check("custom empty object", decode("e30=") == {})
    for bad in ("", "AAAA", "not base64!!!"):
        try:
            decode(bad)
            check(f"reject {bad!r}", False)
        except DecodeError:
            check(f"reject {bad!r}", True)
    print("self-test: all checks passed" if not failures else f"self-test: {len(failures)} failure(s)")
    return 1 if failures else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, help="Archivo .rev o .custom")
    source.add_argument("--self-test", action="store_true", help="Pruebas internas (sin red)")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON; por defecto stdout")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
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
