#!/usr/bin/env python3
"""CLI adapter: decode a ThaiVPN Connect ``profile.json`` file.

The app stores the same encrypted JSON as its live catalog in its
private file ``profile.json`` (Base64 + XXTEA, key "aluya20"; see
thaivpn.py). This adapter decodes such a file to JSON and can
re-encrypt a decoded catalog back into profile.json format
(``--encrypt``, round-trip verification only).

Contracts:

* ``decode(raw) -> dict`` — the decrypted catalog/profile dict.
* ``run(data: bytes) -> str`` — JSON document string.
* CLI: ``file_decoder.py <profile.json>`` prints one JSON document;
  exit 1 on failure.

ROUTING NOTE (deliberate, see README.md): this decoder is NOT wired
to ``cloud/workers/python/engine.py``. The file is literally named
``profile.json`` — its suffix is ``json`` — and registering a ``json``
engine would claim every ``.json`` file the user imports. The
supported live route is the catalog (server_catalog_decoder.py);
this file decoder ships for operator/manual use and for the
dossier's round-trip verification. No real exported profile.json
has been supplied yet (VERIFIED_SYNTHETIC by round-trip with the
live catalog).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__:
    from .thaivpn import (
        decode_catalog,
        decrypt_blob,
        encrypt_blob,
    )
else:
    from thaivpn import (
        decode_catalog,
        decrypt_blob,
        encrypt_blob,
    )

MAX_BYTES = 8 * 1024 * 1024


def decode(raw) -> dict:
    """Decrypt a profile.json (bytes/str, Base64 + XXTEA) -> dict."""
    if isinstance(raw, bytes):
        if not raw or len(raw) > MAX_BYTES:
            raise ValueError("archivo vacío o demasiado grande")
        try:
            text = raw.decode("utf-8-sig").strip()
        except UnicodeError:
            raise ValueError("profile.json no es texto UTF-8") from None
    elif isinstance(raw, str):
        text = raw.strip()
    else:
        raise ValueError("tipo de entrada no válido")
    if not text:
        raise ValueError("profile.json vacío")
    try:
        return decode_catalog(decrypt_blob(text))
    except (ValueError, TypeError):
        raise ValueError(
            "profile.json inválido o incompatible con ThaiVPN "
            "Connect 2.4.") from None


def run(data: bytes) -> str:
    """Decrypt profile.json bytes -> JSON document string."""
    return json.dumps(decode(data), ensure_ascii=False, indent=2)


def self_test() -> int:
    """Round-trip: synthetic catalog -> profile.json blob -> decode."""
    catalog = {
        "Version": "0.0-test",
        "Servers": [{"Name": "SYNTHETIC 01",
                     "ServerIP": "ZXhhbXBsZS5pbnZhbGlk",
                     "Username": "c3ludGhldGlj",
                     "Password": "c3ludGhldGlj"}],
        "Networks": [{"Name": "1.DIRECT"}],
    }
    blob = encrypt_blob(catalog)
    out = decode(blob)
    assert out["Version"] == "0.0-test", out
    assert out["Servers"][0]["ServerIP"] == "example.invalid", out
    assert out["Servers"][0]["Username"] == "synthetic", out
    for bad in ("", "AAAA", "!!!not-base64!!!"):
        try:
            decode(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"bad input must fail: {bad!r}")
    print("self-test OK: profile.json round-trip, truncated/garbage "
          "negatives")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path,
                        help="archivo profile.json")
    parser.add_argument("--encrypt", metavar="CATALOG.JSON",
                        help="cifrar un catálogo descifrado a "
                        "formato profile.json")
    parser.add_argument("--out", metavar="FILE",
                        help="escribir el resultado aquí")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    try:
        if args.encrypt:
            catalog = json.loads(Path(args.encrypt).read_text(
                encoding="utf-8"))
            blob = encrypt_blob(catalog)
            if args.out:
                Path(args.out).write_text(blob, encoding="utf-8")
            else:
                print(blob)
            return 0
        if args.file:
            data = args.file.read_bytes()
        else:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        text = run(data)
        if args.out:
            Path(args.out).write_text(text + "\n", encoding="utf-8")
        else:
            sys.stdout.write(text)
        return 0
    except (ValueError, OSError):
        print("No se pudo leer el profile.json de ThaiVPN Connect.",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
