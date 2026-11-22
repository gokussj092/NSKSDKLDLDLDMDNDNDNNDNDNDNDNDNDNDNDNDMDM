#!/usr/bin/env python3
"""AM Tunnel Lite (app.vpn.amtunnellite) 63 ("AM") — files for SP-DECODE.

Adapted from the dossier deliverable ``amtunnel_files.py`` (analysis
``app.vpn.amtunnellite/63/``); same formats and behaviour, no rewrite.
The XXTEA primitive is imported from ``codec.py`` (same module, same
key ``'...|...'`` and non-standard delta ``0x9E5729B1``) instead of
being duplicated here.

File formats the app actually uses (verified in the APK; no .sks):

1. pdrv2.json (local copy of the catalog, in the phone's filesDir)
   Contents: the same body as the remote catalog (Base64 -> XXTEA with
   the static key '...|...' -> JSON UTF-8). The app writes it in
   LQf.run() after downloading the catalog and reads it on startup.
   This module decrypts it from a local file; the ``pdtv2`` suffix is
   registered in ``_C8_FILE_ENGINES`` (``engine.py``) for that route.

2. assets/wg/am*.conf (1,000 files EMBEDDED in the APK, WireGuard)
   No section headers; exactly three keys per file:
     Endpoint = <IPv4 without port>
     Hash1    = Base64 of 32 bytes
     Hash2    = Base64 of 32 bytes
   The app's WG service reads them (literal 'wg/' in LI70::C). They
   are internal assets, not an import format; the parser is exposed
   here for direct/CLI use only and has no registered suffix.

There is NO user import format in this version:
  - The manifest declares no file import intent-filter, no URL scheme
    of its own (only generic Firebase deep-links).
  - No file picker (ACTION_GET_CONTENT / ACTION_OPEN_DOCUMENT), no
    import-extension literals in the DEX.
  - No text scheme of its own: 'udp://...' are DNS options in the UI
    (LJY), not profile import links.
  So this module implements NO user profile import; it documents the
  two real formats the app reads.

Usage:
  python3 file_decoder.py pdrv2.json [--output cat.json]
  python3 file_decoder.py --wg am0001.conf [--json]
  python3 file_decoder.py --self-test
"""
from __future__ import annotations

import argparse
import base64
import binascii
import ipaddress
import json
import re
import sys
from pathlib import Path
if __package__:
    from .codec import DecodeError, MAX_BYTES, decode_catalog_b64, xxtea_decrypt, xxtea_encrypt
else:
    from codec import DecodeError, MAX_BYTES, decode_catalog_b64, xxtea_decrypt, xxtea_encrypt


# ------------------------------------------------------- pdrv2.json local
def decode_pdrv2_bytes(raw: bytes) -> dict:
    """Decrypt the contents of a pdrv2.json (Base64 -> XXTEA -> JSON)."""
    return decode_catalog_b64(raw)


def decode_pdrv2_file(path: str) -> dict:
    with open(path, "rb") as f:
        return decode_pdrv2_bytes(f.read())


# ------------------------------------------------------- wg am*.conf
_WG_KEYS = ("Endpoint", "Hash1", "Hash2")


def parse_wg_conf(text: str) -> dict:
    """Parse an embedded WireGuard .conf (Endpoint/Hash1/Hash2).

    Returns {'Endpoint': str (IPv4), 'Hash1': bytes (32 B),
    'Hash2': bytes (32 B)}. Raises ValueError on invalid format.
    """
    fields: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("[") or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("linea sin '=': %r" % line[:40])
        k, v = line.split("=", 1)
        fields[k.strip()] = v.strip()
    if tuple(sorted(fields)) != tuple(sorted(_WG_KEYS)):
        raise ValueError("claves inesperadas: %s" % sorted(fields))
    try:
        ipaddress.IPv4Address(fields["Endpoint"])
    except ValueError:
        raise ValueError("Endpoint no es IPv4: %r" % fields["Endpoint"][:40])
    out = {"Endpoint": fields["Endpoint"]}
    for key in ("Hash1", "Hash2"):
        try:
            raw = base64.b64decode(fields[key], validate=True)
        except binascii.Error:
            raise ValueError("%s no es Base64 estricto" % key)
        if len(raw) != 32:
            raise ValueError("%s decodifica a %d B, no 32" % (key, len(raw)))
        out[key] = raw
    return out


def parse_wg_conf_file(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return parse_wg_conf(f.read())


def run(data: bytes) -> str:
    """Decrypt a local ``pdrv2.json`` body and return the full catalog JSON.

    Accepts the raw file bytes (Base64 body, as the app stores it).
    Anything else — empty or oversize input, HTML, non-Base64 text,
    truncated XXTEA — is rejected with DecodeError.
    """
    if not isinstance(data, bytes) or not data:
        raise DecodeError("Archivo pdrv2.json vacio.")
    if len(data) > MAX_BYTES:
        raise DecodeError("El archivo supera el limite de tamano.")
    return json.dumps(decode_pdrv2_bytes(data), ensure_ascii=False, indent=2)


# ---------------------------------------------------------------- self-test
def self_test() -> int:
    print("AM Tunnel Lite (archivos) — self-test")
    ok = 0

    def check(name, cond):
        nonlocal ok
        print("  %s: %s" % ("ok" if cond else "FALLO", name))
        ok += bool(cond)

    # 1. Synthetic pdrv2: JSON -> XXTEA -> Base64 -> decode_pdrv2_bytes.
    doc = {"Version": "0.0", "Free_servers": [], "Payloads": [],
           "UpdaterLink": "", "UDPVersion": "v2", "Changelogs": "test"}
    blob = base64.b64encode(
        xxtea_encrypt(json.dumps(doc).encode("utf-8")))
    check("pdrv2 sintetico", decode_pdrv2_bytes(blob) == doc)
    # 2. Corrupt pdrv2 (valid Base64, invalid XXTEA) -> ValueError.
    try:
        decode_pdrv2_bytes(base64.b64encode(b"\x00" * 32))
        check("pdrv2 corrupto rechazado", False)
    except (ValueError, json.JSONDecodeError):
        check("pdrv2 corrupto rechazado", True)
    # 3. Valid synthetic wg .conf.
    h1 = base64.b64encode(bytes(range(32))).decode()
    h2 = base64.b64encode(bytes(range(32, 64))).decode()
    good = "Endpoint = 10.0.0.1\nHash1 = %s\nHash2 = %s\n" % (h1, h2)
    parsed = parse_wg_conf(good)
    check("wg .conf sintetico",
          parsed["Endpoint"] == "10.0.0.1"
          and parsed["Hash1"] == bytes(range(32))
          and parsed["Hash2"] == bytes(range(32, 64)))
    # 4. wg .conf with non-IPv4 Endpoint -> ValueError.
    try:
        parse_wg_conf("Endpoint = not-an-ip\nHash1 = %s\nHash2 = %s\n" % (h1, h2))
        check("wg Endpoint invalido rechazado", False)
    except ValueError:
        check("wg Endpoint invalido rechazado", True)
    # 5. wg .conf with short Hash -> ValueError.
    try:
        parse_wg_conf("Endpoint = 10.0.0.1\nHash1 = %s\nHash2 = %s\n"
                      % (base64.b64encode(b"short").decode(), h2))
        check("wg Hash corto rechazado", False)
    except ValueError:
        check("wg Hash corto rechazado", True)
    # 6. wg .conf with extra key -> ValueError.
    try:
        parse_wg_conf(good + "Extra = x\n")
        check("wg clave extra rechazada", False)
    except ValueError:
        check("wg clave extra rechazada", True)
    print("SELF-TEST OK (%d comprobaciones)" % ok if ok == 6
          else "SELF-TEST FALLO (%d/6)" % ok)
    return 0 if ok == 6 else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="AM Tunnel Lite 63 — archivos para SP-DECODE")
    ap.add_argument("path", nargs="?",
                    help="archivo pdrv2.json local a descifrar")
    ap.add_argument("--wg", help="archivo wg am*.conf a parsear")
    ap.add_argument("--output", help="archivo donde guardar el JSON")
    ap.add_argument("--json", action="store_true",
                    help="imprimir el .conf parseado como JSON "
                         "(hashes en Base64)")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.wg:
        parsed = parse_wg_conf_file(args.wg)
        view = {"Endpoint": parsed["Endpoint"],
                "Hash1": base64.b64encode(parsed["Hash1"]).decode(),
                "Hash2": base64.b64encode(parsed["Hash2"]).decode()}
        print(json.dumps(view, indent=2) if args.json else
              "Endpoint: %s\nHash1: %d B\nHash2: %d B"
              % (parsed["Endpoint"], len(parsed["Hash1"]),
                 len(parsed["Hash2"])))
        return 0

    if not args.path:
        ap.error("falta el archivo pdrv2.json (o usa --wg / --self-test)")
    try:
        with open(args.path, "rb") as f:
            data = f.read(MAX_BYTES + 1)
        out = run(data)
    except (ValueError, OSError) as exc:
        print("No se pudo leer el pdrv2.json: %s" % exc, file=sys.stderr)
        return 1
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out + "\n")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
