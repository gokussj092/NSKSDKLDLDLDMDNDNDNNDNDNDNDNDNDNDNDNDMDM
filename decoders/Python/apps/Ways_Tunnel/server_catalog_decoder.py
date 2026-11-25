#!/usr/bin/env python3
"""Ways Tunnel 18.1 (18) live catalog: download or open an offline copy.

Thin worker adapter over the original decoder in ``waystunnel.py``
(kept verbatim): the live ``config.json`` is glyph text
(640 glyphs -> 320 bytes of Base64 per block in the general case)
decrypted with AES-256-CBC, key SHA-256 of the upper-case hex of the
app password, zero IV, PKCS#7 (see ``waystunnel.py`` and the dossier
``analysis/com.ways.tunnel/18/``).

This module exposes the contract the repo uses:

* ``decode_catalog(data: bytes) -> dict`` — decrypt the glyph body
  and return ONLY the redacted catalog shape already published in
  ``~/workspace/catalogs/waystunnel/catalog.json`` (``Version``,
  ``ReleaseNotes``, ``Servers``, ``Networks``), whitelisting
  per-server and per-network fields. Dropped on purpose: the whole
  ``WhatsApp`` invite key, and every credential-bearing field
  (``ServerIP``, ``ServerUser``, ``ServerPass``, ``ProxyIP``,
  ``SlowChave``, ``TokenAuth``, ``NameServer``, ``udpserver``,
  ``udpobfs``, ``udpauth``, ``OpenVPNConfig``, ``v2rayJson`` on
  servers; ``SlowDns``, ``OpenVPNConfig``, ``v2rayJson`` on
  networks). The result JSON carries NO download API: the endpoint
  lives in ``waystunnel.py`` (and README/TESTING), never in the
  result.
* ``render(doc) -> str`` — the redacted document as JSON text.
* ``run(data: bytes) -> str`` — the C8 catalog-bridge entry point
  (``cloud/workers/python/catalog_vpn_bridge.py`` calls ``run``).

This module ships NO ``file_decoder.py`` on purpose: the app
registers no file suffix and imports no configuration files
(manifest + code reviewed), like the catalog-only WinzapVPN
precedent. Text links (``wyst://``) live in ``text_decoder.py``.

Live catalog verified 2026-11-24: HTTP 200, 276,225 UTF-8 bytes
(92,800 glyphs) -> 36,007 B JSON, SHA-256
``468725bbef20019fbd48d84b0029e5912ee30df8518b428413b5202305aa7b10``,
version 1.0.49, 5 servers, 78 networks; the decrypted bytes are
byte-identical to the stored live copy. No premium catalog exists:
v1.0.49 carries no VIP/premium field and the app downloads this
single ``config.json`` (see ``waystunnel.py`` docstring).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__:
    from .waystunnel import CATALOG_URL, decode_config, download_catalog_raw
else:
    from waystunnel import CATALOG_URL, decode_config, download_catalog_raw

MAX_BYTES = 8 * 1024 * 1024

APP_NAME = "Ways Tunnel"
PACKAGE = "com.ways.tunnel"
VERSION = "18.1"
VERSION_CODE = 18

# Whitelisted result fields: exactly the redacted catalog shape in
# ~/workspace/catalogs/waystunnel/catalog.json. Anything else the
# live catalog carries (credentials, tokens, invite links) is
# dropped, never served.
_SERVER_FIELDS = {
    "Flag": str, "MyServer": str, "Name": str, "ProxyPort": str,
    "SSLPort": str, "ServerPort": str, "supportedProtocol": str,
    "udpbuffer": str, "udpdown": str, "udpup": str,
}
_NETWORK_FIELDS = {
    "DownSlot": str, "Flag": str, "Modo": str, "MyServer": str,
    "Name": str, "Payload": str, "SNI": str, "UpSlot": str,
}


class DecodeError(ValueError):
    pass


def _unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise DecodeError("JSON ambiguo.")
        out[key] = value
    return out


def _invalid_constant(value):
    raise DecodeError("Constante JSON inválida.")


def _whitelist(record, fields):
    """Copy only whitelisted string fields; drop the rest."""
    if not isinstance(record, dict):
        raise DecodeError("Registro de catálogo inválido.")
    out = {}
    for name, kind in fields.items():
        if name not in record:
            continue
        value = record[name]
        if kind is str and isinstance(value, str):
            out[name] = value
    return out


def decode_catalog(data: bytes) -> dict:
    """Decrypt a glyph-text catalog body; return the redacted catalog."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Entrada vacía o superior a 8 MiB.")
    if data.lstrip().startswith(b"<"):
        raise DecodeError("Respuesta remota inválida (HTML).")
    try:
        text = data.decode("utf-8-sig").strip()
    except UnicodeError:
        raise DecodeError("Catálogo no UTF-8.") from None
    if not text:
        raise DecodeError("Catálogo vacío.")
    try:
        plain = decode_config(text)
    except ValueError:
        raise DecodeError(
            "Catálogo inválido o incompatible con Ways Tunnel 18.1."
        ) from None
    try:
        doc = json.loads(plain, object_pairs_hook=_unique,
                         parse_constant=_invalid_constant)
    except DecodeError:
        raise
    except ValueError:
        raise DecodeError("Catálogo descifrado sin JSON válido.") from None
    if not isinstance(doc, dict):
        raise DecodeError("Catálogo sin JSON válido.")
    version = doc.get("Version")
    if not isinstance(version, str) or not version:
        raise DecodeError("Falta Version en el catálogo.")
    servers = doc.get("Servers")
    if not isinstance(servers, list) or not servers:
        raise DecodeError("Faltan servidores en el catálogo.")
    networks = doc.get("Networks")
    if not isinstance(networks, list) or not networks:
        raise DecodeError("Faltan networks en el catálogo.")
    out = {"Version": version}
    notes = doc.get("ReleaseNotes")
    if isinstance(notes, str):
        out["ReleaseNotes"] = notes
    out["Servers"] = [_whitelist(row, _SERVER_FIELDS) for row in servers]
    out["Networks"] = [_whitelist(row, _NETWORK_FIELDS) for row in networks]
    for row in out["Servers"]:
        if not isinstance(row.get("Name"), str) or not row["Name"]:
            raise DecodeError("Servidor sin Name en el catálogo.")
    for row in out["Networks"]:
        if not isinstance(row.get("Name"), str) or not row["Name"]:
            raise DecodeError("Network sin Name en el catálogo.")
    return out


def render(doc) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


def run(data: bytes) -> str:
    return render(decode_catalog(data))


def download() -> bytes:
    # Plain GET + ?t=<millis>, timeout 15 s, exactly like the app
    # (waystunnel.download_catalog_raw). No headers, no auth.
    try:
        raw = download_catalog_raw()
    except Exception:
        raise DecodeError("No se pudo descargar el catálogo autorizado.") from None
    data = raw.encode("utf-8")
    if not data or len(data) > MAX_BYTES or data.lstrip().startswith(b"<"):
        raise DecodeError("Catálogo remoto vacío o incompatible.")
    return data


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    modes = p.add_mutually_exclusive_group()
    modes.add_argument("file", nargs="?", type=Path)
    modes.add_argument("--stdin", action="store_true")
    modes.add_argument("--download", action="store_true",
                       help="Descargar el catálogo vivo fijo (predeterminado)")
    a = p.parse_args()
    try:
        if a.file:
            with a.file.open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        elif a.stdin:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            data = download()
        sys.stdout.write(run(data))
        return 0
    except (OSError, ValueError):
        print("No se pudo leer el catálogo completo de Ways Tunnel.",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
