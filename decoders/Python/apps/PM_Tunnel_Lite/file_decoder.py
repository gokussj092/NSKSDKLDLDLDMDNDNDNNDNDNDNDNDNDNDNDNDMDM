#!/usr/bin/env python3
"""PM Tunnel Lite 1.0 `.js` files, `custom_payload.json` and
`pmtunnellite://` links.

Standalone codec (see ``codec.py``): the key material differs from
every ``decoders/Python/renz.py`` profile, so NO profile is
registered in ``renz.py`` and the canonical ``renz.decode_file`` /
``renz.decode_text`` route cannot serve these formats and is NOT
used here. PM Tunnel Lite stays online-only, with no offline port,
like GCP/NETFLUX.

Formats the app itself reads and writes (all mode-0 encryption):

  .js catalog file  - picked with the in-app file picker: the whole
                      file is one Base64 string, mode-0 decrypted to
                      the same catalog JSON the remote update.js
                      carries. The app only accepts it if its
                      ``Version`` equals the stored catalog version.
                      The bundled fallback catalog (``res/ae/e.js``,
                      Version ``1.0``) is exactly this format.
  pmtunnellite://   - paste-only text link (no Android intent
                      filter): ``pmtunnellite://`` + Base64(mode-0
                      (JSON of ONE server entry)). Import checks
                      ``isSetExpiry``/``Expiry`` and ``isPinEnabled``.
                      No real link has been observed yet, so link
                      support is VERIFIED_SYNTHETIC (round-trip only).
  custom_payload.json - the app's custom-servers store: mode-0
                      encrypted JSON array of server entries.
  drlb (raw resource) - mode-3 encrypted DEX (anti-tamper). NOT a
                      user format: :func:`decode_drlb` below is a
                      diagnostic helper only and is never registered
                      anywhere.

DECISION (documented in full in ``status.md`` / ``hunks.md``): the
``.js`` suffix is NOT registered in ``file-formats.json`` nor in the
engine's ``_C8_FILE_ENGINES``. ``.js`` is a generic extension — the
file catalog dispatches purely by longest filename suffix with no
content detection, and the engine dispatches purely by suffix (content
predicates exist only for five shared suffixes) — so registering
``js`` would route EVERY ``.js`` upload to this decoder. The module
still implements ``.js`` decoding (``run`` / ``decode_js_*``) for
direct and CLI use; only the public file-format registration is
withheld. The text link IS registered (``pmtunnellite://`` is
unambiguous, and text suffixes need not be file suffixes).
"""
from pathlib import Path
import argparse
import json
import sys
if __package__:
    from .codec import (
        DecodeError, MAX_BYTES, dec_server_entry,
        decrypt_dex, decrypt_mode0, decode_catalog, encrypt_mode0,
    )
else:
    from codec import (
        DecodeError, MAX_BYTES, dec_server_entry,
        decrypt_dex, decrypt_mode0, decode_catalog, encrypt_mode0,
    )

SCHEME = "pmtunnellite://"
DEX_MAGIC = b"dex\n037\x00"


def _decrypt_outer_json(text: str):
    """Mode-0 decrypt one document -> parsed JSON (dict or list)."""
    try:
        parsed = json.loads(decrypt_mode0(text.strip()))
    except Exception:
        raise DecodeError("Documento PM Tunnel Lite inválido.") from None
    if not isinstance(parsed, (dict, list)):
        raise DecodeError("Documento PM Tunnel Lite inválido.")
    return parsed


def decode_js_text(text: str) -> dict:
    """Mode-0 decrypt a ``.js`` catalog document -> raw parsed dict."""
    parsed = _decrypt_outer_json(text)
    if not isinstance(parsed, dict):
        raise DecodeError("Documento .js inválido.")
    return parsed


def decode_js_file(path):
    with open(path, "r", encoding="utf-8") as fh:
        return decode_js_text(fh.read())


def encode_js_text(doc):
    """Inverse: catalog dict -> ``.js`` file contents (Base64, mode 0)."""
    raw = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
    return encrypt_mode0(raw.encode("utf-8")).decode("ascii")


def decode_custom_payload_text(text: str) -> list:
    """Mode-0 decrypt -> JSON array of (still encrypted) server entries."""
    parsed = _decrypt_outer_json(text)
    if not isinstance(parsed, list):
        raise DecodeError("custom_payload.json inválido.")
    return parsed


def decode_custom_payload_file(path):
    with open(path, "r", encoding="utf-8") as fh:
        return decode_custom_payload_text(fh.read())


def decode_link(text: str) -> dict:
    """Strip the scheme and mode-0 decrypt -> one raw server-entry dict.

    Field values are still encrypted here; use :func:`decode_text`
    for the fully decrypted entry.
    """
    value = text.strip()
    if not value.lower().startswith(SCHEME):
        raise DecodeError("not a %s link" % SCHEME)
    parsed = _decrypt_outer_json(value[len(SCHEME):])
    if not isinstance(parsed, dict):
        raise DecodeError("Enlace pmtunnellite:// inválido.")
    return parsed


def encode_link(server_entry):
    """Inverse: one server-entry dict -> ``pmtunnellite://`` link."""
    raw = json.dumps(server_entry, ensure_ascii=False,
                     separators=(",", ":"))
    return SCHEME + encrypt_mode0(raw.encode("utf-8")).decode("ascii")


def decode_drlb(data: bytes) -> bytes:
    """Mode-3 decrypt of the ``res/ae/drlb`` resource -> raw DEX bytes.

    Diagnostic only: the drlb DEX is an anti-tamper payload, not a
    user format, and is never registered as one.
    """
    try:
        dex = decrypt_dex(data)
    except Exception:
        raise DecodeError("drlb inválido.") from None
    if not dex.startswith(DEX_MAGIC):
        raise DecodeError("drlb did not decrypt to a DEX (magic %r)"
                         % dex[:8])
    return dex


def _render_config(config, extension=".js"):
    return json.dumps({"application": "PM Tunnel Lite",
                       "extension": extension,
                       "config": config}, ensure_ascii=False, indent=2)


def run(data: bytes) -> str:
    """Decrypt a ``.js`` catalog, a ``custom_payload.json`` array, or a
    payload carrying the ``pmtunnellite://`` scheme prefix.

    Accepts bytes that are a bare mode-0 document or that start with
    ``pmtunnellite://`` (case-insensitive). Anything else — empty or
    oversize input, non-UTF-8 bytes, another scheme, garbage — is
    rejected with DecodeError. Fields are fully decrypted (modes
    0/1/2); a catalog document keeps its Servers/Networks sections.
    """
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Perfil vacío o superior a 8 MiB.")
    try:
        text = data.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise DecodeError("Perfil PM Tunnel Lite inválido.") from None
    if not text:
        raise DecodeError("Perfil PM Tunnel Lite inválido.")
    if "://" in text:
        prefix, _, payload = text.partition("://")
        if prefix.lower() + "://" != SCHEME:
            raise DecodeError("Perfil PM Tunnel Lite inválido.")
        entry = decode_link(text)
        return _render_config(dec_server_entry(entry))
    parsed = _decrypt_outer_json(text)
    if isinstance(parsed, list):
        return _render_config(
            [dec_server_entry(item) for item in parsed
             if isinstance(item, dict)])
    if isinstance(parsed, dict) and "Servers" in parsed and "Networks" in parsed:
        return _render_config(
            decode_catalog(data), extension=".js")
    if isinstance(parsed, dict):
        return _render_config(dec_server_entry(parsed))
    raise DecodeError("Perfil PM Tunnel Lite inválido.")


def decode_text(text: str) -> str | None:
    """Decrypt a ``pmtunnellite://`` link (case-insensitive scheme).

    Returns the JSON document, or None when the text is not a
    ``pmtunnellite://`` link, the payload is empty, or decryption
    fails — so the text bridge keeps looking (or, for this unambiguous
    scheme, treats None as final).
    """
    if not isinstance(text, str):
        return None
    value = text.strip()
    if not value.lower().startswith(SCHEME):
        return None
    try:
        entry = decode_link(value)
    except DecodeError:
        return None
    try:
        config = dec_server_entry(entry)
    except DecodeError:
        return None
    return json.dumps({"application": "PM Tunnel Lite",
                       "protocol": SCHEME,
                       "config": config}, ensure_ascii=False, indent=2)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("file", nargs="?", type=Path)
    a = p.parse_args()
    try:
        if a.file:
            with a.file.open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        else:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        sys.stdout.write(run(data))
        return 0
    except (ValueError, OSError):
        print("No se pudo leer el perfil PM Tunnel Lite.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
