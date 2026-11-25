#!/usr/bin/env python3
"""B SHIELD NET 2.9 `.bshield` files and `bshieldnet://` / `bshield://` links.

Explicit dispatch to the existing shared RENZ profile ``bshield``
via ``bshieldnet.py`` in this same directory (no new profile, no
new key material: the profile already lives in
``decoders/Python/renz.py``). The canonical routes already serve
these formats -- the frozen C0 file engine
(``docs/cloud/C0_FORMAT_MATRIX.csv``: ``bshield`` ->
``decoders/Python/renz.py``) and the generic RENZ text handler in
``cloud/workers/python/text_bridge.py`` (``HANDLERS`` includes
``decoders.Python.renz``) -- so this module is the app's explicit
file/text entry point for tests and for the documented route, not a
second decoder. It never invents a value: a payload that does not
open with the ``bshield`` profile is rejected.
"""
from pathlib import Path
import argparse
import json
import sys
if __package__:
    from . import bshieldnet
    from .codec import DecodeError, MAX_BYTES
else:
    import bshieldnet
    from codec import DecodeError, MAX_BYTES

SCHEMES = ("bshieldnet://", "bshield://")


def run(data: bytes) -> str:
    """Decrypt a bare `.bshield` payload, or one carrying a scheme prefix.

    Accepts bytes that are a bare payload or that start with
    ``bshieldnet://`` / ``bshield://`` (case-insensitive). Anything
    else -- empty or oversize input, non-UTF-8 bytes, another scheme,
    garbage -- is rejected with DecodeError.
    """
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError('Perfil vacío o superior a 8 MiB.')
    try:
        text = data.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise DecodeError('Perfil B SHIELD NET inválido.') from None
    if not text:
        raise DecodeError('Perfil B SHIELD NET inválido.')
    if "://" in text:
        prefix, _, payload = text.partition("://")
        if prefix.lower() + "://" not in SCHEMES:
            raise DecodeError('Perfil B SHIELD NET inválido.')
    else:
        payload = text
    try:
        config = bshieldnet._decode_payload(payload)
    except bshieldnet.DecodeError:
        raise DecodeError('Perfil B SHIELD NET inválido.') from None
    return json.dumps({"application": "RENZ / BSHIELD", "extension": ".bshield",
                       "config": config}, ensure_ascii=False, indent=2)


def decode_text(text: str) -> str | None:
    """Decrypt a `bshieldnet://` / `bshield://` link (case-insensitive scheme).

    Returns the JSON document, or None when the text is not a B SHIELD
    link, the payload is empty, or decryption fails -- so the text
    bridge keeps looking (or, for these unambiguous schemes, treats
    None as final).
    """
    if not isinstance(text, str):
        return None
    value = text.strip()
    if not value.lower().startswith(SCHEMES):
        return None
    try:
        config = bshieldnet._decode_payload(value.split("://", 1)[1])
    except (bshieldnet.DecodeError, IndexError):
        return None
    if config is None:
        return None
    scheme = value.split("://", 1)[0].lower() + "://"
    return json.dumps({"application": "RENZ / BSHIELD", "protocol": scheme,
                       "config": config}, ensure_ascii=False, indent=2)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('file', nargs='?', type=Path)
    a = p.parse_args()
    try:
        if a.file:
            with a.file.open('rb') as stream:
                data = stream.read(MAX_BYTES + 1)
        else:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        sys.stdout.write(run(data))
        return 0
    except (ValueError, OSError):
        print('No se pudo leer el perfil B SHIELD NET.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
