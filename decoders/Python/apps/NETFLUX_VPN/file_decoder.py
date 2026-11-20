#!/usr/bin/env python3
"""NetFlux VPN 1.1 `.netflux` files and `netfluxvpn://` links.

Explicit dispatch to the existing shared RENZ profile ``gcpvpn``
(same key material, same live catalog as GCP VPN). NO ``netflux``
profile is registered in ``decoders/Python/renz.py`` -- a server-side
update must not touch the APK -- so the canonical
``renz.decode_file(data, '.netflux')`` / ``renz.decode_text(link)``
route cannot serve this format and is NOT used here. If the NetFlux
and GCP blobs ever diverge, that is a separate decision to take
then. NetFlux stays online-only, with no offline port, like GCP VPN.
"""
from pathlib import Path
import argparse
import json
import sys
if __package__:
    from .codec import DecodeError, MAX_BYTES, shared
else:
    from codec import DecodeError, MAX_BYTES, shared

SCHEME = "netfluxvpn://"


def _decode_payload(payload: str):
    """Decrypt one bare payload with the shared ``gcpvpn`` profile.

    Returns the already recursively-decrypted config, or None.
    """
    if not payload or not payload.strip():
        return None
    return shared._decode_config(payload.strip(), "gcpvpn")


def run(data: bytes) -> str:
    """Decrypt a bare `.netflux` payload, or one carrying the scheme prefix.

    Accepts bytes that are a bare payload or that start with
    ``netfluxvpn://`` (case-insensitive). Anything else -- empty or
    oversize input, non-UTF-8 bytes, another scheme, garbage -- is
    rejected with DecodeError.
    """
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError('Perfil vacío o superior a 8 MiB.')
    try:
        text = data.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise DecodeError('Perfil NetFlux VPN inválido.') from None
    if not text:
        raise DecodeError('Perfil NetFlux VPN inválido.')
    if "://" in text:
        prefix, _, payload = text.partition("://")
        if prefix.lower() + "://" != SCHEME:
            raise DecodeError('Perfil NetFlux VPN inválido.')
    else:
        payload = text
    config = _decode_payload(payload)
    if config is None:
        raise DecodeError('Perfil NetFlux VPN inválido.')
    return json.dumps({"application": "RENZ / NETFLUX", "extension": ".netflux",
                       "config": config}, ensure_ascii=False, indent=2)


def decode_text(text: str) -> str | None:
    """Decrypt a `netfluxvpn://` link (case-insensitive scheme).

    Returns the JSON document, or None when the text is not a
    `netfluxvpn://` link, the payload is empty, or decryption fails --
    so the text bridge keeps looking (or, for this unambiguous scheme,
    treats None as final).
    """
    if not isinstance(text, str):
        return None
    value = text.strip()
    if not value.lower().startswith(SCHEME):
        return None
    config = _decode_payload(value[len(SCHEME):])
    if config is None:
        return None
    return json.dumps({"application": "RENZ / NETFLUX", "protocol": SCHEME,
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
        print('No se pudo leer el perfil NetFlux VPN.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
