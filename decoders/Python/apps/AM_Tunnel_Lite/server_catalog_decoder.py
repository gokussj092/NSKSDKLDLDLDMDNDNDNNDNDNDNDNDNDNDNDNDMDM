#!/usr/bin/env python3
"""Download AM Tunnel Lite 63's fixed catalog or open an offline copy.

The catalog is the app's fixed updater file, fetched with a plain GET
carrying the app's own Android Chrome User-Agent and downloaded by
16 KiB ranges with resumption: the server (LiteSpeed) answers 403
without an Android UA, and it cuts every response to multiples of
16 KiB (see the dossier ``ANALYSIS.md`` section 5 and ``codec.py``).
No authentication, no session, no redirects.

In the cloud flow the broker (``server-vpn-provider.mjs``) performs
the same ranged download and hands the raw bytes to the isolated
worker, which calls ``run()`` here; ``download()`` below is the
identical logic for direct/CLI use.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
if __package__:
    from .codec import CATALOG_URL, DecodeError, MAX_BYTES, decode_catalog, fetch_catalog, render
else:
    from codec import CATALOG_URL, DecodeError, MAX_BYTES, decode_catalog, fetch_catalog, render


def download() -> bytes:
    """Ranged GET with the Android UA; raises DecodeError on failure."""
    try:
        body, _total = fetch_catalog(CATALOG_URL)
    except (IOError, OSError) as exc:
        raise DecodeError("No se pudo descargar el catalogo AM Tunnel Lite autorizado.") from exc
    if not body or len(body) > MAX_BYTES or body.lstrip().startswith(b"<"):
        raise DecodeError("Catalogo AM Tunnel Lite vacio o incompatible.")
    return body


def run(data: bytes) -> str:
    return render(decode_catalog(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('file', nargs='?', type=Path)
    modes.add_argument('--stdin', action='store_true')
    modes.add_argument('--download', action='store_true')
    args = parser.parse_args()
    try:
        if args.file:
            with args.file.open('rb') as stream: data = stream.read(MAX_BYTES + 1)
        elif args.stdin: data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else: data = download()
        print(run(data)); return 0
    except (OSError, ValueError):
        print('No se pudo descargar o abrir el catálogo AM Tunnel Lite.', file=sys.stderr); return 1


if __name__ == '__main__': raise SystemExit(main())
