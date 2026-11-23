#!/usr/bin/env python3
"""Download HTTP WinzapVPN 1.1.61's fixed catalog or open an offline copy."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

if __package__:
    from .codec import CATALOG_URL, DecodeError, MAX_BYTES, decode_catalog, render
else:
    from codec import CATALOG_URL, DecodeError, MAX_BYTES, decode_catalog, render


def download() -> bytes:
    # Plain GET, like the app (no headers beyond the app User-Agent, no
    # auth, no signature — the bootstrap needs none). The User-Agent
    # 'WinZapVPN/1.1.61' matches the broker entry
    # (server-vpn-provider.mjs); a curl control fetch with a default UA
    # returned byte-identical bodies, so the result does not depend on it.
    # requests is used on purpose: urllib proved unstable through the
    # egress proxy of this VM (cut connections / 400 from the origin);
    # see dossier EVIDENCE.md section 8.
    try:
        import requests
    except ImportError:
        raise DecodeError('Falta requests para descargar el catálogo.') from None
    try:
        response = requests.get(
            CATALOG_URL,
            headers={"User-Agent": "WinZapVPN/1.1.61", "Accept": "application/json"},
            timeout=25, allow_redirects=False)
    except Exception:
        raise DecodeError('No se pudo descargar el catálogo autorizado.') from None
    if response.status_code != 200:
        raise DecodeError('Respuesta remota inválida.')
    data = response.content
    if not data or len(data) > MAX_BYTES or data.lstrip().startswith(b"<"):
        raise DecodeError('Catálogo remoto vacío o incompatible.')
    return data


def run(data: bytes) -> str:
    return render(decode_catalog(data))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    modes = p.add_mutually_exclusive_group()
    modes.add_argument('file', nargs='?', type=Path)
    modes.add_argument('--stdin', action='store_true')
    modes.add_argument('--download', action='store_true', help='Descargar la única fuente HTTPS fija (predeterminado)')
    a = p.parse_args()
    try:
        if a.file:
            with a.file.open('rb') as stream:
                data = stream.read(MAX_BYTES + 1)
        elif a.stdin:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            data = download()
        sys.stdout.write(run(data))
        return 0
    except (OSError, ValueError):
        print('No se pudo leer el catálogo completo de HTTP WinzapVPN.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
