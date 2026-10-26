#!/usr/bin/env python3
"""Offline MM catalog reader and fixed official POST downloader.

The remote response is not yet validated: do not enable the public broker.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
from urllib.request import Request, HTTPRedirectHandler, build_opener

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from decoders.Python.apps.MM_Tunnel.codec import DecodeError, MAX_BYTES, decode_catalog, render

SOURCE = "https://strongteam.co/api/mmtunnel/"
POST_BODY = b"type=xsandokUpdatex"


def run(data: bytes) -> str:
    return render(decode_catalog(data))


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise DecodeError("REMOTE_REDIRECT_REJECTED")


def download() -> bytes:
    request = Request(SOURCE, data=POST_BODY, headers={
        "Content-Type": "application/x-www-form-urlencoded", "Accept-Encoding": "identity",
        "User-Agent": "Go-http-client/1.1",
    })
    try:
        with build_opener(_NoRedirect()).open(request, timeout=25) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise DecodeError("INVALID_REMOTE_RESPONSE")
            data = response.read(MAX_BYTES + 1)
    except OSError as exc:
        raise DecodeError("REMOTE_UNAVAILABLE") from exc
    if not data or len(data) > MAX_BYTES:
        raise DecodeError("INVALID_REMOTE_SIZE")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", help="Catalog path, - for stdin; omitted: fixed official POST")
    args = parser.parse_args()
    try:
        if args.file == "-":
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        elif args.file:
            with Path(args.file).open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        else:
            data = download()
        print(run(data))
        return 0
    except (OSError, ValueError, RecursionError):
        print("No se pudo leer el catálogo MM Tunnel completo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
