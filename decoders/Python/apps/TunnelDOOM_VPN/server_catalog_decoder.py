#!/usr/bin/env python3
"""TunnelDOOM full offline catalog reader and fixed-source CLI downloader.

The source could not be reached during analysis; the public broker stays off.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import sys
from urllib.request import HTTPRedirectHandler, Request, build_opener

if __package__:
    from .codec import DecodeError, MAX_BYTES, run
else:
    from codec import DecodeError, MAX_BYTES, run

SOURCE = "https://control.tunneldoom.space/config.json"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise DecodeError("REMOTE_REDIRECT_REJECTED")


def download() -> bytes:
    request = Request(SOURCE, headers={"Accept-Encoding": "identity", "User-Agent": "Dalvik/2.1.0"})
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
    parser.add_argument("file", nargs="?", help="Catalog path or - for stdin; omitted: fixed GET")
    parser.add_argument("-o", "--output", type=Path, help="New private JSON file (0600), never overwritten")
    args = parser.parse_args()
    try:
        if args.file == "-":
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        elif args.file:
            with Path(args.file).open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        else:
            data = download()
        result = run(data) + "\n"
        if args.output:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(result)
        else:
            sys.stdout.write(result)
        return 0
    except (OSError, ValueError, RecursionError):
        print("No se pudo leer el catálogo TunnelDOOM completo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
