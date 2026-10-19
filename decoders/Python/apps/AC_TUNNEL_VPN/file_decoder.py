#!/usr/bin/env python3
"""AC TUNNEL VPN 1.4: .actun exports and actunnelvpn:// text, offline."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

if __package__:
    from .codec import DecodeError, MAX_BYTES, cloud_reference, envelope, render
else:
    from codec import DecodeError, MAX_BYTES, cloud_reference, envelope, render


def run(data: bytes) -> str:
    return render(envelope(data, profile=True))


def decode_text(text: str) -> str | None:
    """Select real exported profiles; leave older generic RENZ documents alone."""
    if not isinstance(text, str) or not text.lower().startswith("actunnelvpn://"):
        return None
    data = ("actunnelvpn://" + text[len("actunnelvpn://"):]).encode("utf-8")
    # The old protocol's generic JSON vectors have no exported Name field.
    # Decide from the common, verified envelope before any field decoding.
    try:
        import json
        if __package__:
            from . import codec
        else:
            import codec
        raw = codec._input(data)[len(codec.PROFILE_PREFIX):]
        obj = json.loads(codec.decrypt_main(raw), object_pairs_hook=codec._unique,
                         parse_constant=codec._reject_constant)
        if not isinstance(obj, dict) or "Name" not in obj:
            return None
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("Formato o contenido cifrado inválido.") from exc
    return run(data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path, help="Archivo .actun; omitir para leer stdin")
    parser.add_argument("--reference", action="store_true", help="Decodificar solo el identificador acvpn://; sin descargar el perfil")
    args = parser.parse_args()
    try:
        with args.file.open("rb") if args.file else sys.stdin.buffer as stream:
            data = stream.read(MAX_BYTES + 1)
        print(render(cloud_reference(data)) if args.reference else run(data))
        return 0
    except (OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, DecodeError) else "No se pudo leer el archivo.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
