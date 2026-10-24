#!/usr/bin/env python3
"""Decode Tunneltweak 6.2.1 .tut profiles or a user-supplied Cloud UUID."""
from __future__ import annotations
import argparse
import getpass
from pathlib import Path
import sys
if __package__:
    from .codec import DecodeError, MAX_BYTES, MAX_FILE_BYTES, bounded, parse, decode_profile, render
    from .network import download
else:
    from codec import DecodeError, MAX_BYTES, MAX_FILE_BYTES, bounded, parse, decode_profile, render
    from network import download


def run(data: bytes, *, password: str | None = None) -> str:
    return render(decode_profile(data, password=password))


def decode_cloud_response(data: bytes, *, password: str | None = None) -> str:
    try:
        obj = parse(bounded(data).decode("utf-8-sig"))
        if not isinstance(obj.get("config"), str):
            raise DecodeError("Respuesta Cloud incompatible.")
        return render(dict(obj, config=decode_profile(obj["config"].encode("utf-8"), password=password)))
    except DecodeError:
        raise
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise DecodeError("Respuesta Cloud inválida.") from exc


def read_secret(path: Path) -> str:
    with path.open("rb") as stream:
        raw = stream.read(16387)
    if len(raw) > 16386:
        raise DecodeError("Archivo de credencial superior al límite permitido.")
    text = raw.decode("utf-8").removesuffix("\n").removesuffix("\r")
    if not 0 < len(text) <= 4096:
        raise DecodeError("Credencial vacía o superior al límite permitido.")
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path, help="Archivo .tut; sin archivo lee stdin")
    parser.add_argument("--cloud-id", help="UUID propio: descarga solo desde la API original fija")
    secret = parser.add_mutually_exclusive_group()
    secret.add_argument("--password-file", type=Path, help="Contraseña UTF-8 desde un archivo local")
    secret.add_argument("--ask-password", action="store_true", help="Pedir contraseña sin mostrarla")
    args = parser.parse_args()
    if args.file and args.cloud_id:
        parser.error("Elige archivo o --cloud-id.")
    try:
        password = read_secret(args.password_file) if args.password_file else getpass.getpass("Contraseña: ") if args.ask_password else None
        if args.cloud_id:
            result = decode_cloud_response(download(cloud_id=args.cloud_id), password=password)
        else:
            if args.file:
                with args.file.open("rb") as stream:
                    data = stream.read(MAX_FILE_BYTES + 1)
            else:
                data = sys.stdin.buffer.read(MAX_FILE_BYTES + 1)
            result = run(data, password=password)
        print(result)
        return 0
    except (OSError, ValueError, EOFError) as exc:
        print(str(exc) if isinstance(exc, DecodeError) else "No se pudo leer el recurso.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
