#!/usr/bin/env python3
"""Read HTTP Custom .hc files; print complete decoded data without an APK."""
from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path
import sys

if __package__:
    from .codec import HCError, UnrecognizedFormat, MAX_FILE_BYTES, decrypt, historical
else:
    from codec import HCError, UnrecognizedFormat, MAX_FILE_BYTES, decrypt, historical


def run(data: bytes, *, password: str | None = None, hwid: str | None = None) -> str:
    for value in (password, hwid):
        if value is not None and (not isinstance(value, str) or not 0 < len(value) <= 4096):
            raise HCError("INVALID_CREDENTIAL")
    try:
        result = decrypt(data, password=password, hwid=hwid)
    except UnrecognizedFormat:
        try:
            result = historical.decrypt(data, password=password, hwid=hwid)
        except HCError as error:
            if str(error) != "Not a valid HTTP Custom envelope":
                raise
            if __package__:
                from ...HTTPCUSTOM import HCDecryptor
            else:
                from HTTPCUSTOM import HCDecryptor
            legacy = HCDecryptor.execute(data)
            if legacy is None:
                raise HCError("UNRECOGNIZED_FORMAT") from error
            return legacy
    return json.dumps(result, ensure_ascii=False, indent=2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="Archivo .hc, leído como bytes")
    secret = parser.add_mutually_exclusive_group()
    secret.add_argument("--password-file", type=Path, help="Contraseña UTF-8 en archivo local")
    secret.add_argument("--ask-password", action="store_true", help="Pedir contraseña sin mostrarla")
    secret.add_argument("--auth-stdin", action="store_true", help='JSON stdin con password/hwid')
    parser.add_argument("--hwid", help="HWID original de 32 caracteres")
    args = parser.parse_args()
    try:
        password, hwid = None, args.hwid
        if args.auth_stdin:
            raw = sys.stdin.buffer.read(8193)
            if len(raw) > 8192:
                raise HCError("INVALID_CREDENTIAL")
            credentials = json.loads(raw.decode("utf-8"))
            if not isinstance(credentials, dict) or not set(credentials) <= {"password", "hwid"}:
                raise HCError("INVALID_CREDENTIAL")
            password = credentials.get("password")
            hwid = credentials.get("hwid", hwid)
        elif args.password_file:
            with args.password_file.open("rb") as stream:
                raw = stream.read(16385)
            if len(raw) > 16384:
                raise HCError("INVALID_CREDENTIAL")
            password = raw.decode("utf-8").removesuffix("\n").removesuffix("\r")
        elif args.ask_password:
            password = getpass.getpass("Contraseña: ")
        with args.file.open("rb") as stream:
            data = stream.read(MAX_FILE_BYTES + 1)
        print(run(data, password=password, hwid=hwid))
        return 0
    except (OSError, EOFError, ValueError, UnicodeError, TypeError) as error:
        print(str(error) if isinstance(error, HCError) else "No se pudo leer el archivo o las credenciales.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
