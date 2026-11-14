#!/usr/bin/env python3
"""DTunnel Mod / Fastiver Vpn Pro 4.2.5 — decodificador de enlaces y archivos.

La app no tiene un formato propio de archivo exportable (ver README.md): lo
que importa y comparte es el enlace de texto `vpn://`, Base64 estándar de un
objeto JSON UTF-8 con el perfil completo (sin cifrar). El manifiesto además
declara el deep link `http(s)://dt.com.br/import/<...>`, pero su carga útil
no se pudo verificar: el host no responde desde aquí y no hay una muestra
real; este script intenta descifrar el segmento como Base64 JSON y lo dice
claro si no es eso.

Formatos que abre:
  - vpn://<Base64(JSON del perfil)>          (verificado, formato de la app)
  - https://dt.com.br/import/<carga>         (manifiesto; carga sin verificar)
  - respuesta cifrada del catálogo guardada  (Base64 AES-256-CBC; usa DTunnel.py)
  - JSON en claro (perfil o lista de perfiles)

Sin dependencias para los enlaces; para respuestas cifradas necesita
DTunnel.py en la misma carpeta.

Uso:
    python3 DTunnel_archivos.py enlace.txt
    python3 DTunnel_archivos.py --link 'vpn://BASE64_DEL_JSON'
    python3 DTunnel_archivos.py --link 'https://dt.com.br/import/....'
    python3 DTunnel_archivos.py respuesta_catalogo.txt
    python3 DTunnel_archivos.py --self-test
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit, unquote

MAX_BYTES = 32 * 1024 * 1024


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _text(data: bytes | str) -> str:
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "La entrada debe ser bytes o texto UTF-8.")
    try:
        text = data.decode("utf-8-sig") if isinstance(data, bytes) else data.removeprefix("\ufeff")
    except UnicodeError as exc:
        raise DecodeError("FORMAT_ERROR", "La entrada no es UTF-8 válido.") from exc
    return text.strip()


def _base64(text: str) -> bytes:
    compact = re.sub(r"[ \t\r\n]", "", text)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) or len(compact) % 4 == 1:
        raise DecodeError("FORMAT_ERROR", "Se esperaba Base64 estándar.")
    try:
        return base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR", "Base64 inválido.") from exc


def _json(text: str):
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise DecodeError("INVALID_JSON", "JSON inválido.") from exc
    return doc


def decode_link(data: bytes | str) -> dict:
    """vpn://Base64(UTF-8 JSON) -> perfil dict. Conserva todos los campos."""
    text = _text(data)
    if not text.startswith("vpn://"):
        raise DecodeError("FORMAT_ERROR", "Se esperaba un enlace vpn://.")
    try:
        plain = _base64(text[6:]).decode("utf-8")
    except UnicodeError as exc:
        raise DecodeError("FORMAT_ERROR", "El enlace no contiene UTF-8 válido.") from exc
    doc = _json(plain)
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El enlace debe contener un objeto JSON.")
    return doc


def decode_import_url(data: bytes | str) -> dict:
    """Deep link http(s)://dt.com.br/import/<carga>.

    La carga útil NO está verificada contra la app (host sin respuesta, sin
    muestra real). Se intenta como Base64 de JSON UTF-8; si no es eso, se
    informa IMPORT_URL_UNVERIFIED en lugar de inventar un perfil.
    """
    text = _text(data)
    parts = urlsplit(text)
    if parts.netloc.lower() != "dt.com.br" or not parts.path.startswith("/import/"):
        raise DecodeError("FORMAT_ERROR", "Se esperaba un enlace dt.com.br/import/...")
    payload = unquote(parts.path[len("/import/"):]).strip()
    if not payload:
        raise DecodeError("IMPORT_URL_UNVERIFIED", "El enlace de importación no trae carga útil.")
    if payload.startswith("vpn://"):
        return decode_link(payload)
    try:
        plain = _base64(payload).decode("utf-8")
        doc = _json(plain)
    except (DecodeError, UnicodeError):
        raise DecodeError("IMPORT_URL_UNVERIFIED",
                          "La carga del enlace dt.com.br/import/ no es Base64 de JSON; "
                          "formato sin verificar (falta una muestra real de la app).")
    if not isinstance(doc, dict):
        raise DecodeError("IMPORT_URL_UNVERIFIED", "La carga del enlace no es un objeto JSON.")
    return doc


def decode_catalog_response(data: bytes | str):
    """Respuesta cifrada guardada; delega en DTunnel.py (misma carpeta)."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import DTunnel
    except ImportError as exc:
        raise DecodeError("MISSING_DTUNNEL", "Falta DTunnel.py en la misma carpeta para descifrar el catálogo.") from exc
    return DTunnel.decode_catalog(data)


def decode(data: bytes | str):
    """Detecta el formato: enlace vpn://, deep link, JSON claro o catálogo cifrado."""
    text = _text(data)
    if text.startswith("vpn://"):
        return decode_link(text)
    if text.startswith(("http://dt.com.br/import/", "https://dt.com.br/import/")):
        return decode_import_url(text)
    if text.startswith(("{", "[")):
        return _json(text)
    return decode_catalog_response(data)


def decode_file(path: Path):
    """Un archivo puede traer un enlace por línea; devuelve lista de perfiles."""
    data = path.read_bytes()
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    text = _text(data)
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) > 1 and all(ln.startswith(("vpn://", "http://dt.com.br/import/", "https://dt.com.br/import/")) for ln in lines):
        return [decode(ln) for ln in lines]
    return decode(data)


def _self_test() -> int:
    ok = 0

    def check(name, cond):
        nonlocal ok
        print(("OK   " if cond else "FAIL ") + name)
        if not cond:
            raise SystemExit(1)
        ok += 1

    profile = {"id": 188710, "name": "perfil prueba", "mode": "SSL_DIRECT",
               "category": {"id": 20628, "name": "SERVIDOR VIP"},
               "server": {"host": "ejemplo.test", "port": 80},
               "config_payload": "GET / HTTP/1.1\r\nHost: ejemplo.test\r\n\r\n"}
    link = "vpn://" + base64.b64encode(json.dumps(profile, ensure_ascii=False).encode()).decode()
    check("vpn:// round-trip", decode_link(link) == profile)
    check("decode() detecta vpn://", decode(link) == profile)
    import_url = "https://dt.com.br/import/" + link[6:]
    check("dt.com.br/import/ con carga vpn://", decode_import_url(import_url) == profile)
    plain_b64 = base64.b64encode(json.dumps(profile, ensure_ascii=False).encode()).decode()
    check("dt.com.br/import/ con Base64 JSON", decode_import_url("https://dt.com.br/import/" + plain_b64) == profile)
    check("JSON en claro", decode(json.dumps(profile, ensure_ascii=False)) == profile)
    check("Lista JSON en claro", decode(json.dumps([profile], ensure_ascii=False)) == [profile])
    # Catálogo vivo real guardado (49 perfiles) descifrado vía DTunnel.py.
    sample = Path(__file__).resolve().parent / "catalog_sample.b64"
    if sample.exists():
        result = decode_catalog_response(sample.read_bytes())
        check("Catálogo vivo real (.b64)", isinstance(result, list) and len(result) == 49)
    else:
        print("SKIP catálogo vivo real (falta catalog_sample.b64)")
    try:
        decode_import_url("https://dt.com.br/import/!!!no-base64!!!")
        check("Import con carga inválida rechazado", False)
    except DecodeError as exc:
        check("Import con carga inválida rechazado", exc.code == "IMPORT_URL_UNVERIFIED")
    try:
        decode_link("https://ejemplo.test/x")
        check("Texto sin vpn:// rechazado", False)
    except DecodeError:
        check("Texto sin vpn:// rechazado", True)
    print(f"SELF-TEST: TODO OK ({ok} pruebas)")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, help="Archivo con enlace(s), respuesta cifrada o JSON")
    source.add_argument("--link", help="Enlace vpn:// o dt.com.br/import/ completo")
    source.add_argument("--self-test", action="store_true", help="Pruebas locales sin red")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; por defecto stdout")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    try:
        result = decode(args.link) if args.link is not None else decode_file(args.file)
        rendered = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        if isinstance(result, list):
            print(f"Perfiles: {len(result)}", file=sys.stderr)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
