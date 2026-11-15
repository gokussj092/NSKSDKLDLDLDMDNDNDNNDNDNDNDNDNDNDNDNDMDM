#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zam VIP NET / Free VIP Net — decodificador de archivos para SP-DECODE.
======================================================================
Formatos propios de la app (zam.freevipnet.com 42.0):

  .zvn  Archivo de configuracion. Texto que empieza con el esquema
        "zamvipnet://" seguido del cifrado modo 0 (Base64 -> AES-128-CBC
        -> XXTEA) de un JSON. El manifest declara ACTION_VIEW con
        pathPattern .*\\.zvn; al abrirlo la app (ZamVIPNETMain.c0 -> O)
        comprueba el prefijo, lo quita y descifra con gf1.b (= modo 0).
        El JSON puede traer isSetExpiry / Expiry / isPinEnabled, o ser
        un catalogo completo (Version / Servers / Networks).
  .js / .rj  Importacion por selector de archivos (onActivityResult):
        el archivo debe terminar en .js o .rj y su contenido es el
        cifrado modo 0 directamente, sin prefijo.
  zamvipnet://<cifrado>  Enlace de texto: mismo formato que .zvn, se
        puede pegar como texto o guardar en un archivo .txt.

  (La exportacion de la app escribe el JSON en claro; este script
  tambien acepta un archivo JSON en claro y solo descifra sus campos.)

Solo stdlib. Uso:
  python3 Zam_VIP_NET_archivos.py archivo.zvn [--out config.json]
  python3 Zam_VIP_NET_archivos.py archivo.js archivo.rj
  python3 Zam_VIP_NET_archivos.py --self-test
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from Zam_VIP_NET import decrypt_mode0, encrypt_mode0, decode_value

PREFIX = "zamvipnet://"


def decode_text(text):
    """Descifra el contenido de un .zvn / .js / .rj / enlace de texto.
    Devuelve el dict JSON con los campos ya descifrados."""
    text = text.strip()
    if text.startswith(PREFIX):
        text = text[len(PREFIX):]
    if not text:
        raise ValueError("archivo vacio")
    # JSON en claro (exportacion de la app)
    if text.startswith("{"):
        data = json.loads(text)
        return decode_value(data)
    plain = decrypt_mode0(text)
    if not plain:
        raise ValueError("no se pudo descifrar el archivo (modo 0)")
    data = json.loads(plain.decode("utf-8"))
    return decode_value(data)


def decode_file(path):
    """Lee un archivo .zvn / .js / .rj / .txt / .json y lo descifra."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return decode_text(f.read())


def encode_zvn(config_dict):
    """Construye el contenido de un .zvn a partir de un dict
    (para --self-test)."""
    raw = json.dumps(config_dict, ensure_ascii=False).encode("utf-8")
    return PREFIX + encrypt_mode0(raw)


def self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("OK  " if cond else "FAIL") + " " + name)
        if not cond:
            ok = False

    sample = {
        "Version": "2.458",
        "isSetExpiry": False,
        "Servers": [{"Name": "Test", "ServerIPHost": "example.com"}],
    }
    # .zvn (con prefijo)
    zvn = encode_zvn(sample)
    check(".zvn round-trip", decode_text(zvn) == sample)
    check(".zvn lleva prefijo", zvn.startswith(PREFIX))
    # .js / .rj (cifrado directo, sin prefijo)
    raw = encrypt_mode0(json.dumps(sample, ensure_ascii=False).encode("utf-8"))
    check(".js/.rj round-trip", decode_text(raw) == sample)
    # JSON en claro (exportacion)
    check("JSON en claro", decode_text(json.dumps(sample)) == sample)
    # enlace de texto con saltos de linea
    check("enlace con whitespace",
          decode_text("\n  " + zvn + "\n") == sample)
    print("SELF-TEST:", "TODO OK" if ok else "HAY FALLOS")
    return ok


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(
        description="Zam VIP NET — decodificador de archivos .zvn / .js / .rj")
    ap.add_argument("files", nargs="*", help="archivos a descifrar")
    ap.add_argument("--out", help="guardar el JSON descifrado (solo con un archivo)")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return 0 if self_test() else 1
    if not args.files:
        ap.error("indica al menos un archivo .zvn / .js / .rj")
    for path in args.files:
        try:
            data = decode_file(path)
        except Exception as e:
            print(f"{path}: ERROR: {e}")
            return 1
        print(f"== {path} ==")
        print("  Version:", data.get("Version"))
        if "Servers" in data:
            print("  Servidores:", len(data["Servers"]))
        if "Networks" in data:
            print("  Redes:", len(data["Networks"]))
        if "isSetExpiry" in data:
            print("  isSetExpiry:", data.get("isSetExpiry"),
                  "| Expiry:", data.get("Expiry"))
        if args.out and len(args.files) == 1:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=1, ensure_ascii=False)
            print("  Guardado en", args.out)
        else:
            print(json.dumps(data, indent=1, ensure_ascii=False)[:2000])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
