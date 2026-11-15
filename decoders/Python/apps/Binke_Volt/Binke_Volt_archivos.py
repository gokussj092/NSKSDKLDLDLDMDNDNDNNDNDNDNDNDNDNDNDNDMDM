#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Binke Volt VPN — decodificador de archivos para SP-DECODE.
===========================================================
Formatos propios de la app (xyz.binkevoltvpn.org 1.1, build 11,
familia RENZ):

  .bvv  Archivo de configuracion. Texto que empieza con el esquema
        "binkevoltvpn://" seguido del cifrado modo 0 (Base64 ->
        AES-128-CBC -> XXTEA -> -2 por byte) de un JSON de perfil
        (un servidor/red). El manifest declara ACTION_VIEW con
        schemes file/content, pathPattern .*\\.bvv, mime */*.
        Al abrirlo la app (BinkeVoltVPNMain.f0 -> Q) comprueba el
        prefijo, lo quita y descifra con pg1.b (= modo 0); el JSON
        puede traer isSetExpiry / Expiry / isPinEnabled; la app le
        pone Type="Imported" y lo guarda en custom_payload.json
        cifrado en modo 0 (pg1.d).
  .js / .rj  Importacion por selector de archivos (requestCode 1996):
        el archivo debe terminar en .js o .rj y su contenido es el
        cifrado modo 0 de un catalogo completo, sin prefijo. La app
        comprueba que su campo Version coincida con la version
        guardada y luego guarda el texto cifrado tal cual en un
        zip a.rlb en getFilesDir().
  binkevoltvpn://<cifrado>  Enlace de texto: mismo formato que .bvv,
        se atiende dentro de la app (Q()/f0()); NO hay un
        intent-filter con ese scheme en el manifest, solo el filtro
        .bvv y los schemes https y sms en otras actividades.
        La exportacion (requestCode 1999) escribe
        "binkevoltvpn://%s" de pg1.d(perfil JSON) en el archivo
        que elija el usuario (presumiblemente .bvv).

  (La exportacion de la app escribe el JSON en claro; este script
  tambien acepta un archivo JSON en claro y solo descifra sus campos.)

Solo stdlib. Uso:
  python3 Binke_Volt_archivos.py archivo.bvv [--out config.json]
  python3 Binke_Volt_archivos.py archivo.js archivo.rj
  python3 Binke_Volt_archivos.py --self-test
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from Binke_Volt import decrypt_mode0, encrypt_mode0, decode_value

PREFIX = "binkevoltvpn://"


def decode_text(text):
    """Descifra el contenido de un .bvv / .js / .rj / enlace de texto.
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
    """Lee un archivo .bvv / .js / .rj / .txt / .json y lo descifra."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return decode_text(f.read())


def encode_bvv(config_dict):
    """Construye el contenido de un .bvv a partir de un dict
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
        "Version": "13.67",
        "isSetExpiry": False,
        "Servers": [{"Name": "Test", "ServerIPHost": "example.com"}],
    }
    # .bvv (con prefijo)
    bvv = encode_bvv(sample)
    check(".bvv round-trip", decode_text(bvv) == sample)
    check(".bvv lleva prefijo", bvv.startswith(PREFIX))
    # .js / .rj (cifrado directo, sin prefijo)
    raw = encrypt_mode0(json.dumps(sample, ensure_ascii=False).encode("utf-8"))
    check(".js/.rj round-trip", decode_text(raw) == sample)
    # JSON en claro (exportacion)
    check("JSON en claro", decode_text(json.dumps(sample)) == sample)
    # enlace de texto con saltos de linea
    check("enlace con whitespace",
          decode_text("\n  " + bvv + "\n") == sample)
    # .js real: el catalogo en vivo 2026-11-14 (Version 13.67,
    # 55 servidores, 789 redes) como archivo .js tal cual lo
    # descargaria la app (el cuerpo Base64 es el cifrado modo 0
    # del catalogo; re-cifrarlo lo reproduce byte a byte).
    import os
    live = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "work", "catalog_live_body.txt")
    if os.path.exists(live):
        with open(live, "r", encoding="utf-8") as f:
            live_data = decode_text(f.read())
        check(".js real (catalogo vivo 13.67)",
              live_data.get("Version") == "13.67"
              and len(live_data.get("Servers", [])) == 55
              and len(live_data.get("Networks", [])) == 789)
    else:
        print("SKIP .js real (sin work/catalog_live_body.txt)")
    print("SELF-TEST:", "TODO OK" if ok else "HAY FALLOS")
    return ok


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(
        description="Binke Volt VPN — decodificador de archivos .bvv / .js / .rj")
    ap.add_argument("files", nargs="*", help="archivos a descifrar")
    ap.add_argument("--out", help="guardar el JSON descifrado (solo con un archivo)")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return 0 if self_test() else 1
    if not args.files:
        ap.error("indica al menos un archivo .bvv / .js / .rj")
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
