#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSP Tunnel — decodificador de archivos para SP-DECODE.
======================================================
Formatos propios de la app (xyz.osptunnel.org 3.7):

  .osp  Archivo de configuracion. Texto con el cifrado de un JSON.
        Acepta tres formas (en este orden):
          osptunnel://<cifrado>  (o el alias osp://<cifrado>)
          <cifrado>               (directo, sin prefijo)
          { ... }                 (JSON en claro, exportacion)
        El cifrado es el modo 0 de RenzUtils.decrypt (Base64 ->
        AES-128-CBC -> XXTEA -> cada byte - 2); si el modo 0 no abre,
        se prueban el modo 1 y el modo 2 (el repo SP-DECODE hace lo
        mismo en decoders/Python/renz.py, _decode_config -> tipos 0-3,
        extension ".osp" y protocolos "osp://"/"osptunnel://" -> "7net").
        El JSON puede traer isSetExpiry / Expiry / isPinEnabled /
        NetworkPinCode (config compartida), o ser un catalogo completo
        (Version / Servers / Networks).
  osptunnel://<cifrado>  Enlace de texto: mismo formato que .osp, se
        puede pegar como texto o guardar en un archivo .txt. La app lo
        valida ("Error! format must start osptunnel://") y lee los
        campos isSetExpiry / Expiry / isPinEnabled / NetworkPinCode.
        No hay intent-filter de esquema ni de extension en el
        manifest: la importacion es por pegado de enlace, no por
        abrir el archivo desde otra app.

Solo stdlib. Uso:
  python3 OSP_Tunnel_archivos.py archivo.osp [--out config.json]
  python3 OSP_Tunnel_archivos.py "osptunnel://<cifrado>"
  python3 OSP_Tunnel_archivos.py --self-test
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from OSP_Tunnel import (decrypt_mode0, decrypt_mode1, decrypt_mode2,
                        encrypt_mode0, decode_value)

PREFIXES = ("osptunnel://", "osp://")


def _decrypt_payload(payload):
    """Prueba los 3 modos sobre el cifrado y devuelve el JSON."""
    for fn in (decrypt_mode0, decrypt_mode1, decrypt_mode2):
        try:
            plain = fn(payload)
        except Exception:
            plain = None
        if plain:
            try:
                return json.loads(plain.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
    raise ValueError("no se pudo descifrar el archivo (ningun modo abre)")


def decode_text(text):
    """Descifra el contenido de un .osp / enlace osptunnel://.
    Devuelve el dict JSON con los campos ya descifrados."""
    text = text.strip()
    if not text:
        raise ValueError("archivo vacio")
    lowered = text.lower()
    for prefix in PREFIXES:
        if lowered.startswith(prefix):
            text = text[len(prefix):].strip()
            break
    # JSON en claro (exportacion de la app)
    if text.startswith("{"):
        data = json.loads(text)
        return decode_value(data)
    data = _decrypt_payload(text)
    return decode_value(data)


def decode_file(path):
    """Lee un archivo .osp / .txt / .json y lo descifra."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return decode_text(f.read())


def encode_osp(config_dict):
    """Construye el contenido de un .osp a partir de un dict
    (para --self-test)."""
    raw = json.dumps(config_dict, ensure_ascii=False).encode("utf-8")
    return "osptunnel://" + encrypt_mode0(raw)


def self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("OK  " if cond else "FAIL") + " " + name)
        if not cond:
            ok = False

    sample = {
        "Version": "40.71",
        "isSetExpiry": False,
        "isPinEnabled": False,
        "Servers": [{"Name": "Test", "ServerIPHost": "example.com"}],
        "Networks": [{"Name": "Direct TCP", "SNIHost": "www.google.com"}],
    }
    # .osp con prefijo osptunnel://
    osp = encode_osp(sample)
    check(".osp round-trip", decode_text(osp) == sample)
    check(".osp lleva prefijo", osp.startswith("osptunnel://"))
    # alias osp://
    check("osp:// round-trip",
          decode_text("osp://" + osp[len("osptunnel://"):]) == sample)
    # cifrado directo, sin prefijo
    raw = encrypt_mode0(json.dumps(sample, ensure_ascii=False).encode("utf-8"))
    check("cifrado directo round-trip", decode_text(raw) == sample)
    # JSON en claro (exportacion)
    check("JSON en claro", decode_text(json.dumps(sample)) == sample)
    # enlace de texto con saltos de linea
    check("enlace con whitespace",
          decode_text("\n  " + osp + "\n") == sample)
    # campos cifrados dentro del JSON (modo 1 y modo 2)
    from OSP_Tunnel import encrypt_mode1, encrypt_mode2
    sample2 = {
        "Version": "40.71",
        "Servers": [{"Name": "VIP 01",
                     "ServerIPHost": encrypt_mode1(b"dyyl4x18ayspo.cloudfront.net"),
                     "Username": encrypt_mode2(b"ksksksk")}],
    }
    check("campos modo 1/2 dentro del .osp",
          decode_text(encode_osp(sample2))["Servers"][0]["ServerIPHost"]
          == "dyyl4x18ayspo.cloudfront.net"
          and decode_text(encode_osp(sample2))["Servers"][0]["Username"]
          == "ksksksk")
    print("SELF-TEST:", "TODO OK" if ok else "HAY FALLOS")
    return ok


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(
        description="OSP Tunnel — decodificador de archivos .osp / osptunnel://")
    ap.add_argument("inputs", nargs="*", help="archivos .osp/.txt/.json o enlaces osptunnel://")
    ap.add_argument("--out", help="guardar el JSON descifrado (solo con una entrada)")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return 0 if self_test() else 1
    if not args.inputs:
        ap.error("indica al menos un archivo .osp o un enlace osptunnel://")
    for item in args.inputs:
        try:
            if os.path.isfile(item):
                data = decode_file(item)
            else:
                data = decode_text(item)
        except Exception as e:
            print(f"{item}: ERROR: {e}")
            return 1
        print(f"== {item} ==")
        print("  Version:", data.get("Version"))
        if "Servers" in data:
            print("  Servidores:", len(data["Servers"]))
        if "Networks" in data:
            print("  Redes:", len(data["Networks"]))
        if "isSetExpiry" in data:
            print("  isSetExpiry:", data.get("isSetExpiry"),
                  "| Expiry:", data.get("Expiry"))
        if "isPinEnabled" in data:
            print("  isPinEnabled:", data.get("isPinEnabled"),
                  "| NetworkPinCode:", data.get("NetworkPinCode"))
        if args.out and len(args.inputs) == 1:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=1, ensure_ascii=False)
            print("  Guardado en", args.out)
        else:
            print(json.dumps(data, indent=1, ensure_ascii=False)[:2000])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
