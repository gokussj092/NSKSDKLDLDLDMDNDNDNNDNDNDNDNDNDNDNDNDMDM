#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PPH GOOD VPN — decodificador de archivos (SP-DECODE)
====================================================
App: PPH GOOD VPN, com.skphvpn.mm, 1.7.2 / versionCode 75.

La app NO tiene un formato propio de archivo exportable con extension
(no hay intent-filter de archivo ni esquema URI propio en el manifest).
Lo que SI guarda/lee como archivo es su catalogo de servidores:

  1. Catalogo crudo (una linea Base64):
     - assets/pphdev.json (incluido en el APK; la app lo lee con
       c_01.readFromAsset y lo abre con c_01.decryptMain)
     - el catalogo descargado (misma forma; la app lo guarda en su
       SQLite, no como archivo, pero el cuerpo crudo es identico)
     - filesDir/Servers.js es solo el nombre que usa getConfigVersion
       para leer la "Version" del catalogo guardado.
     Sobre: Base64 -> XXTEA (clave principal, DELTA 0x2E0BA747) -> JSON.
  2. Catalogo ya descifrado (JSON): se abren los campos cifrados con la
     clave secundaria XXTEA (ServerIP, ServerCloudFront, ServerHTTP,
     ProxyHost, sUdpObfs, Username, Password, ovpnCertificate,
     NetworkPayload, SquidProxy, SSLSNI, Ovpn_Cert) y se ELIMINAN las
     APIs de descarga del catalogo (config_url, ghUsername, ghRepoName,
     ghFilename; regla 2026-11-15). Un valor que no abre se deja tal cual.
  3. Un valor de campo suelto (Base64) -> clave secundaria.
  4. Parser.encode/decode de c_01$Parser: variante Base64 en la que a
     cada byte se le restan 18 antes de codificar (y se suman 18 al
     decodificar). En esta version no se encontraron llamadas en el
     codigo decompilado; se incluye por compatibilidad.

La app tambien importa .ovpn estandar (ConfigParser, de ics-openvpn) y
enlaces v2ray genericos (vmess://, vless://, trojan://, ss://) por
pegar, como cualquier fork de v2rayNG; esos formatos ya los cubre
SP-DECODE de forma generica y no se reimplementan aqui.

Uso:
  PPH_GOOD_VPN_archivos.py --file CATALOGO      abre un catalogo crudo o JSON
  PPH_GOOD_VPN_archivos.py --value BASE64        descifra un campo suelto
  PPH_GOOD_VPN_archivos.py --parser-decode STR   decodifica Parser.encode
  PPH_GOOD_VPN_archivos.py --parser-encode STR   codifica con Parser.encode
  PPH_GOOD_VPN_archivos.py --out JSON            escribe el resultado en JSON
  PPH_GOOD_VPN_archivos.py --self-test           pruebas offline

Python stdlib puro.
"""
import argparse
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from PPH_GOOD_VPN import (MAIN_KEY, FIELD_KEY, decrypt_envelope,
                          decrypt_field, decrypt_catalog_fields,
                          xxtea_decrypt, xxtea_encrypt)


def is_probably_json(data):
    text = data.strip()
    return text[:1] in (b"{", b"[")


def open_catalog_file(path):
    """Abre un catalogo crudo (base64) o ya descifrado (JSON).

    Devuelve (catalogo_con_campos_descifrados, formato_detectado).
    formato: 'raw-base64' | 'json'.
    """
    with open(path, "rb") as fh:
        data = fh.read()
    if is_probably_json(data):
        cat = json.loads(data.decode("utf-8"))
        return decrypt_catalog_fields(cat), "json"
    plain = decrypt_envelope(data)
    if plain is None:
        raise ValueError("DECRYPT_FAILED: %s no abre con la clave principal" % path)
    cat = json.loads(plain.decode("utf-8"))
    return decrypt_catalog_fields(cat), "raw-base64"


def parser_decode(text):
    """Inversa de c_01$Parser.encode: Base64 estandar y +18 por byte."""
    raw = base64.b64decode(text)
    return bytes((b + 18) & 0xFF for b in raw).decode("utf-8", "replace")


def parser_encode(text):
    """c_01$Parser.encode: -18 por byte y Base64 estandar."""
    raw = bytes((b - 18) & 0xFF for b in text.encode("utf-8"))
    return base64.b64encode(raw).decode("ascii")


def self_test():
    ok = True
    total = [0]
    passed = [0]

    def check(name, cond):
        nonlocal ok
        total[0] += 1
        passed[0] += bool(cond)
        print(("OK  " if cond else "FAIL") + " " + name)
        ok = ok and bool(cond)

    here = os.path.dirname(os.path.abspath(__file__))
    # 1. Round-trip Parser.encode/decode.
    check("Parser round-trip",
          parser_decode(parser_encode("https://example.com/x.json")) ==
          "https://example.com/x.json")
    # 2. Un campo suelto abre con la clave secundaria.
    sample_field = "Fu80S1jU1wOW43ObZo0BMqg/HvIGd0o/3vrZqdxn6qQ="
    check("campo suelto ServerIP",
          decrypt_field(sample_field) == "pphfree1.mvpnpvpn.de5.net")
    # 3. Un campo con clave incorrecta no abre.
    check("campo con clave incorrecta no abre",
          xxtea_decrypt(base64.b64decode(sample_field), b"clave-falsa-0000") is None)
    # 4. El catalogo incluido abre desde archivo.
    bundled = os.path.join(here, "catalog_sample_bundled.json")
    if os.path.exists(bundled):
        cat, fmt = open_catalog_file(bundled)
        check("catalogo incluido abre (formato %s)" % fmt, fmt == "raw-base64")
        check("catalogo incluido Version 2.0", cat.get("Version") == "2.0")
        check("catalogo incluido 60 servidores", len(cat.get("Servers", [])) == 60)
        check("catalogo incluido campo descifrado",
              cat["Servers"][0].get("ServerIP") == "pphfree1.mvpnpvpn.de5.net")
        check("catalogo incluido ProxyHost descifrado",
              cat["Servers"][10].get("ProxyHost") == "pphfree1.mvpnpvpn.de5.net")
        check("catalogo incluido sin config_url",
              "config_url" not in cat)
        check("catalogo incluido sin ghUsername/ghRepoName/ghFilename",
              not any(k in cat for k in
                      ("ghUsername", "ghRepoName", "ghFilename")))
    else:
        print("SKIP catalogo incluido (falta catalog_sample_bundled.json)")
    # 5. El catalogo en vivo guardado abre desde archivo.
    live = os.path.join(here, "catalog_sample.b64")
    if os.path.exists(live):
        cat, fmt = open_catalog_file(live)
        check("catalogo en vivo abre (formato %s)" % fmt, fmt == "raw-base64")
        check("catalogo en vivo Version 6.6", cat.get("Version") == "6.6")
        check("catalogo en vivo 15 servidores", len(cat.get("Servers", [])) == 15)
        check("catalogo en vivo 7 redes", len(cat.get("HTTPNetworks", [])) == 7)
    else:
        print("SKIP catalogo en vivo (falta catalog_sample.b64)")
    # 6. Un JSON ya descifrado tambien se abre (campos cifrados dentro).
    live_dec = os.path.join(here, "catalog_sample_decrypted.json")
    if os.path.exists(live_dec):
        cat, fmt = open_catalog_file(live_dec)
        check("JSON descifrado abre (formato %s)" % fmt, fmt == "json")
        check("JSON descifrado campos abiertos",
              cat["Servers"][0].get("ServerIP") == "thfree1.pphdevgoodvpn.shop")
        check("JSON descifrado sin config_url",
              "config_url" not in cat)
    else:
        print("SKIP JSON descifrado (falta catalog_sample_decrypted.json)")
    print("SELF-TEST: %s (%d/%d)" % ("OK" if ok else "FALLO",
                                      passed[0], total[0]))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="Archivos de PPH GOOD VPN")
    ap.add_argument("--file", help="catalogo crudo (base64) o JSON descifrado")
    ap.add_argument("--value", help="un campo cifrado suelto (Base64)")
    ap.add_argument("--parser-decode", help="decodificar un valor Parser.encode")
    ap.add_argument("--parser-encode", help="codificar con Parser.encode")
    ap.add_argument("--out", help="escribir el resultado en JSON")
    ap.add_argument("--self-test", action="store_true", help="pruebas offline")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    result = None
    if args.file:
        try:
            cat, fmt = open_catalog_file(args.file)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print("archivo: %s (formato %s)" % (args.file, fmt))
        print("Version: %s | FileName: %s | servidores: %d | redes: %d" % (
            cat.get("Version"), cat.get("FileName"),
            len(cat.get("Servers", [])), len(cat.get("HTTPNetworks", []))))
        result = cat
    elif args.value:
        dec = decrypt_field(args.value)
        if dec is None:
            print("DECRYPT_FAILED: el valor no abre con la clave secundaria",
                  file=sys.stderr)
            return 1
        print(dec)
        result = {"value": args.value, "decrypted": dec}
    elif args.parser_decode:
        print(parser_decode(args.parser_decode))
        result = {"parser_decode": parser_decode(args.parser_decode)}
    elif args.parser_encode:
        print(parser_encode(args.parser_encode))
        result = {"parser_encode": parser_encode(args.parser_encode)}
    else:
        ap.print_help()
        return 2

    if args.out and result is not None:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)
        print("escrito en: %s" % args.out)
    elif args.out:
        print("nada que escribir", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
