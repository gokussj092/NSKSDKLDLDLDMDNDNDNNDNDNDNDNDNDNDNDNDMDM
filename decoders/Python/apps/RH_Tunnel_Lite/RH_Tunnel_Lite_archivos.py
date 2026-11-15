#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RH Tunnel Lite (com.rhtunnelmax.app) 39.0.1 - Decodificador de archivos SP-DECODE
================================================================================
Formatos que abre este script (todos verificados contra la APK 39.0.1):

  1. sabconfig.hs / rhtunnel.json / Servers.js (blob cifrado):
     Doble capa AES (util.decrypt x2): empaquetado chino de 12 bits + AES/CBC/
     PKCS7 con clave SHA-256, IV cero. El texto lleva el prefijo
     "Telegram@noob_xman" antes del JSON. Es el mismo formato del asset
     integrado de la APK y del catalogo en vivo de GitHub.

  2. Enlaces de texto (compartir por portapapeles; la app NO registra scheme
     en el manifest, se importan pegando el texto):
       SabDev://<XXTEA-Base64>  -> JSON de UN servidor (17 campos)
       shanS://<XXTEA-Base64>   -> JSON de UNA red/payload (23 campos)
     XXTEA con delta no estandar, Base64 estandar. Este script tambien los
     GENERA a partir de un JSON (round-trip verificado).

  3. Archivos .hs exportados: la app guarda en <externo>/TkProGen/<nombre>.hs
     (c_01.save). En 39.0.1 ese metodo no tiene llamadas visibles en el codigo
     descompilado; el flujo de compartir activo es el de los enlaces 2.
     Este script abre un .hs probando en orden: enlace SabDev:// / shanS://,
     blob doble-AES, JSON en claro, y XXTEA-Base64 suelto. Si Pedro aporta un
     .hs real exportado por la app, se ajusta el envoltorio exacto.

Uso:
  python3 RH_Tunnel_Lite_archivos.py ARCHIVO            # detecta y descifra
  python3 RH_Tunnel_Lite_archivos.py --link 'SabDev://...'
  python3 RH_Tunnel_Lite_archivos.py --link 'shanS://...'
  python3 RH_Tunnel_Lite_archivos.py --make-link servidor.json [--kind server|network]
  python3 RH_Tunnel_Lite_archivos.py --make-hs servidor.json SALIDA.hs
  python3 RH_Tunnel_Lite_archivos.py --self-test

Reutiliza la criptografia de RH_Tunnel_Lite.py (mismo directorio).
Solo biblioteca estandar.
"""

import argparse
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from RH_Tunnel_Lite import (  # noqa: E402
    c01_decrypt, c01_encrypt, parse_catalog, sab_decrypt, sab_encrypt,
    _PREFIX, maybe_xxtea,
)

SERVER_FIELDS = [
    "Name", "serverType", "FLAG", "Category", "V2rayType", "V2rayID",
    "ServerIP", "sUdpObfs", "ServerCloudFront", "ServerHTTP", "TcpPort",
    "SSLPort", "ProxyHost", "ProxyPort", "AutoLogIn", "Username", "Password",
    "MultiCert", "ovpnCertificate", "Server_exp_box", "Server_exp",
    "server_web_renew", "isAddOrEdited",
]

NETWORK_FIELDS = [
    "FLAG", "proto_spin", "server_type", "payload_type", "Name",
    "NetworkPayload", "V2rayPayloadType", "Info", "UseDefProxy",
    "AutoReplace", "SquidProxy", "SquidPort", "NetworkFrontQuery",
    "NetworkBackQuery", "SSLSNI", "SSLPort", "isAddOrEdited",
]


def decode_link(text):
    """Descifra un enlace SabDev:// o shanS:// y devuelve (kind, dict)."""
    text = text.strip()
    for prefix, kind in (("SabDev://", "server"), ("shanS://", "network")):
        if text.startswith(prefix):
            raw = c01_decrypt(text[len(prefix):])
            if raw is None:
                raise ValueError("XXTEA no abre el enlace %s" % prefix)
            obj = json.loads(raw)
            return kind, {k: maybe_xxtea(v) for k, v in obj.items()}
    raise ValueError("no es un enlace SabDev:// ni shanS://")


def encode_link(kind, obj):
    """Construye un enlace SabDev:// (server) o shanS:// (network)."""
    fields = SERVER_FIELDS if kind == "server" else NETWORK_FIELDS
    sub = {k: obj[k] for k in fields if k in obj}
    prefix = "SabDev://" if kind == "server" else "shanS://"
    return prefix + c01_encrypt(json.dumps(sub, ensure_ascii=False))


def decode_text(text):
    """Detecta el formato de un texto y devuelve (formato, objeto)."""
    t = text.strip()
    if not t:
        raise ValueError("texto vacio")
    if t.startswith("SabDev://") or t.startswith("shanS://"):
        kind, obj = decode_link(t)
        return "link-" + kind, obj
    if t.startswith("{"):
        return "json-claro", parse_catalog(t)
    # Blob doble-AES (sabconfig.hs / rhtunnel.json / Servers.js cifrado)
    try:
        raw = sab_decrypt(t)
        if raw.startswith(_PREFIX.encode()):
            raw = raw[len(_PREFIX):]
        return "sab-blob", parse_catalog(raw.decode("utf-8"))
    except Exception:
        pass
    # XXTEA-Base64 suelto
    try:
        raw = c01_decrypt(t)
        if raw is not None:
            return "xxtea-base64", json.loads(raw)
    except Exception:
        pass
    raise ValueError("formato no reconocido (ni enlace, ni JSON, ni blob sab, ni XXTEA)")


def decode_file(path):
    with open(path, "r", encoding="utf-8", errors="strict") as f:
        text = f.read()
    return decode_text(text)


def make_hs(obj, kind, out_path):
    """Escribe un .hs con el enlace de compartir (el payload que la app
    comparte por portapapeles). Envoltorio exacto pendiente de un .hs real."""
    link = encode_link(kind, obj)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(link)
    return link


def self_test():
    ok = 0
    fails = []

    def check(name, cond):
        nonlocal ok
        if cond:
            ok += 1
            print("  OK  " + name)
        else:
            fails.append(name)
            print("  FAIL " + name)

    print("RH Tunnel Lite (archivos) --self-test")
    here = os.path.dirname(os.path.abspath(__file__))

    # 1. Asset real de la APK: sabconfig.hs integrado (Version 200.8)
    asset = os.path.join(here, "apk", "assets", "sabconfig.hs")
    if os.path.exists(asset):
        fmt, obj = decode_file(asset)
        check("sabconfig.hs real de la APK abre (%s, Version %s, %d servidores)"
              % (fmt, obj.get("Version"), len(obj.get("Servers", []))),
              fmt == "sab-blob" and len(obj.get("Servers", [])) == 17)
    else:
        print("  SKIP sabconfig.hs (no esta apk/assets/sabconfig.hs)")

    # 2. Blob en vivo descargado (si existe la muestra)
    live = os.path.join(here, "samples", "rhtunnel.json")
    if os.path.exists(live):
        fmt, obj = decode_file(live)
        check("rhtunnel.json en vivo abre (%s, Version %s, %d servidores, %d redes)"
              % (fmt, obj.get("Version"), len(obj.get("Servers", [])),
                 len(obj.get("HTTPNetworks", []))),
              fmt == "sab-blob" and len(obj.get("Servers", [])) == 17
              and len(obj.get("HTTPNetworks", [])) == 200)
    else:
        print("  SKIP rhtunnel.json en vivo (no esta samples/rhtunnel.json)")

    # 3. Enlaces round-trip con datos reales del catalogo en vivo
    live_dec = os.path.join(here, "samples", "catalogo-en-vivo.json")
    if os.path.exists(live_dec):
        doc = json.load(open(live_dec, encoding="utf-8"))
        srv = doc["Servers"][0]
        link = encode_link("server", srv)
        kind, back = decode_link(link)
        check("SabDev:// round-trip con servidor real (IP %s)" % back.get("ServerIP"),
              kind == "server" and back.get("ServerIP") == srv.get("ServerIP")
              and back.get("Name") == srv.get("Name"))
        net = doc["HTTPNetworks"][0]
        link2 = encode_link("network", net)
        kind2, back2 = decode_link(link2)
        check("shanS:// round-trip con red real (SNI %s)" % back2.get("SSLSNI"),
              kind2 == "network" and back2.get("SSLSNI") == net.get("SSLSNI"))
        # 4. .hs sintetico (enlace dentro de .hs) round-trip
        import tempfile
        fd, tmp = tempfile.mkstemp(suffix=".hs")
        os.close(fd)
        make_hs(srv, "server", tmp)
        fmt4, back4 = decode_file(tmp)
        check(".hs sintetico (enlace SabDev://) abre", fmt4 == "link-server"
              and back4.get("ServerIP") == srv.get("ServerIP"))
        os.remove(tmp)
    else:
        print("  SKIP round-trips con catalogo real (no esta samples/catalogo-en-vivo.json)")

    # 5. Blob sintetico doble-AES round-trip
    mini = {"FileName": "update", "Version": "9.9-test", "Servers": [], "HTTPNetworks": []}
    blob = sab_encrypt((_PREFIX + json.dumps(mini)).encode("utf-8"))
    fmt5, back5 = decode_text(blob)
    check("blob sintetico doble-AES abre", fmt5 == "sab-blob" and back5["Version"] == "9.9-test")

    print("self-test: %d OK, %d FAIL" % (ok, len(fails)))
    return 1 if fails else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="RH Tunnel Lite - decodificador de archivos")
    ap.add_argument("archivo", nargs="?", help="archivo a descifrar (.hs, .json, blob)")
    ap.add_argument("--link", metavar="ENLACE", help="descifrar un enlace SabDev:// o shanS://")
    ap.add_argument("--make-link", metavar="JSON", help="generar enlace desde un JSON de servidor/red")
    ap.add_argument("--kind", choices=["server", "network"], default="server",
                    help="tipo para --make-link / --make-hs")
    ap.add_argument("--make-hs", metavar="SALIDA.hs",
                    help="escribir .hs con el enlace generado desde --make-link")
    ap.add_argument("--out", metavar="ARCHIVO", help="guardar el JSON descifrado")
    ap.add_argument("--self-test", action="store_true", help="pruebas internas")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.make_link:
        with open(args.make_link, "r", encoding="utf-8") as f:
            obj = json.load(f)
        link = encode_link(args.kind, obj)
        if args.make_hs:
            with open(args.make_hs, "w", encoding="utf-8") as f:
                f.write(link)
            print("escrito %s" % args.make_hs)
        print(link)
        return 0

    if args.link:
        kind, obj = decode_link(args.link)
        result = obj
    elif args.archivo:
        fmt, obj = decode_file(args.archivo)
        print("formato: %s" % fmt)
        result = obj
    else:
        ap.print_help()
        return 2

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=1)
        print("guardado en %s" % args.out)
    print(json.dumps(result, ensure_ascii=False, indent=1)[:3000])
    return 0


if __name__ == "__main__":
    sys.exit(main())
