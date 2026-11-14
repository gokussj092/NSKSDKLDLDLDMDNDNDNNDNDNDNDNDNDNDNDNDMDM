#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IGNIX VPN MAX — lector de archivos locales para SP-DECODE.

Paquete: http.ignixmax.vpn — versión 44 / versionCode 44.

La app NO tiene formato propio de archivo importable por el usuario:
el manifiesto no declara ningún intent-filter de ACTION_VIEW /
ACTION_GET_CONTENT para archivos de configuración, y no existe ninguna
extensión propia (.ignix o similar) ni esquema URI propio. Lo que la app
sí guarda en su almacenamiento interno (filesDir) es el catálogo ya
descifrado:
  - Config.json          (catálogo gratuito descifrado)
  - ConfigPremium.json   (catálogo VIP descifrado)
Ambos son JSON en claro con la misma estructura del catálogo (Version /
Servers / Networks, por analogía con la familia Prominex — ver JyFast;
la forma exacta de IGNIX no está confirmada porque aún no se ha obtenido
un catálogo autenticado).

Este script lee uno de esos archivos (o un cuerpo crudo guardado con
--raw-out de IGNIX_VPN_MAX.py) y resume su contenido: claves de nivel
superior, versión, número de servidores y de payloads (redes) cuando
están presentes. Si el archivo es el cuerpo cifrado del catálogo (no
JSON), lo reporta como CIPHER_PENDING con su SHA-256 en lugar de
inventar un contenido.

Uso:
  python3 IGNIX_VPN_MAX_archivos.py Config.json
  python3 IGNIX_VPN_MAX_archivos.py ConfigPremium.json --json
  python3 IGNIX_VPN_MAX_archivos.py --self-test

Solo stdlib de Python 3.10+. Sin dependencias.
"""

import argparse
import hashlib
import json
import sys

SERVER_KEYS = ("Servers", "servers")
NETWORK_KEYS = ("Networks", "networks", "NetworksAuto", "networksAuto")
VERSION_KEYS = ("Version", "version", "AppVersion", "appVersion")


def read_config(path):
    """Lee Config.json / ConfigPremium.json (o un cuerpo crudo) y resume."""
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return {"status": "CIPHER_PENDING", "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "note": "el archivo no es UTF-8: cuerpo cifrado o binario"}
    try:
        obj = json.loads(text)
    except ValueError:
        return {"status": "CIPHER_PENDING", "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "head": data[:64].hex(),
                "note": "el archivo no es JSON: cuerpo cifrado del catálogo"}
    if not isinstance(obj, dict):
        return {"status": "ERROR", "error": "JSON de nivel superior no es objeto"}
    if "error" in obj:
        return {"status": "ERROR", "error": obj.get("error"), "raw": obj}
    servers = None
    for key in SERVER_KEYS:
        if isinstance(obj.get(key), list):
            servers = obj[key]
            break
    payloads = None
    for key in NETWORK_KEYS:
        if isinstance(obj.get(key), list):
            payloads = obj[key] if payloads is None else payloads + obj[key]
            break
    version = None
    for key in VERSION_KEYS:
        if obj.get(key) is not None:
            version = obj[key]
            break
    names = []
    if isinstance(servers, list):
        names = [s.get("Name") or s.get("name") or s.get("ServerIP")
                 for s in servers if isinstance(s, dict)][:10]
    return {
        "status": "OK",
        "file": path,
        "top_level_keys": sorted(obj.keys()),
        "version": version,
        "servers": len(servers) if isinstance(servers, list) else None,
        "payloads": len(payloads) if isinstance(payloads, list) else None,
        "sample_names": names,
        "catalog": obj,
    }


def summarize(result):
    if result["status"] == "OK":
        return ("archivo OK: versión %s, %s servidores, %s payloads "
                "(claves: %s)"
                % (result.get("version"), result.get("servers"),
                   result.get("payloads"),
                   ", ".join(result.get("top_level_keys", []))))
    if result["status"] == "ERROR":
        return "error: %s" % result.get("error")
    return ("archivo cifrado/pendiente: %d bytes, SHA-256 %s"
            % (result["size"], result["sha256"]))


def self_test():
    """Prueba con un Config.json sintético con la forma de la familia
    Prominex (JyFast: Version + Servers con Name). El archivo real de
    IGNIX aún no existe: la forma exacta de su catálogo está pendiente
    de obtener un catálogo autenticado. Esta prueba solo verifica la
    lógica de resumen JSON, no el formato real de IGNIX."""
    import tempfile
    import os
    synthetic = {
        "Version": "1.0.0",
        "Servers": [
            {"Name": "Servidor sintético 1", "ServerIP": "10.0.0.1"},
            {"Name": "Servidor sintético 2", "ServerIP": "10.0.0.2"},
        ],
        "Networks": [{"Name": "Payload sintético"}],
    }
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(synthetic, fh)
        result = read_config(path)
        ok = (result["status"] == "OK" and result["version"] == "1.0.0"
              and result["servers"] == 2 and result["payloads"] == 1)
        print("self-test Config.json sintético: %s" % summarize(result))
        # Y un cuerpo no JSON debe reportarse como pendiente, no romperse.
        fd2, path2 = tempfile.mkstemp(suffix=".bin")
        try:
            with os.fdopen(fd2, "wb") as fh:
                fh.write(b"\x01\x02\x03cuerpo-cifrado-ficticio")
            result2 = read_config(path2)
            ok2 = result2["status"] == "CIPHER_PENDING"
            print("self-test cuerpo cifrado: %s" % summarize(result2))
        finally:
            os.unlink(path2)
        return ok and ok2
    finally:
        os.unlink(path)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="IGNIX VPN MAX — lector de Config.json/ConfigPremium.json.")
    parser.add_argument("path", nargs="?", default=None,
                        help="Config.json o ConfigPremium.json de la app")
    parser.add_argument("--json", action="store_true",
                        help="imprimir el resultado completo como JSON")
    parser.add_argument("--self-test", action="store_true",
                        help="prueba con archivos sintéticos")
    args = parser.parse_args(argv)
    if args.self_test:
        ok = self_test()
        print("SELF-TEST %s" % ("OK" if ok else "FALLIDO"))
        return 0 if ok else 1
    if not args.path:
        parser.error("falta la ruta del archivo (o usa --self-test)")
    try:
        result = read_config(args.path)
    except OSError as exc:
        print("ERROR: no se pudo leer %s: %s" % (args.path, exc), file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(summarize(result))
    return 0 if result["status"] == "OK" else 2


if __name__ == "__main__":
    raise SystemExit(main())
