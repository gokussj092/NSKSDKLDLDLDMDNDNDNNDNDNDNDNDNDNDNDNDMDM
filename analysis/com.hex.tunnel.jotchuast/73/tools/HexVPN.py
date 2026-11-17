#!/usr/bin/env python3
"""HexVPN 1.7.3-Rev (com.hex.tunnel.jotchuast, build 73) — sonda de catalogo.

RESULTADO: NO_CATALOG. No existe un endpoint HTTP de catalogo recuperable
por analisis estatico de este build (ver README.md para la cadena completa
de evidencia). Este script NO inventa un catalogo: sondea el unico
endpoint publico conocido (Firebase Realtime Database del proyecto
hex-tunnel-afd6e, cuya URL viene en los recursos del APK) y registra el
resultado; todo devuelve 401 Permission denied sin autenticacion, y la
app NO incluye SDK de Realtime Database, Auth ni Firestore, asi que ese
endpoint no es la fuente del catalogo en la app.

Uso:
    python3 HexVPN.py --url        # responde NO_CATALOG con el motivo
    python3 HexVPN.py --probe      # sondea RTDB en vivo y escribe live.json
    python3 HexVPN.py --probe --out live.json
    python3 HexVPN.py --self-test  # comprobaciones offline (sin red)

Sin secretos ni tokens: la sonda es un GET anonimo sin autenticacion.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

APP = "HexVPN"
PACKAGE = "com.hex.tunnel.jotchuast"
VERSION_NAME = "1.7.3-Rev"
VERSION_CODE = 73
APKS_SHA256 = "df5c64a9cfde6a84908d3928c32a539a458a708f92550e9bc6736d7b3790d735"

RTDB_BASE = "https://hex-tunnel-afd6e-default-rtdb.firebaseio.com"
# Nodos candidatos probados sin autenticacion (todos 401). La lista es
# evidencia, no una suposicion: ninguno es legible en publico.
CANDIDATE_NODES = [
    "", "servers", "free_servers", "vip_servers", "free", "vip", "config",
    "updates", "version", "app_config", "server_list", "servers_list",
    "public", "catalog", "data", "settings", "info", "status",
    "freeServers", "vipServers", "all_servers", "serverlist", "hexvpn",
    "hex", "tunnel", "announcements", "notices",
]

HERE = Path(__file__).resolve().parent


def no_catalog_report() -> dict:
    return {
        "application": APP,
        "package": PACKAGE,
        "version": VERSION_NAME,
        "versionCode": VERSION_CODE,
        "catalog": {"status": "NO_CATALOG"},
        "reason": (
            "No hay endpoint HTTP de catalogo recuperable por analisis "
            "estatico: las URLs viven en metodos cifrados con KovSec "
            "(AppConfig.updatesJsonUrl/serversUpdateUrl, "
            "ServerUpdateManager, ServerCatalogStore, ServerPresence); "
            "la app no incluye SDK de Firebase Database/Auth/Firestore; "
            "el RTDB del proyecto responde 401 sin autenticacion en la "
            "raiz y en todos los nodos candidatos; no hay URL en recursos, "
            "assets ni librerias nativas, ni catalogo embebido."
        ),
        "what_would_confirm": (
            "Captura de red en un telefono durante 'buscar actualizaciones' "
            "en la app (revela updatesJsonUrl/serversUpdateUrl y el "
            "User-Agent real), o un .hexcm real exportado por este build."
        ),
    }


def _probe_url(url: str, timeout: int = 15) -> tuple[int | None, str]:
    req = urllib.request.Request(url, method="GET", headers={
        "User-Agent": "HexVPN-catalog-probe/1.0",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(512).decode("utf-8", "replace")
            return resp.status, body
    except urllib.error.HTTPError as err:
        try:
            body = err.read(512).decode("utf-8", "replace")
        except Exception:
            body = ""
        return err.code, body
    except Exception as err:  # red caida, DNS, timeout...
        return None, f"{type(err).__name__}: {err}"


def run_probe(out: Path) -> dict:
    stamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    probes = []
    for node in CANDIDATE_NODES:
        url = f"{RTDB_BASE}/{node}.json" if node else f"{RTDB_BASE}/.json"
        status, body = _probe_url(url)
        probes.append({
            "node": node or "(root)",
            "url": url,
            "http_status": status,
            "body_snippet": body.strip()[:120],
        })
        print(f"  {node or '(root)'} -> {status} {body.strip()[:80]}")
    report = {
        **no_catalog_report(),
        "probed_at_utc": stamp,
        "probed_endpoint": RTDB_BASE,
        "probes": probes,
        "servers": [],
        "networks": [],
        "payloads": [],
        "catalog_version": None,
        "note": (
            "live.json NO contiene servidores: el catalogo en vivo no se "
            "pudo descargar ni descifrar. En este JSON no van APIs de "
            "descarga; solo datos descifrados, y aqui no hay ninguno."
        ),
    }
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return report


def _synthetic_doc() -> dict:
    return {
        "version": 1,
        "server": {
            "name": "SYNTHETIC-TEST",
            "host": "127.0.0.1",
            "port": 443,
            "user": "test",
            "password": "test",
        },
        "meta": {"blocked": False},
    }


def _seal(doc: dict, double: bool, fd) -> bytes:
    """Sella un documento sintetico con las mismas primitivas del lector.

    Usa las constantes del propio modulo HexVPN_archivos (sin
    imprimirlas) para que la prueba sea un round-trip real del codigo
    entregado, no una reimplementacion aparte.
    """
    import base64
    import hashlib as _hashlib
    import os as _os
    from Crypto.Cipher import AES, ChaCha20_Poly1305

    unsigned = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
    signature = _hashlib.sha256(unsigned.encode() + fd.PASSWORD).hexdigest()
    signed = dict(doc)
    signed["signature"] = signature
    text = json.dumps(signed, ensure_ascii=False, separators=(",", ":"))
    inner = text.encode()
    if double:
        nonce = _os.urandom(12)
        cipher = ChaCha20_Poly1305.new(key=fd.INNER_KEY, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(inner)
        inner = base64.b64encode(nonce + ct + tag)
    salt = _os.urandom(16)
    nonce = _os.urandom(12)
    key = _hashlib.pbkdf2_hmac("sha256", fd.PASSWORD, salt, 100_000, 32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(inner)
    return base64.b64encode(salt + nonce + ct + tag)


def self_test() -> int:
    sys.path.insert(0, str(HERE))
    import HexVPN_archivos as fd

    failures = []

    def check(name: str, ok: bool, detail: str = ""):
        print(("ok   " if ok else "FAIL ") + name + (f" ({detail})" if detail and not ok else ""))
        if not ok:
            failures.append(name)

    # 1. El .apks de origen sigue siendo el verificado.
    src = Path.home() / "workspace/user/files/HexVPN_1.7.3-Rev_0_btjx.apks"
    if src.exists():
        digest = hashlib.sha256(src.read_bytes()).hexdigest()
        check("apks sha256", digest == APKS_SHA256)
    else:
        print("skip apks sha256 (archivo de origen no presente)")
    # 2. Round-trip sintetico sobre el lector entregado (simple y doble).
    doc = _synthetic_doc()
    for double in (False, True):
        try:
            wire = _seal(doc, double, fd)
            back, method = fd.decode_with_method(wire)
            check(f"round-trip {'doble' if double else 'simple'}",
                  back == {**doc, "signature": back["signature"]}
                  and back["server"] == doc["server"]
                  and back["meta"] == doc["meta"]
                  and ("chacha" in method) == double,
                  method)
        except Exception as err:
            check(f"round-trip {'doble' if double else 'simple'}", False, repr(err))
    # 3. Manipulacion rechazada (tag alterado y documento sin firma).
    try:
        import base64 as _b64
        wire = bytearray(_b64.b64decode(_seal(doc, False, fd)))
        wire[-1] ^= 1
        fd.decode_with_method(_b64.b64encode(bytes(wire)))
        check("tag alterado rechazado", False, "abrio sin error")
    except Exception:
        check("tag alterado rechazado", True)
    try:
        fd.decode_with_method(b"{}")
        check("documento vacio rechazado", False, "abrio sin error")
    except Exception:
        check("documento vacio rechazado", True)
    # 4. Icono 512x512 presente.
    png = HERE / "HexVPN.png"
    if png.exists():
        from PIL import Image
        with Image.open(png) as im:
            check("icono 512x512", im.size == (512, 512), str(im.size))
    else:
        check("icono 512x512", False, "falta HexVPN.png")
    # 5. --url responde NO_CATALOG.
    check("--url es NO_CATALOG",
          no_catalog_report()["catalog"]["status"] == "NO_CATALOG")
    print(f"self-test: {len(failures)} fallos")
    return 1 if failures else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", action="store_true",
                        help="Responde NO_CATALOG con el motivo")
    parser.add_argument("--probe", action="store_true",
                        help="Sondea el RTDB en vivo y escribe live.json")
    parser.add_argument("--out", default="live.json",
                        help="Destino del informe de la sonda (def: live.json)")
    parser.add_argument("--self-test", action="store_true",
                        help="Comprobaciones offline (sin red)")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.url:
        print(json.dumps(no_catalog_report(), ensure_ascii=False, indent=2))
        return 0
    if args.probe:
        out = Path(args.out)
        if not out.is_absolute():
            out = HERE / out
        print(f"Sondeando {RTDB_BASE} ({len(CANDIDATE_NODES)} nodos)...")
        report = run_probe(out)
        print(f"Informe en {out}")
        print(f"Catalogo: {report['catalog']['status']} "
              f"(servidores: {len(report['servers'])})")
        return 1
    parser.print_help()
    print()
    print(json.dumps(no_catalog_report(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
