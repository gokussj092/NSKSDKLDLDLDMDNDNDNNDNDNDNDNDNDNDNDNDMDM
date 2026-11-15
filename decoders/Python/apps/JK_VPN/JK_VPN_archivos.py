#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JK VPN (FastVPN JK) — com.fastvpn.jk — v1.5 (versionCode 15).
Archivos para SP-DECODE.

FORMATOS
--------
1. .hs — el archivo de catalogo de la app (lo que descarga de su URL fija).
   Base64 de un cifrado Tink Streaming AEAD (AES-256-GCM-HKDF); al
   descifrarlo sale el JSON {"Version","Message","Servers","Networks",
   "setOpenVPN"}. Ver JK_VPN_catalogo.py para el metodo completo.
   Este script descifra un .hs local y tambien cifra JSON -> .hs
   (round-trip: salt y nonce-prefix aleatorios por archivo, como Tink).
2. profile.enc — donde la app guarda el catalogo ya descifrado en el
   telefono (getFilesDir()/profile.enc). Esta cifrado con el MISMO
   Streaming AEAD pero con una clave guardada en el Android Keystore del
   dispositivo (master key "android-keystore://private_master_key",
   keyset "StreamingAeadKeyset", prefs "StreamingCryptoPreferences").
   NO se puede descifrar fuera del telefono que lo creo: este script no
   lo intenta; documentado aqui para no confundirlo con el .hs.
3. Valores ED: — dentro del JSON, los campos sensibles van como
   "ED:" + Base32 (bj1.a/b). Sin prefijo, la app prueba Base64 plano.
   ed-decodificar / ed-codificar replican bj1.a / bj1.b.
4. Enlaces de texto — la app (base v2rayNG) acepta enlaces estandar:
   vmess://, vless://, trojan://, ss:// y socks:// (enum fy), ademas de
   URLs de suscripcion (lista Base64 de enlaces vmess://). No tiene
   esquema URI propio ni deep-link en el manifest. El subcomando
   "enlaces" extrae los enlaces v2ray ya descifrados del catalogo.
   Los campos "v2ray" del catalogo son enlaces vless:// completos.
5. OpenVPN — el campo "openvpnCert" (ED:) es una configuracion .ovpn
   completa de cliente; el subcomando "ovpn" la exporta a archivos .ovpn.

NUBE
----
No hay cuenta, registro de dispositivo, codigos para compartir ni
creditos: el catalogo es un archivo publico y la app no tiene endpoints
de nube. La unica URL es la del catalogo (ver JK_VPN_catalogo.py).
"""
import argparse
import base64
import binascii
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from JK_VPN_catalogo import (
        CIPHERTEXT_SEGMENT_SIZE,
        HEADER_SIZE,
        HKDF_INFO,
        NONCE_PREFIX_SIZE,
        PLAINTEXT_SEGMENT_SIZE,
        SALT_SIZE,
        TEST_VECTOR_HS_B64,
        TEST_VECTOR_JSON,
        descifrar_hs_b64,
        descifrar_hs_bytes,
        decodificar_valor,
        gcm_encrypt,
        hkdf_sha256,
        limpiar_catalogo,
        pbkdf2_ikm,
    )
except ImportError as e:  # pragma: no cover
    sys.stderr.write("Falta JK_VPN_catalogo.py en el mismo directorio: %s\n" % e)
    raise

# ---------------------------------------------------------------- ED: (bj1.b)
def ed_codificar(texto):
    """Replica bj1.b: Base32 del texto UTF-8 con prefijo 'ED:'."""
    if texto is None or texto == "":
        return ""
    return "ED:" + base64.b32encode(texto.encode("utf-8")).decode("ascii")

def ed_decodificar(valor):
    """Replica bj1.a (ver JK_VPN_catalogo.decodificar_valor)."""
    return decodificar_valor(valor)

# ---------------------------------------------------------------- cifrar .hs
def cifrar_hs_bytes(plaintext, salt=None, nonce_prefix=None):
    """Cifra JSON (bytes) a bytes de .hs (sin Base64), estilo Tink Streaming
    AEAD: cabecera 40 B + segmentos. Salt/nonce aleatorios si no se dan."""
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    if nonce_prefix is None:
        nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)
    if len(salt) != SALT_SIZE or len(nonce_prefix) != NONCE_PREFIX_SIZE:
        raise ValueError("salt 32 B y nonce-prefix 7 B")
    ikm = pbkdf2_ikm()
    key = hkdf_sha256(ikm, salt, HKDF_INFO, 32)
    out = bytearray(bytes([HEADER_SIZE]) + salt + nonce_prefix)
    # Segmentos de plaintext: primero 4040 B, luego 4080 B.
    chunks = []
    first_len = PLAINTEXT_SEGMENT_SIZE - HEADER_SIZE  # 4040
    chunks.append(plaintext[:first_len])
    off = first_len
    while off < len(plaintext):
        chunks.append(plaintext[off:off + PLAINTEXT_SEGMENT_SIZE])
        off += len(chunks[-1])
    if not chunks:
        chunks = [b""]
    for i, chunk in enumerate(chunks):
        last = 1 if i == len(chunks) - 1 else 0
        nonce = nonce_prefix + struct.pack(">I", i) + bytes([last])
        out += gcm_encrypt(key, nonce, chunk)
    return bytes(out)

def cifrar_hs_b64(plaintext, salt=None, nonce_prefix=None):
    """Cifra JSON (bytes) a .hs en Base64 (una linea, como la app)."""
    return base64.b64encode(
        cifrar_hs_bytes(plaintext, salt, nonce_prefix)).decode("ascii")

def cargar_catalogo_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

# ---------------------------------------------------------------- enlaces / ovpn
def extraer_enlaces(obj):
    """Enlaces v2ray (vless://, vmess://, ...) ya descifrados del catalogo.
    Devuelve lista de (nombre_servidor, enlace)."""
    obj = limpiar_catalogo(obj)
    enlaces = []
    for s in obj.get("Servers", []) or []:
        v2ray = (s.get("v2ray") or "").strip()
        if v2ray:
            enlaces.append((s.get("name", ""), v2ray))
    return enlaces

def exportar_ovpn(obj, directorio):
    """Exporta cada openvpnCert descifrado a <nombre>.ovpn. Devuelve rutas."""
    obj = limpiar_catalogo(obj)
    os.makedirs(directorio, exist_ok=True)
    rutas = []
    for s in obj.get("Servers", []) or []:
        cert = (s.get("openvpnCert") or "").strip()
        if not cert:
            continue
        nombre = re.sub(r"[^A-Za-z0-9_.-]+", "_", s.get("name", "servidor")).strip("_")
        ruta = os.path.join(directorio, nombre + ".ovpn")
        with open(ruta, "w", encoding="utf-8") as f:
            f.write(cert if cert.endswith("\n") else cert + "\n")
        rutas.append(ruta)
    return rutas

# ---------------------------------------------------------------- self-test
def self_test():
    ok = []

    def check(nombre, cond):
        ok.append((nombre, bool(cond)))
        print(("OK  " if cond else "FALLO ") + nombre)
        return cond

    check("ED: codificar", ed_codificar("kindssh1.kind-vpn.com") ==
          "ED:NNUW4ZDTONUDCLTLNFXGILLWOBXC4Y3PNU======")
    check("ED: decodificar", ed_decodificar("ED:NNUW4ZDTONUDCLTLNFXGILLWOBXC4Y3PNU======") ==
          "kindssh1.kind-vpn.com")
    check("ED: round-trip", ed_decodificar(ed_codificar("usuario:clave 123")) ==
          "usuario:clave 123")
    check("ED: vacio", ed_codificar("") == "" and ed_decodificar("") == "")
    # Vector .hs embebido: descifrar con el modulo catalogo
    try:
        obj = descifrar_hs_b64(TEST_VECTOR_HS_B64)
        check("vector .hs descifra", obj == TEST_VECTOR_JSON)
    except Exception as e:
        check("vector .hs descifra (%s)" % e, False)
    # Round-trip cifrar -> descifrar (salt/nonce aleatorios)
    try:
        plain = json.dumps(TEST_VECTOR_JSON, ensure_ascii=False).encode("utf-8")
        hs = cifrar_hs_bytes(plain)
        check("cifrar .hs cabecera 40", hs[0] == 40 and len(hs) == 40 + len(plain) + 16)
        check("round-trip .hs", descifrar_hs_bytes(hs) == TEST_VECTOR_JSON)
        b64 = cifrar_hs_b64(plain)
        check("round-trip .hs Base64", descifrar_hs_b64(b64) == TEST_VECTOR_JSON)
    except Exception as e:
        check("round-trip .hs (%s)" % e, False)
    # Round-trip con catalogo grande (varios segmentos): JSON sintetico > 8 KB
    try:
        grande = {"Version": "1.0", "Message": "x" * 100,
                  "Servers": [{"type": "OpenVPN", "name": "S%02d" % i,
                               "host": "ED:NNUW4ZDTONUDCLTLNFXGILLWOBXC4Y3PNU======",
                               "openvpnCert": "ED:" + base64.b32encode(
                                   ("client\nremote test %d\n" % i).encode()).decode()}
                              for i in range(60)],
                  "Networks": [], "setOpenVPN": ""}
        plain = json.dumps(grande, ensure_ascii=False).encode("utf-8")
        check("catalogo grande %d B (3 segmentos)" % len(plain), len(plain) > 8120)
        check("round-trip multi-segmento",
              descifrar_hs_bytes(cifrar_hs_bytes(plain)) == grande)
        check("enlaces en catalogo grande",
              extraer_enlaces(grande) == [])
        check("ovpn exporta 60",
              len(exportar_ovpn(grande, "/tmp/jkvpn_ovpn_test")) == 60)
    except Exception as e:
        check("catalogo grande (%s)" % e, False)
    fallos = [n for n, c in ok if not c]
    print("self-test: %d/%d OK" % (len(ok) - len(fallos), len(ok)))
    return not fallos

# ---------------------------------------------------------------- CLI
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="JK VPN (com.fastvpn.jk) 1.5 — archivos .hs, valores ED:, enlaces y .ovpn")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("descifrar", help="descifrar un .hs local a JSON")
    p.add_argument("archivo", help="archivo .hs (Base64)")
    p.add_argument("-o", "--salida", help="JSON de salida (por defecto, stdout)")
    p.add_argument("--crudo", action="store_true",
                   help="no aplicar la limpieza ED:/Base64")
    p = sub.add_parser("cifrar", help="cifrar un JSON de catalogo a .hs")
    p.add_argument("archivo", help="JSON de catalogo")
    p.add_argument("-o", "--salida", help=".hs de salida (por defecto, stdout)")
    p = sub.add_parser("ed-decodificar", help="decodificar un valor ED: o Base64")
    p.add_argument("valor", help="valor a decodificar")
    p = sub.add_parser("ed-codificar", help="codificar texto a ED: (Base32)")
    p.add_argument("texto", help="texto a codificar")
    p = sub.add_parser("enlaces", help="extraer enlaces v2ray del catalogo")
    p.add_argument("archivo", help="JSON de catalogo (limpio o crudo) o .hs")
    p.add_argument("-o", "--salida", help="archivo de texto con los enlaces")
    p = sub.add_parser("ovpn", help="exportar openvpnCert a archivos .ovpn")
    p.add_argument("archivo", help="JSON de catalogo (limpio o crudo) o .hs")
    p.add_argument("directorio", help="directorio de salida")
    ap.add_argument("--self-test", action="store_true", help="ejecutar self-test")
    args = ap.parse_args(argv)

    if args.self_test:
        return 0 if self_test() else 1

    if args.cmd == "descifrar":
        with open(args.archivo, "rb") as f:
            obj = descifrar_hs_b64(f.read())
        if not args.crudo:
            obj = limpiar_catalogo(obj)
        texto = json.dumps(obj, ensure_ascii=False, indent=2)
        if args.salida:
            with open(args.salida, "w", encoding="utf-8") as f:
                f.write(texto + "\n")
        else:
            sys.stdout.write(texto + "\n")
        return 0

    if args.cmd == "cifrar":
        obj = cargar_catalogo_json(args.archivo)
        plain = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        b64 = cifrar_hs_b64(plain)
        if args.salida:
            with open(args.salida, "w", encoding="utf-8") as f:
                f.write(b64 + "\n")
        else:
            sys.stdout.write(b64 + "\n")
        return 0

    if args.cmd == "ed-decodificar":
        print(ed_decodificar(args.valor))
        return 0

    if args.cmd == "ed-codificar":
        print(ed_codificar(args.texto))
        return 0

    if args.cmd in ("enlaces", "ovpn"):
        if args.archivo.lower().endswith(".hs"):
            with open(args.archivo, "rb") as f:
                obj = descifrar_hs_b64(f.read())
        else:
            obj = cargar_catalogo_json(args.archivo)
        if args.cmd == "enlaces":
            enlaces = extraer_enlaces(obj)
            texto = "".join("%s\t%s\n" % (n, e) for n, e in enlaces)
            if args.salida:
                with open(args.salida, "w", encoding="utf-8") as f:
                    f.write(texto)
            else:
                sys.stdout.write(texto)
            print("%d enlaces v2ray" % len(enlaces), file=sys.stderr)
        else:
            rutas = exportar_ovpn(obj, args.directorio)
            for r in rutas:
                print(r)
            print("%d archivos .ovpn" % len(rutas), file=sys.stderr)
        return 0

    ap.print_help()
    return 2

if __name__ == "__main__":
    sys.exit(main())
