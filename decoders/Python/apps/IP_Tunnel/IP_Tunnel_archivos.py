#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP Tunnel — decodificador de archivos exportados para SP-DECODE.

App: IP Tunnel, com.iptunnel.tunnel, 1.4.8-alpha (versionCode 49).

Formato de archivo propio (ExportActivity / w91.h)
--------------------------------------------------
La app NO registra extensión propia ni esquema URI en el manifest: la
exportación usa ACTION_CREATE_DOCUMENT (el usuario elige el nombre) y la
importación usa ACTION_GET_CONTENT (selector de archivos). El contenido
del archivo es UNA línea Base64:

    Base64( XXTEA( JSON_de_exportación , clave="@Adedayo's WeTunnel" ) )

XXTEA variante yy.l/yy.o, delta 0x9A7393B4 (la misma del catálogo); la
clave son los primeros 16 bytes UTF-8 de "@Adedayo's WeTunnel".

El JSON de exportación tiene: PSInstall, DeviceID, RootBlock, isBlockVPN,
isXposed, isBlockAppList, ConfigAppBlockList, MobileData, ExpireDate,
Message, Config (config de conexión, cadena JSON), Server (servidor,
cadena JSON o "none").

Firma (ce0): la app exige firma RSA válida al importar (vc.F = true).
Campos Sig (Base64url), SigTs, SigKid (debe ser "k1", vc.G), SigV,
SigAlg ("RS256"). Se verifica con SHA256withRSA y la clave pública
incrustada vc.H, sobre el payload canónico de 15 líneas separadas por
'\\n' (ce0.b): ExpireDate, RootBlock(1/0), MobileData(1/0), Message,
Config, Server, DeviceID, PSInstall(1/0), isBlockVPN(1/0),
isBlockAppList(1/0), ConfigAppBlockList, isXposed(1/0), SigTs, SigKid,
SigV. Este script VERIFICA la firma; no puede crear una válida (haría
falta la clave privada del vendedor), así que un archivo re-cifrado con
--encrypt se puede LEER aquí pero la app lo rechazará al importar
("Invalid config signature") si no lleva una firma válida.

Este script también abre blobs del catálogo (misma envoltura XXTEA con
la clave del catálogo vc.z), como el valor DATA de system.db
(tabla iptunnel_table): prueba primero la clave de exportación y luego
la del catálogo, e informa cuál abrió el archivo.

Uso:
    python3 IP_Tunnel_archivos.py archivo_exportado [--summary] [-o salida.json]
    python3 IP_Tunnel_archivos.py --stdin
    python3 IP_Tunnel_archivos.py --encrypt export.json [-o salida.b64]
    python3 IP_Tunnel_archivos.py --self-test

Solo stdlib de Python 3.
"""

import argparse
import base64
import hashlib
import json
import os
import sys

DELTA = 0x9A7393B4
MASK = 0xFFFFFFFF

EXPORT_KEY = "@Adedayo's WeTunnel"
CATALOG_KEY = (
    "8f3c7a1e6d2b4c9f0a5e1d7c3b8f6a2e9c4d1f7b0a3e6c2d5f8a1b9c7e4d2a6"
)

# Clave pública RSA incrustada en la app (vc.H) para verificar Sig.
VC_H_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuwTv8Z6TPjrZuCMPYN2r\n"
    "LJNPbYn6yhCZtP7PnZFl4xQI2rc1DUhCk3r5fUe2p6aQP4fKH0yhATQ6lT23iVHZ\n"
    "NWRhCJ/qZIM+RhGuoLUVhTLfmWrCgRRemCc8X0TzhrqUzPdCqRVsah1a1hfA2NcN\n"
    "UXdptVFIzTRGGiCFCLrNLBRZ2BXbC6XC7ExrV7TCf/eUIqeIKqK91YyMZwoFNC8E\n"
    "GiOyyy2+6lt2xsAm6TvtbagojiVElKbecrMVMAzfyrTNdjGt7xrkbwSQ5O/4XyLP\n"
    "55ZGJuDJKKTq6cQciy+dODNn00mhTlvjZcOWf5CQ+G4KairskwzlAufbhlgqbfI0\n"
    "NwIDAQAB\n"
    "-----END PUBLIC KEY-----\n"
)

_HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLED_CONFIG = os.path.join(_HERE, "bundled_config.b64")
LIVE_SAMPLE = os.path.join(_HERE, "catalog_sample.b64")


# ---------------------------------------------------------------- XXTEA
def _to_ints(data, include_length):
    n = len(data)
    length = (n >> 2) if (n & 3) == 0 else (n >> 2) + 1
    if include_length:
        v = [0] * (length + 1)
        v[length] = n
    else:
        v = [0] * length
    for i in range(n):
        v[i >> 2] |= (data[i] & 0xFF) << ((i & 3) << 3)
    return v


def _to_bytes(v, include_length):
    length = len(v) << 2
    if include_length:
        n = v[-1]
        if n < length - 7 or n > length - 4:
            return None
        length = n
    out = bytearray(length)
    for i in range(length):
        out[i] = (v[i >> 2] >> ((i & 3) << 3)) & 0xFF
    return bytes(out)


def _mx(sum_, y, z, p, k, e):
    return (
        (((sum_ ^ y) + ((k[(p & 3) ^ e] ^ z) & MASK)) & MASK)
        ^ ((((z >> 5) ^ ((y << 2) & MASK)) + ((y >> 3) ^ ((z << 4) & MASK))) & MASK)
    )


def xxtea_decrypt(data, key16):
    if len(data) == 0:
        return data
    v = _to_ints(data, False)
    k = _to_ints(key16, False)
    n = len(v)
    if n < 2:
        return None
    rounds = 6 + 52 // n
    sum_ = (rounds * DELTA) & MASK
    y = v[0]
    while sum_ != 0:
        e = (sum_ >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            y = (v[p] - _mx(sum_, y, z, p, k, e)) & MASK
            v[p] = y
        z = v[n - 1]
        y = (v[0] - _mx(sum_, y, z, 0, k, e)) & MASK
        v[0] = y
        sum_ = (sum_ - DELTA) & MASK
    return _to_bytes(v, True)


def xxtea_encrypt(data, key16):
    if len(data) == 0:
        return data
    v = _to_ints(data, True)
    k = _to_ints(key16, False)
    n = len(v)
    if n < 2:
        return None
    rounds = 6 + 52 // n
    sum_ = 0
    z = v[n - 1]
    for _ in range(rounds):
        sum_ = (sum_ + DELTA) & MASK
        e = (sum_ >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            z = (v[p] + _mx(sum_, y, z, p, k, e)) & MASK
            v[p] = z
        y = v[0]
        z = (v[n - 1] + _mx(sum_, y, z, n - 1, k, e)) & MASK
        v[n - 1] = z
    return _to_bytes(v, False)


def _key_bytes(keystr):
    key = keystr.encode("utf-8")
    if len(key) != 16:
        key = (key + b"\x00" * 16)[:16]
    return key


def yy_m(b64str, keystr):
    try:
        data = base64.b64decode("".join(b64str.split()))
    except Exception:
        return None
    pt = xxtea_decrypt(data, _key_bytes(keystr))
    if pt is None:
        return None
    try:
        return pt.decode("utf-8")
    except UnicodeDecodeError:
        return None


def yy_p(text, keystr):
    ct = xxtea_encrypt(text.encode("utf-8"), _key_bytes(keystr))
    if ct is None:
        return None
    return base64.b64encode(ct).decode("ascii")


# ---------------------------------------------------------------- firma RS256
def _der_read(data, pos):
    tag = data[pos]
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        nbytes = length & 0x7F
        length = int.from_bytes(data[pos:pos + nbytes], "big")
        pos += nbytes
    return tag, data[pos:pos + length], pos + length


def parse_spki_pem(pem):
    """Devuelve (n, e) de una clave pública RSA en formato PEM SPKI."""
    b64 = "".join(
        line.strip()
        for line in pem.splitlines()
        if "-----" not in line
    )
    der = base64.b64decode(b64)
    _, outer, _ = _der_read(der, 0)
    _, _alg, pos1 = _der_read(outer, 0)
    _, bitstring, _ = _der_read(outer, pos1)
    # _der_read sobre el contenido del BIT STRING: primer byte = nº de bits sin usar
    _, rsapub, _ = _der_read(bitstring, 1)
    _, n_bytes, p2 = _der_read(rsapub, 0)
    _, e_bytes, _ = _der_read(rsapub, p2)
    return int.from_bytes(n_bytes, "big"), int.from_bytes(e_bytes, "big")


_SHA256_DER_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)


def rsa_verify_rs256(payload, sig_b64url, n, e):
    """Verifica una firma RS256 (PKCS#1 v1.5 + SHA-256) en stdlib puro."""
    try:
        sig = base64.urlsafe_b64decode(sig_b64url + "=" * (-len(sig_b64url) % 4))
    except Exception:
        return False
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    m = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    digest = hashlib.sha256(payload.encode("utf-8")).digest()
    expected = b"\x00\x01" + b"\xff" * (k - len(_SHA256_DER_PREFIX) - len(digest) - 3) \
        + b"\x00" + _SHA256_DER_PREFIX + digest
    return m == expected


def canonical_payload(obj):
    """ce0.b: 15 líneas separadas por '\\n' (booleanos como 1/0)."""
    def b01(v):
        return "1" if v else "0"

    fields = [
        str(obj.get("ExpireDate", 0) or 0),
        b01(obj.get("RootBlock", False)),
        b01(obj.get("MobileData", False)),
        obj.get("Message", "") or "",
        obj.get("Config", "") or "",
        obj.get("Server", "") or "",
        obj.get("DeviceID", "") or "",
        b01(obj.get("PSInstall", False)),
        b01(obj.get("isBlockVPN", False)),
        b01(obj.get("isBlockAppList", False)),
        obj.get("ConfigAppBlockList", "") or "",
        b01(obj.get("isXposed", False)),
        str(obj.get("SigTs", 0) or 0),
        obj.get("SigKid", "") or "",
        str(obj.get("SigV", 1) or 1),
    ]
    return "\n".join(fields)


def has_signature(obj):
    return all(k in obj for k in ("Sig", "SigTs", "SigKid", "SigV"))


def signature_status(obj):
    """(presente, válida) según ce0.o / ce0.A."""
    if not has_signature(obj):
        return False, False
    if obj.get("SigAlg", "RS256") != "RS256":
        return True, False
    if obj.get("SigKid", "") != "k1":
        return True, False
    try:
        n, e = parse_spki_pem(VC_H_PEM)
        ok = rsa_verify_rs256(
            canonical_payload(obj), obj.get("Sig", ""), n, e
        )
    except Exception:
        return True, False
    return True, ok


# ---------------------------------------------------------------- decodificación
def decode_file_text(text):
    """Descifra un archivo exportado o un blob de catálogo.

    Devuelve (obj_json, clave_usada, firma_presente, firma_válida).
    """
    text = text.strip()
    if text.startswith("{"):
        obj = json.loads(text)
        return obj, "sin cifrar (JSON plano)", *signature_status(obj)
    for keystr, label in (
        (EXPORT_KEY, "exportación (@Adedayo's WeTunnel)"),
        (CATALOG_KEY, "catálogo (vc.z)"),
    ):
        plain = yy_m(text, keystr)
        if plain is None:
            continue
        try:
            obj = json.loads(plain)
        except json.JSONDecodeError:
            continue
        return obj, label, *signature_status(obj)
    raise ValueError(
        "DECODE_FAILED: el archivo no abre ni con la clave de exportación "
        "ni con la del catálogo"
    )


def summarize(obj, key_label, sig_present, sig_ok):
    lines = ["Clave que abrió el archivo: %s" % key_label]
    if "Servers" in obj and "Tweaks" in obj:
        lines.append("Tipo: blob de CATÁLOGO")
        lines.append("Version: %s" % obj.get("Version"))
        lines.append("Servidores: %d" % len(obj.get("Servers", [])))
        lines.append("Tweaks: %d" % len(obj.get("Tweaks", [])))
        return "\n".join(lines)
    lines.append("Tipo: archivo de CONFIGURACIÓN exportado")
    for field in (
        "PSInstall", "DeviceID", "RootBlock", "isBlockVPN", "isXposed",
        "isBlockAppList", "ConfigAppBlockList", "MobileData", "ExpireDate",
        "Message",
    ):
        lines.append("  %s: %s" % (field, obj.get(field)))
    config = obj.get("Config", "")
    server = obj.get("Server", "")
    lines.append("  Config: %s" % (config[:100] + ("..." if len(config) > 100 else "")))
    lines.append("  Server: %s" % (server[:100] + ("..." if len(server) > 100 else "")))
    if sig_present:
        lines.append("  Firma RS256: presente, válida=%s" % sig_ok)
    else:
        lines.append("  Firma RS256: AUSENTE (la app rechaza el archivo al importar)")
    return "\n".join(lines)


# ---------------------------------------------------------------- CLI
def self_test():
    ok = 0
    fails = []

    def check(name, cond):
        nonlocal ok
        if cond:
            ok += 1
            print("  OK   %s" % name)
        else:
            fails.append(name)
            print("  FAIL %s" % name)

    print("IP Tunnel archivos --self-test")
    # 1. Round-trip del formato de exportación.
    sample = {
        "PSInstall": False, "DeviceID": "", "RootBlock": False,
        "isBlockVPN": False, "isXposed": False, "isBlockAppList": False,
        "ConfigAppBlockList": "", "MobileData": True, "ExpireDate": 0,
        "Message": "prueba", "Config": "{\"Type\":1}",
        "Server": "none",
    }
    text = json.dumps(sample, separators=(",", ":"))
    blob = yy_p(text, EXPORT_KEY)
    obj, label, sig_p, sig_ok = decode_file_text(blob)
    check("export round-trip", obj == sample)
    check("export detecta clave de exportación", "exportación" in label)
    check("export sin firma -> ausente", sig_p is False)
    # 2. Blobs de catálogo (bundled + muestra viva) abren con la clave vc.z.
    with open(BUNDLED_CONFIG, "r", encoding="utf-8") as fh:
        obj_b, label_b, _, _ = decode_file_text(fh.read())
    check("bundled abre con clave de catálogo", "catálogo" in label_b)
    check("bundled Version 1.00", obj_b.get("Version") == "1.00")
    with open(LIVE_SAMPLE, "r", encoding="utf-8") as fh:
        obj_l, label_l, _, _ = decode_file_text(fh.read())
    check("live abre con clave de catálogo", "catálogo" in label_l)
    check("live Version 1.91", obj_l.get("Version") == "1.91")
    # 3. Payload canónico ce0.b (15 líneas, booleanos 1/0).
    payload = canonical_payload({
        "ExpireDate": 0, "RootBlock": True, "MobileData": False,
        "Message": "m", "Config": "c", "Server": "s", "DeviceID": "d",
        "PSInstall": False, "isBlockVPN": True, "isBlockAppList": False,
        "ConfigAppBlockList": "", "isXposed": False,
        "SigTs": 123, "SigKid": "k1", "SigV": 1,
    })
    check(
        "payload canónico 15 líneas",
        payload == "0\n1\n0\nm\nc\ns\nd\n0\n1\n0\n\n0\n123\nk1\n1",
    )
    # 4. Verificación RS256 con una clave de prueba (no la de la app):
    #    firma el payload canónico con d y comprueba con (n, e).
    test_n = 0x55abbcceefa0b9cfa8f82bffcb3bbe29adaec7b05834eaab85bd7e13f5a2d91da8237e73c26519d19a205396c473aa586fe779b2436137bb436b336a58dc8e1b
    test_e = 65537
    test_d = 0x1ef3c36d888a2b57e996705f24905b2e37c014099474d9ec4a8fa2039815d41745269425feefb509b1ae36c5121eb3818df7f50dfdfa032926173964d9499b01
    k = (test_n.bit_length() + 7) // 8
    digest = hashlib.sha256(payload.encode("utf-8")).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(_SHA256_DER_PREFIX) - len(digest) - 3) \
        + b"\x00" + _SHA256_DER_PREFIX + digest
    sig_int = pow(int.from_bytes(em, "big"), test_d, test_n)
    sig_b64 = base64.urlsafe_b64encode(
        sig_int.to_bytes(k, "big")).decode().rstrip("=")
    check("RS256 verifica firma de prueba", rsa_verify_rs256(payload, sig_b64, test_n, test_e))
    check("RS256 rechaza payload alterado",
          not rsa_verify_rs256(payload + "x", sig_b64, test_n, test_e))
    # 5. La clave pública incrustada vc.H parsea a RSA-2048.
    n, e = parse_spki_pem(VC_H_PEM)
    check("vc.H es RSA-2048", n.bit_length() == 2048 and e == 65537)
    print("%d/%d checks OK" % (ok, ok + len(fails)))
    return 0 if not fails else 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Decodificador de archivos exportados de IP Tunnel."
    )
    ap.add_argument("archivo", nargs="?", help="archivo exportado (Base64 XXTEA)")
    ap.add_argument("--stdin", action="store_true", help="lee el archivo de stdin")
    ap.add_argument("--encrypt", metavar="JSON",
                    help="cifra un JSON de exportación a blob Base64 (ojo: sin firma válida la app lo rechazará al importar)")
    ap.add_argument("-o", "--output", help="guarda el JSON descifrado / blob cifrado")
    ap.add_argument("--summary", action="store_true", help="muestra solo el resumen")
    ap.add_argument("--self-test", action="store_true", help="pruebas internas")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.encrypt:
        with open(args.encrypt, "r", encoding="utf-8") as fh:
            text = fh.read()
        json.loads(text)  # valida que sea JSON
        blob = yy_p(text, EXPORT_KEY)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(blob)
            print("Blob guardado en %s" % args.output)
        else:
            print(blob)
        print("AVISO: este blob NO lleva firma RS256 válida; la app lo rechazará "
              "al importar (se necesita la clave privada del vendedor).")
        return 0

    if args.stdin:
        text = sys.stdin.read()
    elif args.archivo:
        with open(args.archivo, "r", encoding="utf-8") as fh:
            text = fh.read()
    else:
        ap.error("indica un archivo, --stdin o --encrypt")

    obj, label, sig_present, sig_ok = decode_file_text(text)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=2)
        print("JSON guardado en %s" % args.output)
    if args.summary or args.output:
        print(summarize(obj, label, sig_present, sig_ok))
    else:
        print(json.dumps(obj, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
