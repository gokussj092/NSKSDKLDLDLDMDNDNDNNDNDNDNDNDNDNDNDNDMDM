#!/usr/bin/env python3
"""MO VPN (com.movpn.vpnth, versionCode 6, versionName 1.0.6): archivos de
catalogo guardados (SVPN/Config.json o el asset pntvpn.json).

Standalone Python 3.10+, standard library only, no network access.
Para descargar el catalogo en vivo usa MO_VPN.py.

La app NO tiene formato propio de archivo de perfil: el manifiesto
declara 15 actividades y NINGUN intent-filter (sin ACTION_VIEW, sin
esquemas, sin sufijos .sks/.movpn ni ningun otro). La app importa
enlaces estandar vmess:// / vless:// / trojan:// / ss:// por
portapapeles (herencia del fork de v2rayNG). Su unico "archivo" es el
catalogo mismo: al actualizar, PRDownloader guarda el cuerpo cifrado
en <filesDir>/SVPN/Config.json; si ese archivo no existe, la app lee
el asset pntvpn.json del APK. Este script descifra cualquiera de los
dos (mismo formato, misma clave).

Formato (verificado en vivo 2026-11-17 contra el endpoint real y
contra el asset del APK 1.0.6; valores nativos recuperados emulando
con Unicorn los JNI de libnative-sec.so):
  * Cuerpo: una linea Base64 estandar.
  * Base64 -> XXTEA (clase SVPNDex, DELTA fijo 0xD1FBFA0B, clave =
    NativeSec.getAesKey() = "com.movpn.paidapk") -> JSON.
  * Campos cifrados de cada servidor/red (FileUtils.showJson):
    Base64 -> XXTEA (clase XxTea, DELTA = NativeSec.getDelta() =
    0x3B2959AF, clave = FileUtils.getPass() = "5741")
    -> texto UTF-8 con caracteres portadores (U+2C00-U+2DFF)
    -> cada caracter -= 5741, dos veces -> texto plano.
    Campos: ServerIP, ServerCloudFront, ServerHTTP, V2ray, SlowIP,
    PublicKey, Username, Password, NetworkPayload, SquidProxy, WSHost,
    Address, NetworkFrontQuery, NetworkBackQuery.

SEGURIDAD: el catalogo trae un campo "tokenKey" que es un token de
GitHub (40 caracteres). NO se incluye en la salida guardada con -o ni
se imprime jamas. Tampoco se reproduce en el README ni en el resumen.

Uso:
    python3 MO_VPN_archivos.py Config.json
    python3 MO_VPN_archivos.py pntvpn.json --summary
    python3 MO_VPN_archivos.py --text <cuerpo Base64>
    python3 MO_VPN_archivos.py Config.json -o out.json
    python3 MO_VPN_archivos.py --self-test
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
from pathlib import Path

MAX_BYTES = 8 * 1024 * 1024
CATALOG_KEY = b"com.movpn.paidapk"
FIELD_KEY = b"5741"
DELTA_CATALOG = 0xD1FBFA0B
DELTA_FIELD = 0x3B2959AF

ENCRYPTED_FIELDS = (
    "ServerIP", "ServerCloudFront", "ServerHTTP", "V2ray", "SlowIP",
    "PublicKey", "Username", "Password", "NetworkPayload", "SquidProxy",
    "WSHost", "Address", "NetworkFrontQuery", "NetworkBackQuery",
)


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def _mx(total: int, y: int, z: int, p: int, e: int, k: list) -> int:
    a = _u32(((_u32(z >> 5) ^ _u32(y << 2)) + _u32(_u32(y >> 3) ^ _u32(z << 4))))
    b = _u32(_u32(total ^ y) + _u32(k[(p & 3) ^ e] ^ z))
    return _u32(a ^ b)


def _to_words(data: bytes, include_length: bool) -> list:
    import struct
    n = (len(data) + 3) // 4
    words = list(struct.unpack("<%dI" % n, data + b"\x00" * (n * 4 - len(data))))
    if include_length:
        words.append(len(data))
    return words


def _from_words(words: list, use_length: bool):
    import struct
    total = len(words) << 2
    if use_length:
        length = words[-1]
        if length < total - 7 or length > total - 4:
            return None
        total = length
    out = struct.pack("<%dI" % len(words), *words)
    return out[:total]


def _fix_key(key: bytes) -> bytes:
    if len(key) == 16:
        return key
    if len(key) < 16:
        return key + b"\x00" * (16 - len(key))
    return key[:16]


def xxtea_encrypt(data: bytes, key: bytes, delta: int) -> bytes:
    import struct
    v = _to_words(data, True)
    k = list(struct.unpack("<4I", _fix_key(key)))
    n = len(v)
    rounds = 6 + 52 // n
    total = 0
    z = v[n - 1]
    for _ in range(rounds):
        total = _u32(total + delta)
        e = (total >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            z = _u32(v[p] + _mx(total, y, z, p, e, k))
            v[p] = z
        y = v[0]
        z = _u32(v[n - 1] + _mx(total, y, z, n - 1, e, k))
        v[n - 1] = z
    return struct.pack("<%dI" % n, *v)


def xxtea_decrypt(data: bytes, key: bytes, delta: int):
    import struct
    if not data:
        return b""
    v = _to_words(data, False)
    k = list(struct.unpack("<4I", _fix_key(key)))
    n = len(v)
    if n < 2:
        return None
    rounds = 6 + 52 // n
    total = _u32(rounds * delta)
    y = v[0]
    while total != 0:
        e = (total >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            y = _u32(v[p] - _mx(total, y, z, p, e, k))
            v[p] = y
        z = v[n - 1]
        y = _u32(v[0] - _mx(total, y, z, 0, e, k))
        v[0] = y
        total = _u32(total - delta)
    return _from_words(v, True)


def _b64decode(text: str) -> bytes:
    """TeaBase64.decode de la app: Base64 estandar, ignora caracteres
    fuera del alfabeto y corta en el primer '='."""
    cleaned = "".join(ch for ch in text.strip() if ch in
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    cleaned = cleaned.split("=", 1)[0]
    cleaned += "=" * (-len(cleaned) % 4)
    return base64.b64decode(cleaned)


def show_json(value: str) -> str:
    """FileUtils.showJson: XXTEA (delta de campo, clave "5741") + cada
    caracter -= 5741 dos veces."""
    if not value:
        return ""
    raw = xxtea_decrypt(_b64decode(value), FIELD_KEY, DELTA_FIELD)
    if raw is None:
        raise DecodeError("FIELD_XXTEA", "el campo no abre con XXTEA (clave 5741)")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError("FIELD_UTF8", "el campo descifrado no es UTF-8: %s" % exc)
    return "".join(chr(ord(ch) - 2 * 5741) for ch in text)


def decrypt_fields(catalog: dict) -> dict:
    """Copia del catalogo con los campos cifrados ya descifrados en su
    sitio (los vacios quedan vacios; los que no abren quedan con el
    valor original y se marcan en _field_errors)."""
    out = json.loads(json.dumps(catalog))
    errors = {}
    for server in out.get("Servers", []) or []:
        if not isinstance(server, dict):
            continue
        for field in ENCRYPTED_FIELDS:
            value = server.get(field)
            if isinstance(value, str) and value:
                try:
                    server[field] = show_json(value)
                except DecodeError as exc:
                    errors.setdefault(server.get("Name", "?"), []).append(field + ":" + exc.code)
    for net in (out.get("HTTPNetworks", []) or []) + (out.get("SSLNetworks", []) or []):
        if not isinstance(net, dict):
            continue
        for field in ENCRYPTED_FIELDS:
            value = net.get(field)
            if isinstance(value, str) and value:
                try:
                    net[field] = show_json(value)
                except DecodeError as exc:
                    errors.setdefault(net.get("Name", "?"), []).append(field + ":" + exc.code)
    if errors:
        out["_field_errors"] = errors
    return out


def decode(data) -> dict:
    """Descifra un cuerpo de catalogo guardado y devuelve el JSON con
    los campos ya descifrados. Sin tokenKey: se elimina antes de
    devolver (es un token de GitHub incrustado en el catalogo)."""
    if isinstance(data, (bytes, bytearray)):
        text = bytes(data).decode("utf-8", "replace")
    else:
        text = str(data)
    text = text.strip()
    if not text:
        raise DecodeError("EMPTY", "cuerpo vacio")
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "la entrada supera el limite de tamano.")
    try:
        blob = _b64decode(text)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("BASE64", "el cuerpo no es Base64: %s" % exc)
    raw = xxtea_decrypt(blob, CATALOG_KEY, DELTA_CATALOG)
    if raw is None:
        raise DecodeError("XXTEA", "el catalogo no abre con XXTEA (delta 0xD1FBFA0B, clave com.movpn.paidapk)")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError("JSON", "el catalogo descifrado no es JSON: %s" % exc)
    if not isinstance(doc, dict) or "Servers" not in doc:
        raise DecodeError("WRONG_DOCUMENT", "el documento no es un catalogo MO VPN (sin Servers).")
    out = decrypt_fields(doc)
    out.pop("tokenKey", None)
    return out


def run(file_bytes) -> str | None:
    """API offline: JSON completo del catalogo o None."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=1) + "\n"
    except DecodeError:
        return None


def _read(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "el archivo supera el limite de tamano.")
    return data


def _self_test() -> int:
    failures = []

    def check(name, cond):
        print(("ok  " if cond else "FAIL") + " " + name)
        if not cond:
            failures.append(name)

    sample = {"FileName": "selftest", "Servers": [{"Name": "T-1", "Category": 0}],
              "HTTPNetworks": [], "SSLNetworks": []}
    plain = json.dumps(sample)
    blob = xxtea_encrypt(plain.encode("utf-8"), CATALOG_KEY, DELTA_CATALOG)
    encoded = base64.b64encode(blob).decode("ascii")
    check("catalogo XXTEA round-trip", decode(encoded) == sample)
    check("campo show/hide round-trip",
          show_json(__import__("base64").b64encode(
              xxtea_encrypt("".join(chr(ord(c) + 2 * 5741) for c in "m.free1.mvpn5g.com").encode("utf-8"),
                            FIELD_KEY, DELTA_FIELD)).decode("ascii")) == "m.free1.mvpn5g.com")
    check("campo vacio", show_json("") == "")

    here = Path(__file__).resolve().parent
    path = here / "pntvpn.json"
    if not path.exists():
        print("skip pntvpn.json (no esta junto al script)")
    else:
        try:
            cat = decode(path.read_bytes())
            check("pntvpn.json abre (FileName=%s, %d servidores)" % (
                cat.get("FileName"), len(cat.get("Servers", []))),
                cat.get("FileName") == "config.gen" and len(cat.get("Servers", [])) == 13)
            check("pntvpn.json: 11 redes HTTP", len(cat.get("HTTPNetworks", [])) == 11)
            first = cat["Servers"][0]
            check("pntvpn.json: ServerIP descifrado",
                  isinstance(first.get("ServerIP"), str) and "." in first["ServerIP"])
            check("pntvpn.json: V2ray descifrado",
                  isinstance(first.get("V2ray"), str) and first["V2ray"].startswith("vless://"))
            check("pntvpn.json: sin tokenKey", "tokenKey" not in cat)
            check("pntvpn.json: sin errores de campo", "_field_errors" not in cat)
        except DecodeError as exc:
            check("pntvpn.json abre", False)
            print("     " + exc.code + ": " + str(exc))
    if failures:
        print("SELF-TEST: %d fallo(s): %s" % (len(failures), failures))
        return 1
    print("SELF-TEST: todo ok")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path,
                        help="Archivo guardado: SVPN/Config.json o el asset pntvpn.json")
    source.add_argument("--text", help="Cuerpo Base64 del catalogo guardado")
    source.add_argument("--self-test", action="store_true",
                        help="Round-trip + muestra pntvpn.json del APK")
    parser.add_argument("-o", "--output", type=Path,
                        help="Guardar JSON descifrado (sin tokenKey); no sobrescribe")
    parser.add_argument("--summary", action="store_true",
                        help="Solo recuentos (version y tamanos de lista), sin valores descifrados")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    try:
        doc = decode(args.text if args.text is not None else _read(args.file))
        if args.summary:
            rendered = json.dumps({
                "FileName": doc.get("FileName"),
                "Servers": len(doc.get("Servers", []) or []),
                "Servers_free_Category0": sum(
                    1 for s in doc.get("Servers", []) or []
                    if isinstance(s, dict) and str(s.get("Category")) == "0"),
                "HTTPNetworks": len(doc.get("HTTPNetworks", []) or []),
                "HTTPNetworks_with_payload": sum(
                    1 for n in doc.get("HTTPNetworks", []) or []
                    if isinstance(n, dict) and n.get("NetworkPayload")),
                "SSLNetworks": len(doc.get("SSLNetworks", []) or []),
                "field_errors": doc.get("_field_errors"),
            }, ensure_ascii=False, indent=2) + "\n"
        else:
            rendered = json.dumps(doc, ensure_ascii=False, indent=1) + "\n"
        if args.output:
            fd = __import__("os").open(args.output, __import__("os").O_WRONLY | __import__("os").O_CREAT | __import__("os").O_EXCL, 0o600)
            try:
                __import__("os").write(fd, rendered.encode("utf-8"))
            finally:
                __import__("os").close(fd)
        else:
            sys.stdout.write(rendered)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
