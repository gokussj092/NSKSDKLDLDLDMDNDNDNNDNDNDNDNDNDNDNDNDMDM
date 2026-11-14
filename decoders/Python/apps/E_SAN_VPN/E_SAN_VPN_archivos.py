#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
E-SAN VPN (com.misaki.esanvpn) — descifrador de archivos guardados para SP-DECODE.
Python 3.10+, solo biblioteca estándar (XXTEA en Python puro).

App: E-SAN VPN 1.6.4 (versionCode 74), minSdk 32.

Formatos que guarda la app en getFilesDir():
  * profile.json (FORMATO ANTIGUO, migración en MainActivity.onCreate):
      Base64( XXTEA( JSON, clave = primeros 16 B del token ) )
      Token (MainDetail.b()): "Bs3PI5e1Olf5Me8E9Vc7bP1oUhS0eZ"
      XXTEA con delta 0x2E0BA747 (772515655), longitud en la última palabra.
      El JSON trae "Servers" y "Profiles" con las claves ANTIGUAS, que la
      app migra al leer: Name -> ServerName, Flag -> ServerFlag,
      SSLPort -> OpenVPNSSLPort y SSHSSLPort (el mismo valor en ambas),
      ServerDNS -> ServerIP; en Profiles: Name -> PayloadName,
      Flag -> PayloadFlag. Después de migrar, la app reescribe el
      catálogo como profile.enc y BORRA profile.json, por lo que este
      archivo solo existe en instalaciones antiguas o en respaldos.
      ESTE SCRIPT LO DESCIFRA (con la migración incluida).
  * profile.enc (FORMATO ACTUAL, du0.a): el JSON descifrado, cifrado con
      Tink StreamingAead con una clave propia DEL DISPOSITIVO (keyset en
      EncryptedSharedPreferences "StreamingCryptoPreferences", clave
      maestra en Android Keystore "android-keystore://private_master_key").
      NO SE PUEDE DESCIFRAR SIN CONEXIÓN. Este script lo detecta
      (binario que empieza por 0x28) y lo informa como bloqueado, sin
      inventar servidores.

La app NO tiene formato de perfil importable por intent (su MainActivity
solo declara MAIN/LAUNCHER), no tiene esquema de texto propio (no hay
esan://) y no exporta perfiles: el HTTP Custom de la misma familia
tampoco permite exportar como texto. El catálogo en vivo se descarga
con E_SAN_VPN.py --url.

Los valores "ED:..." (Base32) se decodifican igual que en el catálogo.

Uso:
  python3 E_SAN_VPN_archivos.py profile.json [-o salida.json]
  python3 E_SAN_VPN_archivos.py --self-test
"""

import base64
import binascii
import json
import math
import struct
import sys

LEGACY_TOKEN = "Bs3PI5e1Olf5Me8E9Vc7bP1oUhS0eZ"
XXTEA_DELTA = 772515655  # 0x2E0BA747 (Lon;->c)
MAX_DEPTH = 64
MAX_NODES = 200000

# Migración de claves antiguas -> actuales (MainActivity.onCreate).
SERVER_RENAMES = (
    ("Name", "ServerName"),
    ("Flag", "ServerFlag"),
    ("ServerDNS", "ServerIP"),
)
SERVER_SSL_TARGETS = ("OpenVPNSSLPort", "SSHSSLPort")
PROFILE_RENAMES = (
    ("Name", "PayloadName"),
    ("Flag", "PayloadFlag"),
)


class DecodeError(ValueError):
    """Error de descifrado con un código estable para SP-DECODE."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------- XXTEA
def _mx(y, z, s, p, e, k):
    return (((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) & 0xffffffff)
            ^ (((s ^ y) + (k[(p & 3) ^ e] ^ z)) & 0xffffffff)) & 0xffffffff


def xxtea_decrypt(data, key, delta=XXTEA_DELTA):
    """XXTEA con longitud en la última palabra (Lon;->c). Devuelve None
    si la palabra de longitud no es válida."""
    pad = (-len(data)) % 4
    data = data + b"\x00" * pad
    n = len(data) // 4
    if n < 2:
        return None
    v = list(struct.unpack("<%dI" % n, data))
    kk = list(struct.unpack("<4I", key[:16].ljust(16, b"\x00")))
    rounds = 52 // n + 6
    s = (rounds * delta) & 0xffffffff
    while s != 0:
        e = (s >> 2) & 3
        y = v[0]
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            y = v[p] = (v[p] - _mx(y, z, s, p, e, kk)) & 0xffffffff
        z = v[n - 1]
        y = v[0] = (v[0] - _mx(y, z, s, 0, e, kk)) & 0xffffffff
        s = (s - delta) & 0xffffffff
    out = struct.pack("<%dI" % n, *v)
    length = v[-1]
    total = n * 4
    if length < total - 7 or length > total - 4:
        return None
    return out[:length]


def xxtea_encrypt(data, key, delta=XXTEA_DELTA):
    """Inverso de xxtea_decrypt (mismo layout). Solo para --self-test."""
    n = (len(data) + 4 + 3) // 4
    body = data + b"\x00" * ((n - 1) * 4 - len(data))
    v = list(struct.unpack("<%dI" % (n - 1), body)) + [len(data)]
    kk = list(struct.unpack("<4I", key[:16].ljust(16, b"\x00")))
    rounds = 52 // n + 6
    s = 0
    for _ in range(rounds):
        s = (s + delta) & 0xffffffff
        e = (s >> 2) & 3
        z = v[n - 1]
        for p in range(n - 1):
            y = v[p + 1]
            z = v[p] = (v[p] + _mx(y, z, s, p, e, kk)) & 0xffffffff
        y = v[0]
        z = v[n - 1] = (v[n - 1] + _mx(y, z, s, n - 1, e, kk)) & 0xffffffff
    return struct.pack("<%dI" % n, *v)


# ------------------------------------------------------------- ED: (Base32)
def _ed_decode(value):
    if not isinstance(value, str) or not value.startswith("ED:"):
        return value
    body = value[3:]
    try:
        raw = base64.b32decode(body + "=" * ((8 - len(body) % 8) % 8))
    except Exception:
        return value
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return value


def _decode_ed_fields(doc):
    if isinstance(doc, dict):
        return {k: _decode_ed_fields(v) for k, v in doc.items()}
    if isinstance(doc, list):
        return [_decode_ed_fields(v) for v in doc]
    return _ed_decode(doc)


# ------------------------------------------------------------- Migración
def _migrate(doc):
    """Aplica la migración de claves antiguas de MainActivity.onCreate."""
    for server in doc.get("Servers", []) or []:
        if not isinstance(server, dict):
            continue
        for old, new in SERVER_RENAMES:
            if old in server and new not in server:
                server[new] = server.pop(old)
            elif old in server:
                server.pop(old)
        if "SSLPort" in server:
            value = server.pop("SSLPort")
            for target in SERVER_SSL_TARGETS:
                server.setdefault(target, value)
    for profile in doc.get("Profiles", []) or []:
        if not isinstance(profile, dict):
            continue
        for old, new in PROFILE_RENAMES:
            if old in profile and new not in profile:
                profile[new] = profile.pop(old)
            elif old in profile:
                profile.pop(old)
    return doc


# ------------------------------------------------------------- JSON
def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _nonfinite(_value):
    raise ValueError("nonfinite number")


def _validate(doc):
    pending, count = [(doc, 0)], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            raise DecodeError("SIZE_LIMIT", "El JSON supera el límite de complejidad.")
        if isinstance(value, dict):
            pending.extend((v, depth + 1) for v in value.values())
            pending.extend((k, depth + 1) for k in value)
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise DecodeError("INVALID_JSON", "Número JSON no finito.")
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError as exc:
                raise DecodeError("INVALID_JSON", "Unicode JSON inválido.") from exc
    return doc


def _json(data):
    try:
        doc = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON", "JSON inválido o con claves duplicadas.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El documento debe contener un objeto JSON.")
    return _validate(doc)


def _profile_json(data: bytes) -> dict:
    doc = _json(data)
    if not isinstance(doc.get("Servers"), list) and not isinstance(doc.get("Profiles"), list):
        raise DecodeError("WRONG_DOCUMENT",
                          "El JSON no trae las listas Servers ni Profiles de profile.json.")
    return _decode_ed_fields(_migrate(doc))


def decode(data) -> dict:
    """API offline: descifra un profile.json antiguo y devuelve el dict
    (con la migración de claves aplicada y los ED: decodificados).
    Acepta el texto Base64 del archivo, sus bytes, o un JSON ya abierto.
    Un profile.enc (clave del dispositivo) lanza PROFILE_ENC_DEVICE_KEY;
    un catálogo e-san-vpn.json (Base64 Tink) lanza WRONG_FILE."""
    if isinstance(data, (bytes, bytearray)):
        raw = bytes(data)
    else:
        raw = str(data).encode("utf-8")
    text = raw.decode("utf-8", "replace")
    if text.lstrip().startswith("{"):
        return _profile_json(raw)
    if raw[:1] == b"\x28" and len(raw) > 40:
        # Binario Tink directo: es profile.enc (clave del dispositivo).
        raise DecodeError(
            "PROFILE_ENC_DEVICE_KEY",
            "Esto es profile.enc: está cifrado con una clave Tink propia del "
            "dispositivo (Android Keystore) y no se puede descifrar sin conexión. "
            "Descarga el catálogo con E_SAN_VPN.py --url en su lugar.",
        )
    stripped = "".join(text.split())
    try:
        blob = base64.b64decode(stripped, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("NOT_BASE64", "El archivo no es Base64 ni JSON.") from exc
    if blob[:1] == b"\x28" and len(blob) > 40:
        # Base64 que esconde un sobre Tink: es el catálogo, no un perfil.
        raise DecodeError(
            "WRONG_FILE",
            "Esto es el catálogo e-san-vpn.json (sobre Tink), no un profile.json. "
            "Usa E_SAN_VPN.py --file para descifrarlo.",
        )
    plain = xxtea_decrypt(blob, LEGACY_TOKEN.encode("utf-8"))
    if plain is None:
        raise DecodeError(
            "XXTEA_BAD_LENGTH",
            "El XXTEA no abrió el archivo (palabra de longitud inválida). "
            "No es un profile.json de E-SAN VPN 1.6.4 o la clave cambió.",
        )
    return _profile_json(plain)


def run(file_bytes) -> str | None:
    """API offline: JSON completo del perfil o None; nunca una lista parcial."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


# ------------------------------------------------------------- CLI
def _self_test():
    """Construye un profile.json antiguo sintético (claves antiguas + ED:),
    lo cifra con XXTEA + Base64 y comprueba que decode() lo abre con la
    migración aplicada. También comprueba la detección de profile.enc."""
    legacy = {
        "Servers": [
            {"Name": "TEST_UDP_01", "Flag": "th", "SSLPort": "",
             "ServerDNS": "ED:OVSHAMJOMUWXGYLOFVSG44ZOMNXW2===",
             "Username": "", "Password": "", "UDPConfig": "ED:PMRGC5LUNBPXG5DSEI5CEZLTMFXDUZLTMFXCE7I"},
            {"Name": "TEST_VPN_01", "Flag": "th", "SSLPort": "1194",
             "ServerDNS": "ED:ORUGC2LMMFXGIMJOMUWXGYLOFVSG44ZOMNXW2===",
             "Username": "ED:E5EUK3DTJFAWYTRH", "Password": "ED:E5WFGSLFNRJES5SJMNEUKJY="},
        ],
        "Profiles": [
            {"Name": "Test Network", "Flag": "esan", "Payload": "",
             "SelectedProtocal": "Direct", "Protocal": "OVPN"},
        ],
    }
    plain = json.dumps(legacy, ensure_ascii=False).encode("utf-8")
    blob = base64.b64encode(xxtea_encrypt(plain, LEGACY_TOKEN.encode("utf-8"))).decode("ascii")
    doc = decode(blob)
    assert len(doc["Servers"]) == 2, doc
    s0 = doc["Servers"][0]
    assert s0["ServerName"] == "TEST_UDP_01", s0
    assert s0["ServerFlag"] == "th", s0
    assert s0["ServerIP"] == "udp1.e-san-dns.com", s0["ServerIP"]
    assert "ServerDNS" not in s0 and "Name" not in s0, s0
    s1 = doc["Servers"][1]
    assert s1["OpenVPNSSLPort"] == "1194" and s1["SSHSSLPort"] == "1194", s1
    assert s1["ServerIP"] == "thailand1.e-san-dns.com", s1["ServerIP"]
    p0 = doc["Profiles"][0]
    assert p0["PayloadName"] == "Test Network" and p0["PayloadFlag"] == "esan", p0
    assert "Name" not in p0 and "Flag" not in p0, p0
    # profile.enc (binario Tink) se detecta y se informa como bloqueado.
    try:
        decode(b"\x28" + b"\x00" * 60)
    except DecodeError as exc:
        assert exc.code == "PROFILE_ENC_DEVICE_KEY", exc.code
    else:
        raise AssertionError("profile.enc no detectado")
    # El catálogo Tink en Base64 se rechaza con WRONG_FILE.
    import base64 as _b64
    try:
        decode(_b64.b64encode(b"\x28" + b"\x00" * 60).decode("ascii"))
    except DecodeError as exc:
        assert exc.code == "WRONG_FILE", exc.code
    else:
        raise AssertionError("catálogo Tink no detectado")
    return ("self-test OK: profile.json antiguo (XXTEA + migración + ED:) "
            "y detección de profile.enc / catálogo")


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(
        description="Descifrador de profile.json antiguo de E-SAN VPN.")
    parser.add_argument("file", nargs="?", default=None,
                        help="Archivo profile.json a descifrar.")
    parser.add_argument("--self-test", action="store_true",
                        help="Verifica el descifrado con un perfil sintético.")
    parser.add_argument("-o", "--output", default=None,
                        help="Guarda el JSON descifrado en este archivo.")
    args = parser.parse_args(argv)
    if args.self_test:
        print(_self_test())
        return 0
    if not args.file:
        parser.error("falta el archivo profile.json (o usa --self-test)")
        return 2
    try:
        with open(args.file, "rb") as fh:
            raw = fh.read()
        out = run(raw)
        if out is None:
            raise DecodeError("DECRYPT_FAILED", "No se pudo descifrar el archivo.")
    except DecodeError as exc:
        print("error [%s]: %s" % (exc.code, exc), file=sys.stderr)
        return 1
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print("guardado en %s" % args.output)
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
