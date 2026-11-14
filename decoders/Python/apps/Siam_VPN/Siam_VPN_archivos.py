#!/usr/bin/env python3
"""Siam VPN 4.9 (siam.pro.net): decoder for profile.json files.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
For the live catalog use Siam_VPN.py. See README.md here.

Method (verified against this APK, versionCode 49, versionName 4.9;
the app reads filesDir/profile.json on start in MainActivity.onCreate):
  profile.json content (one line of text)
  -> Base64 decode (the app's Ld32.i: standard alphabet, characters
     outside the alphabet are skipped, '=' ends the input)
  -> XXTEA decrypt (the app's Lk20.e; delta 0x2e0ba747, key = the first
     16 UTF-8 bytes of MainDetail.b(), "BamINlswE$re@+G"; the last
     word holds the plaintext length, as in the app's format)
  -> JSON with Version, Message, Servers, Networks and setOpenVPN.
  The loader then migrates old key names to the current ones, only
  when the old key is present (reproduced here in normalize()):
    Servers:  Name -> ServerName, Flag -> ServerFlag,
              SSLPort -> OpenVPNSSLPort and SSHSSLPort,
              ServerDNS present -> ServerDNS := ServerIP,
              OvpnCertificate -> setOpenVPN,
              AutoLogIn / MultiCert: boolean -> "true"/"false" string.
    Networks: Name -> PayloadName, Flag -> PayloadFlag,
              Info -> PayloadInfo,
              ServerDNS present -> ServerDNS := "",
              UseDefProxy: boolean -> "true"/"false" string.
  -> every field that carries an "ED:" value is Base32 (Lo41.a):
     "ED:" + Base32(UTF-8 plaintext).  A plain Base64 value in one of
     those fields is decoded as a fallback, like Lo41.a does.
  A file that is already plain JSON is accepted as-is (it is only
  normalized and its "ED:" fields decoded), so a catalog JSON saved
  by Siam_VPN.py can be passed through this script too.
No real profile.json exported from a phone was available yet, so the
XXTEA/Base64 path is verified by round-trip (encrypt -> decrypt) and
by matching the app's bytecode exactly; end-to-end confirmation with
a real profile.json is still pending (see README.md).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import math
from pathlib import Path
import re
import struct
import sys

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
MASK = 0xFFFFFFFF
XXTEA_DELTA = 0x2E0BA747
# XXTEA key: first 16 UTF-8 bytes of MainDetail.b() (the native
# "api-siam" string).  A format constant, not a password.
XXTEA_KEY = b"BamINlswE$re@+G"
ED_FIELDS_SERVERS = (
    "ServerIP", "Username", "Password", "setOpenVPN", "V2Ray",
    "UDPConfig", "Cloudfront", "NameServer", "PublicKey", "ServerDNS",
)
ED_FIELDS_NETWORKS = ("Payload", "SquidProxy", "ServerDNS", "Sni")
SERVER_RENAMES = (
    ("Name", "ServerName"),
    ("Flag", "ServerFlag"),
    ("OvpnCertificate", "setOpenVPN"),
)
NETWORK_RENAMES = (
    ("Name", "PayloadName"),
    ("Flag", "PayloadFlag"),
    ("Info", "PayloadInfo"),
)


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- XXTEA (app variant, delta 0x2e0ba747)

def _mx(total, y, z, position, e, key):
    return (((total ^ y) + (key[(position & 3) ^ e] ^ z))
            ^ (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))) & MASK


def _words(data):
    return list(struct.unpack("<" + "I" * (len(data) // 4), data))


def xxtea_decrypt(data, key=XXTEA_KEY):
    """XXTEA decrypt (Lk20.e); the last word holds the plain length."""
    if not data:
        return b""
    if len(data) < 8 or len(data) % 4:
        raise DecodeError("TRUNCATED", "El cuerpo no contiene palabras XXTEA completas.")
    values = _words(data)
    k = struct.unpack("<4I", key[:16].ljust(16, b"\0"))
    count = len(values)
    total = ((6 + 52 // count) * XXTEA_DELTA) & MASK
    y = values[0]
    while total:
        e = (total >> 2) & 3
        for position in range(count - 1, 0, -1):
            values[position] = (values[position]
                                - _mx(total, y, values[position - 1], position, e, k)) & MASK
            y = values[position]
        values[0] = (values[0] - _mx(total, y, values[-1], 0, e, k)) & MASK
        y = values[0]
        total = (total - XXTEA_DELTA) & MASK
    length = values[-1]
    maximum = count * 4 - 4
    if not maximum - 3 <= length <= maximum:
        raise DecodeError("DECRYPT_FAILED", "La longitud interna XXTEA no es válida para esta aplicación.")
    return struct.pack("<" + "I" * (count - 1), *values[:-1])[:length]


def xxtea_encrypt(data, key=XXTEA_KEY):
    """XXTEA encrypt (inverse of xxtea_decrypt; used by --self-test)."""
    k = struct.unpack("<4I", key[:16].ljust(16, b"\0"))
    padded = data + bytes((-len(data)) % 4)
    values = _words(padded) + [len(data)]
    count = len(values)
    rounds = 6 + 52 // count
    total = 0
    z = values[-1]
    for _ in range(rounds):
        total = (total + XXTEA_DELTA) & MASK
        e = (total >> 2) & 3
        for position in range(count - 1):
            y = values[position + 1]
            values[position] = (values[position]
                                + _mx(total, y, z, position, e, k)) & MASK
            z = values[position]
        y = values[0]
        values[-1] = (values[-1] + _mx(total, y, z, count - 1, e, k)) & MASK
        z = values[-1]
    return struct.pack("<" + "I" * count, *values)


# ---------------------------------------------------------------- "ED:" fields (Lo41.a)

def _b32decode_padded(text):
    return base64.b32decode(text + "=" * (-len(text) % 8))


def decode_ed(value):
    """Decode one field value the way the app's Lo41.a does."""
    if not isinstance(value, str) or not value:
        return value
    if value.startswith("ED:"):
        try:
            return _b32decode_padded(value[3:]).decode("utf-8")
        except (ValueError, binascii.Error, UnicodeError):
            return value
    compact = re.sub(r"\s", "", value)
    if (len(compact) >= 8 and len(compact) % 4 == 0
            and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact)):
        try:
            raw = base64.b64decode(compact, validate=True)
            text = raw.decode("utf-8")
            if text and text.isprintable():
                return text
        except (ValueError, binascii.Error, UnicodeError):
            pass
    return value


def encode_ed(value):
    """Encode one field value the way the app's Lo41.b does."""
    if not isinstance(value, str) or not value:
        return value
    return "ED:" + base64.b32encode(value.encode("utf-8")).decode("ascii")


def _bool_str(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def normalize(doc):
    """Apply the app's old->new key migration (MainActivity.onCreate)."""
    if not isinstance(doc, dict):
        return doc
    for server in doc.get("Servers", []) or []:
        if not isinstance(server, dict):
            continue
        for old, new in SERVER_RENAMES:
            if old in server:
                server[new] = server.pop(old)
        if "SSLPort" in server:
            value = server.pop("SSLPort")
            server["OpenVPNSSLPort"] = value
            server["SSHSSLPort"] = value
        if "ServerDNS" in server:
            server["ServerDNS"] = server.get("ServerIP", "")
        for field in ("AutoLogIn", "MultiCert"):
            if field in server:
                server[field] = _bool_str(server[field])
    for network in doc.get("Networks", []) or []:
        if not isinstance(network, dict):
            continue
        for old, new in NETWORK_RENAMES:
            if old in network:
                network[new] = network.pop(old)
        if "ServerDNS" in network:
            network["ServerDNS"] = ""
        if "UseDefProxy" in network:
            network["UseDefProxy"] = _bool_str(network["UseDefProxy"])
    return doc


def _decode_ed_fields(doc, keep_ed=False):
    if keep_ed or not isinstance(doc, dict):
        return doc
    for server in doc.get("Servers", []) or []:
        if isinstance(server, dict):
            for field in ED_FIELDS_SERVERS:
                if field in server:
                    server[field] = decode_ed(server[field])
    for network in doc.get("Networks", []) or []:
        if isinstance(network, dict):
            for field in ED_FIELDS_NETWORKS:
                if field in network:
                    network[field] = decode_ed(network[field])
    return doc


# ---------------------------------------------------------------- helpers

def _text(data):
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "Se esperaba texto o bytes UTF-8.")
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    try:
        value = data.decode("utf-8-sig") if isinstance(data, bytes) else data.removeprefix("\ufeff")
        if len(value.encode("utf-8")) > MAX_BYTES:
            raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    except UnicodeError as exc:
        raise DecodeError("FORMAT_ERROR", "La entrada no es UTF-8 válido.") from exc
    return value.strip()


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


def _base64_lenient(text):
    """Base64 decode like the app's Ld32.i: standard alphabet, other
    characters are skipped, '=' ends the input."""
    compact = re.sub(r"[^A-Za-z0-9+/=]", "", text)
    compact = compact.split("=", 1)[0]
    if not compact:
        raise DecodeError("FORMAT_ERROR", "El archivo no contiene Base64.")
    try:
        return base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR", "Base64 inválido.") from exc


def decode_profile(data, keep_ed=False):
    """Decode a profile.json file (or a plain catalog JSON) -> dict."""
    text = _text(data)
    try:
        doc = _json(text)
        return _decode_ed_fields(normalize(doc), keep_ed=keep_ed)
    except DecodeError as exc:
        if exc.code != "INVALID_JSON":
            raise
    blob = _base64_lenient(text)
    plain = xxtea_decrypt(blob)
    doc = _json(plain)
    return _decode_ed_fields(normalize(doc), keep_ed=keep_ed)


def encode_profile(doc):
    """Encode a catalog dict as a profile.json file (inverse path)."""
    plain = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(xxtea_encrypt(plain)).decode("ascii")


# ---------------------------------------------------------------- self-test

def _self_test():
    checks = []

    def check(name, ok):
        checks.append((name, bool(ok)))
        return ok

    doc = {
        "Version": "8.70", "Message": "update", "setOpenVPN": "",
        "Servers": [{
            # Old key names, like an exported profile.json from an
            # older app version.
            "Name": "Test 1", "Flag": "th", "SSLPort": "443",
            "ServerDNS": "old.example.com", "ServerIP": "new.example.com",
            "OvpnCertificate": "CERT",
            "Username": encode_ed("Openvpn-User"),
            "Password": encode_ed("s3cret"),
            "AutoLogIn": True, "MultiCert": False,
            "SelectType": "OpenVPN",
        }],
        "Networks": [{
            "Name": "Test payload", "Flag": "ais", "Info": "info",
            "ServerDNS": "1.2.3.4", "UseDefProxy": True,
            "Payload": encode_ed("GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]"),
            "SelectedProtocal": "HTTP Proxy", "Protocal": "OVPN",
        }],
    }
    encoded = encode_profile(doc)
    out = decode_profile(encoded)
    server = out["Servers"][0]
    network = out["Networks"][0]
    check("xxtea-roundtrip",
          out.get("Version") == "8.70"
          and server.get("ServerName") == "Test 1"
          and server.get("ServerFlag") == "th"
          and server.get("OpenVPNSSLPort") == "443"
          and server.get("SSHSSLPort") == "443"
          and server.get("setOpenVPN") == "CERT"
          and server.get("ServerDNS") == "new.example.com"
          and server.get("AutoLogIn") == "true"
          and server.get("MultiCert") == "false"
          and server.get("Username") == "Openvpn-User"
          and server.get("Password") == "s3cret"
          and network.get("PayloadName") == "Test payload"
          and network.get("PayloadFlag") == "ais"
          and network.get("PayloadInfo") == "info"
          and network.get("ServerDNS") == ""
          and network.get("UseDefProxy") == "true"
          and network.get("Payload").startswith("GET / HTTP/1.1"))
    # A plain JSON file passes through (only normalized + ED decoded).
    plain_doc = {"Version": "8.70", "Servers": [{"ServerName": "X",
                  "ServerIP": encode_ed("h.example.com")}],
                 "Networks": []}
    out2 = decode_profile(json.dumps(plain_doc, ensure_ascii=False))
    check("plain-json",
          out2["Servers"][0]["ServerName"] == "X"
          and out2["Servers"][0]["ServerIP"] == "h.example.com")
    # Corrupt ciphertext must fail, never silently return garbage.
    bad = bytearray(base64.b64decode(encoded))
    bad[len(bad) // 2] ^= 0xFF
    try:
        decode_profile(base64.b64encode(bytes(bad)).decode("ascii"))
        check("corrupt-fails", False)
    except DecodeError:
        check("corrupt-fails", True)
    # "ED:" helpers.
    check("ed-roundtrip", decode_ed(encode_ed("readyidc-o-1.opensignal.uk"))
          == "readyidc-o-1.opensignal.uk")
    return checks


# ---------------------------------------------------------------- CLI

def run(argv=None):
    parser = argparse.ArgumentParser(
        description="Decodificador de archivos profile.json de Siam VPN.")
    parser.add_argument("path", nargs="?", default=None,
                        help="Archivo profile.json (o JSON plano) a descifrar.")
    parser.add_argument("--keep-ed", action="store_true",
                        help="No descifrar los valores \"ED:\" (dejarlos tal cual).")
    parser.add_argument("-o", "--output", default=None,
                        help="Escribir el JSON descifrado en este archivo.")
    parser.add_argument("--self-test", action="store_true",
                        help="Ejecutar las comprobaciones internas y salir.")
    args = parser.parse_args(argv)
    if args.self_test:
        checks = _self_test()
        failed = [name for name, ok in checks if not ok]
        for name, ok in checks:
            print("%-18s %s" % (name, "OK" if ok else "FAIL"))
        print("%d/%d OK" % (len(checks) - len(failed), len(checks)))
        return 0 if not failed else 1
    if not args.path:
        parser.error("falta el archivo profile.json")
    doc = decode_profile(Path(args.path).read_bytes(), keep_ed=args.keep_ed)
    if args.output:
        Path(args.output).write_text(
            json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("Escrito: %s" % args.output)
    else:
        print(json.dumps(doc, ensure_ascii=False, indent=2))
    servers = doc.get("Servers", []) or []
    networks = doc.get("Networks", []) or []
    print("Resumen: Version %s, %d servidores, %d redes"
          % (doc.get("Version"), len(servers), len(networks)), file=sys.stderr)
    return 0


def main():
    try:
        raise SystemExit(run())
    except DecodeError as exc:
        print("ERROR [%s]: %s" % (exc.code, exc), file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
