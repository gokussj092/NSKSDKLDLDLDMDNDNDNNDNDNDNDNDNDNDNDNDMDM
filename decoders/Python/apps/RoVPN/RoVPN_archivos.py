#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RoVPN (com.mobileapp.rovpn, 7.6) — archivos profile.json (legacy) y profile.enc.

App: **RoVPN**, paquete `com.mobileapp.rovpn`, versionCode **76**,
versionName `7.6`, minSdk 32. Ver `RoVPN.py` para el catálogo (mismo
proveedor). Fecha de trabajo: 2026-11-13. No se modificó el repo
SP-DECODE ni se subió nada a Git.

## profile.json (legacy, importable)

`MainActivity.onCreate` lee `filesDir/profile.json` si existe:

1. Lee el archivo completo como texto UTF-8.
2. `aj2.c(texto)`: Base64 propio (alfabeto estándar; ignora caracteres
   inválidos y se detiene en `=`).
3. `aj2.d(bytes, MainDetail.b().getBytes("UTF-8"))`: **XXTEA modificado**,
   delta `0x2E0BA747` (772515655), clave = primeros 16 bytes UTF-8 de
   `MainDetail.b()` = `aZ%RU%itRMB^8&Ue` (la clave completa es un blob de
   128 caracteres; `aj2.d` trunca a 16 bytes o rellena con ceros).
   El último word del bloque es la longitud del texto plano, que debe
   estar entre `len-7` y `len-4` o el descifrado devuelve null.
4. El JSON resultante tiene `Servers[]` y `Networks[]` con los nombres
   de campo **antiguos**; la app los renombra (ver `SERVER_RENAMES` y
   `NETWORK_RENAMES`) y convierte los booleanos `AutoLogIn`,
   `MultiCert` y `UseDefProxy` a string.
5. Lo importa con el mismo `a0.b(...)` que el catálogo (ye1.b → Tink
   StreamingAead con clave maestra del Keystore → `profile.enc`) y
   **borra `profile.json`**.

Este script hace el camino inverso y también el directo: `decode()`
abre un `profile.json` (Base64 + XXTEA) y devuelve el JSON con los
nombres nuevos; `encode()` toma un JSON con los nombres nuevos y
produce el contenido de un `profile.json` que la app aceptaría
(nombres antiguos, booleanos, XXTEA + Base64).

## profile.enc (actual, NO abrible offline)

El catálogo importado (y el `profile.json` tras importarlo) se guarda
como `profile.enc` en filesDir, cifrado con Tink StreamingAead
(`StreamingAeadKeyset`, preferencias `StreamingCryptoPreferences`,
clave maestra del Android Keystore
`android-keystore://private_master_key`, AD =
`MY_SECURE_JSON_STREAM_V1`). **No se puede abrir offline**: la clave
vive en el Keystore del teléfono que lo generó. Si se le pasa un
`profile.enc`, este script lo detecta (cabecera binaria Tink, primer
byte 0x28) y lo reporta como `PROFILE_ENC_KEYSTORE`, sin inventar
contenido.

## Sin `.sks` y sin esquema de texto propio

Ver `RoVPN.py`: el manifiesto no declara ningún formato importable
propio ni esquema URI propio.

## Pendiente

- Un `profile.json` real exportado del teléfono para la confirmación
  end-to-end (el round-trip sintético está verificado: cifrar ->
  descifrar reproduce el JSON exacto, incluidos caracteres no ASCII).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import struct
import sys
from pathlib import Path

MAX_BYTES = 32 * 1024 * 1024

# Clave XXTEA: primeros 16 bytes UTF-8 de MainDetail.b() (blob de 128 caracteres).
XXTEA_KEY = b"aZ%RU%itRMB^8&Ue"
_DELTA = 772515655  # 0x2E0BA747
_M32 = 0xFFFFFFFF

# Renombres que MainActivity.onCreate aplica al importar profile.json.
SERVER_RENAMES = {
    "Name": "ServerName",
    "Flag": "ServerFlag",
    "OvpnCertificate": "setOpenVPN",
}
SERVER_SSLPORT_TARGETS = ("OpenVPNSSLPort", "SSHSSLPort")  # SSLPort -> ambos
SERVER_BOOL_TO_STRING = ("AutoLogIn", "MultiCert")
NETWORK_RENAMES = {
    "Name": "PayloadName",
    "Flag": "PayloadFlag",
    "Info": "PayloadInfo",
}
NETWORK_BOOL_TO_STRING = ("UseDefProxy",)


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------- Base64 (aj2.c)
_B64_ALPHABET = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")


def _b64decode_aj2(text: str) -> bytes:
    """Base64 propio de la app: ignora caracteres inválidos, se detiene en '='."""
    cleaned = bytearray()
    for ch in text.encode("utf-8", "ignore"):
        if ch == 0x3D:  # '='
            break
        if ch in _B64_ALPHABET:
            cleaned.append(ch)
    cleaned += b"=" * ((-len(cleaned)) % 4)
    try:
        return base64.b64decode(bytes(cleaned))
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("FORMAT_ERROR", "El contenido no es Base64 válido.") from exc


# ------------------------------------------------------------------- XXTEA
def _mx(sum_, y, z, p, e, k):
    return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
            ^ ((sum_ ^ y) + (k[(p & 3) ^ e] ^ z))) & _M32


def _to_words(data: bytes):
    n = (len(data) + 3) // 4
    v = [0] * n
    for i, b in enumerate(data):
        v[i >> 2] |= b << ((i & 3) << 3)
    return v


def _to_bytes(v, length: int) -> bytes:
    out = bytearray()
    for i in range(length):
        out.append((v[i >> 2] >> ((i & 3) << 3)) & 0xFF)
    return bytes(out)


def _key_words(key: bytes = XXTEA_KEY):
    return _to_words(key[:16].ljust(16, b"\x00"))


def xxtea_decrypt(data: bytes, key: bytes = XXTEA_KEY):
    """XXTEA modificado de aj2.d. Devuelve None si la longitud no cuadra."""
    if len(data) == 0:
        return data
    v = _to_words(data)
    k = _key_words(key)
    n = len(v)
    if n < 2:
        return None
    rounds = 6 + 52 // n
    sum_ = (rounds * _DELTA) & _M32
    y, z = v[0], v[n - 1]
    for _ in range(rounds):
        e = (sum_ >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            y = v[p] = (v[p] - _mx(sum_, y, z, p, e, k)) & _M32
        z = v[n - 1]
        y = v[0] = (v[0] - _mx(sum_, y, z, 0, e, k)) & _M32
        sum_ = (sum_ - _DELTA) & _M32
    length = v[n - 1]
    if length < n * 4 - 7 or length > n * 4 - 4:
        return None
    return _to_bytes(v, length)


def xxtea_encrypt(data: bytes, key: bytes = XXTEA_KEY) -> bytes:
    """Inverso de xxtea_decrypt (para --self-test y --encode)."""
    v = _to_words(data) + [len(data)]  # la longitud es una palabra extra
    k = _key_words(key)
    n = len(v)
    if n < 2:
        return data
    rounds = 6 + 52 // n
    sum_ = 0
    z, y = v[n - 1], v[0]
    for _ in range(rounds):
        sum_ = (sum_ + _DELTA) & _M32
        e = (sum_ >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            z = v[p] = (v[p] + _mx(sum_, y, z, p, e, k)) & _M32
        y = v[0]
        z = v[n - 1] = (v[n - 1] + _mx(sum_, y, z, n - 1, e, k)) & _M32
    return _to_bytes(v, n * 4)


# ------------------------------------------------------- renombres de claves
def _bool_to_string(value):
    return str(value).lower() if isinstance(value, bool) else value


def _string_to_bool(value):
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    return value


def _apply_renames(doc: dict) -> dict:
    """Nombres antiguos -> nuevos, como MainActivity.onCreate."""
    out = dict(doc)
    servers = doc.get("Servers")
    if isinstance(servers, list):
        new_servers = []
        for item in servers:
            s = dict(item)
            for old, new in SERVER_RENAMES.items():
                if old in s:
                    s[new] = s.pop(old)
            if "SSLPort" in s:
                value = s.pop("SSLPort")
                for target in SERVER_SSLPORT_TARGETS:
                    s[target] = value
            if "ServerDNS" not in s:
                s["ServerDNS"] = s.get("ServerIP", "")
            for field in SERVER_BOOL_TO_STRING:
                if field in s:
                    s[field] = _bool_to_string(s[field])
            new_servers.append(s)
        out["Servers"] = new_servers
    networks = doc.get("Networks")
    if isinstance(networks, list):
        new_networks = []
        for item in networks:
            n = dict(item)
            for old, new in NETWORK_RENAMES.items():
                if old in n:
                    n[new] = n.pop(old)
            if "ServerDNS" not in n:
                n["ServerDNS"] = ""
            for field in NETWORK_BOOL_TO_STRING:
                if field in n:
                    n[field] = _bool_to_string(n[field])
            new_networks.append(n)
        out["Networks"] = new_networks
    return out


def _reverse_renames(doc: dict) -> dict:
    """Nombres nuevos -> antiguos, para producir un profile.json válido."""
    out = dict(doc)
    servers = doc.get("Servers")
    if isinstance(servers, list):
        old_servers = []
        for item in servers:
            s = dict(item)
            for old, new in SERVER_RENAMES.items():
                if new in s:
                    s[old] = s.pop(new)
            ssl = s.pop("OpenVPNSSLPort", None)
            if ssl is None:
                ssl = s.pop("SSHSSLPort", None)
            else:
                s.pop("SSHSSLPort", None)
            if ssl is not None:
                s["SSLPort"] = ssl
            if s.get("ServerDNS") == s.get("ServerIP"):
                s.pop("ServerDNS", None)
            for field in SERVER_BOOL_TO_STRING:
                if field in s:
                    s[field] = _string_to_bool(s[field])
            old_servers.append(s)
        out["Servers"] = old_servers
    networks = doc.get("Networks")
    if isinstance(networks, list):
        old_networks = []
        for item in networks:
            n = dict(item)
            for old, new in NETWORK_RENAMES.items():
                if new in n:
                    n[old] = n.pop(new)
            if n.get("ServerDNS") == "":
                n.pop("ServerDNS", None)
            for field in NETWORK_BOOL_TO_STRING:
                if field in n:
                    n[field] = _string_to_bool(n[field])
            old_networks.append(n)
        out["Networks"] = old_networks
    return out


# ------------------------------------------------------------------ decode
def _detect_profile_enc(data: bytes) -> bool:
    """True si el contenido es binario con cabecera Tink (profile.enc)."""
    if len(data) >= 1 and data[0] == 0x28:
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return True
    return False


def decode(data: bytes | str) -> dict:
    """Offline API: abre un profile.json y devuelve su JSON (nombres nuevos)."""
    if isinstance(data, str):
        raw = data.encode("utf-8")
    else:
        raw = bytes(data)
    if len(raw) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    if _detect_profile_enc(raw):
        raise DecodeError(
            "PROFILE_ENC_KEYSTORE",
            "Es profile.enc (Tink + clave maestra del Android Keystore): "
            "no se puede abrir offline; solo lo abre el teléfono que lo generó.")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError("FORMAT_ERROR", "El archivo no es texto UTF-8 ni profile.enc.") from exc
    plain = xxtea_decrypt(_b64decode_aj2(text))
    if plain is None:
        raise DecodeError("DECRYPT_FAILED", "El XXTEA no abrió el archivo (clave o longitud inválida).")
    try:
        doc = json.loads(plain.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError("FORMAT_ERROR", "El contenido descifrado no es JSON UTF-8.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El archivo descifrado no es un objeto JSON.")
    return _apply_renames(doc)


def encode(doc: dict) -> str:
    """Offline API: JSON (nombres nuevos) -> contenido de profile.json."""
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "Se esperaba un objeto JSON.")
    old = _reverse_renames(doc)
    raw = json.dumps(old, ensure_ascii=False).encode("utf-8")
    return base64.b64encode(xxtea_encrypt(raw)).decode("ascii")


def run(file_bytes: bytes | str) -> str | None:
    """Offline API: JSON completo del archivo o None; nunca una lista parcial."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


def _read_file(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def _write_output(path: Path, rendered: str) -> None:
    import os
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, rendered.encode("utf-8"))
    finally:
        os.close(fd)


def _self_test() -> int:
    """Round-trip sintético; no usa archivos reales ni red.

    Casos: 1. Un profile.json sintético (nombres antiguos) abre y aplica
    los renombres y la conversión bool->string. 2. encode() del resultado
    reproduce el contenido original byte a byte. 3. Un profile.enc
    sintético se detecta y se reporta como PROFILE_ENC_KEYSTORE.
    4. Un archivo con la clave alterada no abre (DECRYPT_FAILED).
    5. Base64 con saltos de línea y caracteres inválidos se tolera.
    """
    cases = []

    def check(name, ok):
        cases.append(ok)
        print(f"  [{'OK' if ok else 'FAIL'}] {name}")

    print("RoVPN_archivos self-test:")
    old_doc = {
        "Version": "46.1",
        "Servers": [{"Name": "TEST", "Flag": "th", "SSLPort": "443",
                     "OvpnCertificate": "x", "AutoLogIn": True, "MultiCert": False,
                     "ServerIP": "1.2.3.4"}],
        "Networks": [{"Name": "P1", "Flag": "", "Info": "info ☕", "UseDefProxy": True}],
    }
    raw = json.dumps(old_doc, ensure_ascii=False).encode("utf-8")
    content = base64.b64encode(xxtea_encrypt(raw)).decode("ascii")
    try:
        doc = decode(content)
        server = doc["Servers"][0]
        network = doc["Networks"][0]
        check("profile.json abre y renombra claves",
              server.get("ServerName") == "TEST"
              and server.get("ServerFlag") == "th"
              and server.get("OpenVPNSSLPort") == "443"
              and server.get("SSHSSLPort") == "443"
              and server.get("setOpenVPN") == "x"
              and server.get("AutoLogIn") == "true"
              and server.get("MultiCert") == "false"
              and server.get("ServerDNS") == "1.2.3.4"
              and network.get("PayloadName") == "P1"
              and network.get("PayloadInfo") == "info ☕"
              and network.get("UseDefProxy") == "true"
              and network.get("ServerDNS") == "")
    except DecodeError:
        check("profile.json abre y renombra claves", False)
    try:
        back = json.loads(xxtea_decrypt(_b64decode_aj2(encode(doc))).decode("utf-8"))
        check("encode() reproduce el contenido original (mismo JSON)", back == old_doc)
    except DecodeError:
        check("encode() reproduce el contenido original (mismo JSON)", False)
    try:
        decode(bytes([0x28]) + bytes(range(32)) + b"\x00\x01\x02\xff\xfe")
        check("profile.enc detectado (PROFILE_ENC_KEYSTORE)", False)
    except DecodeError as exc:
        check("profile.enc detectado (PROFILE_ENC_KEYSTORE)", exc.code == "PROFILE_ENC_KEYSTORE")
    bad = bytearray(base64.b64decode(content))
    bad[10] ^= 0x01
    try:
        decode(base64.b64encode(bytes(bad)).decode("ascii"))
        check("clave/cuerpo alterado rechazado", False)
    except DecodeError as exc:
        check("clave/cuerpo alterado rechazado", exc.code in ("DECRYPT_FAILED", "FORMAT_ERROR"))
    noisy = "\n".join(content[i:i + 64] for i in range(0, len(content), 64)) + " \n¡basura!"
    try:
        check("Base64 con ruido se tolera", decode(noisy)["Servers"][0]["ServerName"] == "TEST")
    except DecodeError:
        check("Base64 con ruido se tolera", False)
    passed = sum(cases)
    print(json.dumps({"self_test": "pass" if passed == len(cases) else "fail",
                      "passed": passed, "total": len(cases)}, ensure_ascii=False))
    return 0 if passed == len(cases) else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, help="profile.json guardado localmente")
    source.add_argument("--stdin", action="store_true", help="Lee el profile.json desde stdin")
    source.add_argument("--encode", type=Path, metavar="JSON",
                        help="JSON con nombres nuevos -> contenido de profile.json")
    source.add_argument("--self-test", action="store_true",
                        help="Round-trip sintético; no usa archivos reales ni red")
    parser.add_argument("-o", "--output", type=Path, help="Guardar resultado; no sobrescribe")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    try:
        if args.encode is not None:
            doc = json.loads(args.encode.read_text(encoding="utf-8"))
            rendered = encode(doc) + "\n"
        else:
            raw = sys.stdin.buffer.read(MAX_BYTES + 1) if args.stdin else _read_file(args.file)
            if len(raw) > MAX_BYTES:
                raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
            rendered = json.dumps(decode(raw), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            _write_output(args.output, rendered)
        else:
            sys.stdout.write(rendered)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    except (OSError, json.JSONDecodeError):
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
