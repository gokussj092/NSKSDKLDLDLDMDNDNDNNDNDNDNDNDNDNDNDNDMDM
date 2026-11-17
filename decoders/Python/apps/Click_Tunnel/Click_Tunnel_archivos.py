#!/usr/bin/env python3
"""Click Tunnel (com.clicktunnel.vpn, versionCode 1, versionName 1.0): .sup/.wsuiou profile files.

Standalone Python 3.10+; needs pycryptodome (Crypto.Cipher.AES) for AES-GCM.
Use ~/workspace/http-custom-update/venv/bin/python. No network access.
For catalogs use Click_Tunnel.py. See README.md in this directory.

Flow verified by decompiling this APK (jadx 1.5.3; strings via
AbstractC0144Cp0.j, ported in work/cp0.py):
  * Import — Main.onCreate (VIEW intent, schemes content/file, mimeType
    */*, pathPattern .*\\.sup in the manifest) and onActivityResult
    (requestCode 0, GET_CONTENT */* file picker): read the file (lines
    concatenated) -> Main.M(context, str). The QR-scan result
    (CaptureActivity, C1166Vz) and the cloud download (AsyncTaskC1425aN)
    feed the same Main.M with the same text format.
  * Main.M: new C2692j30(AbstractC2334hX.a).a(str) decrypts; the result
    must start with the app name "Click Tunnel" ("Invalid config: does
    not belong to this app" otherwise); the remainder is JSON.
  * Outer cipher (C2692j30): AES/GCM/NoPadding, 128-bit tag; key =
    first 32 bytes of UTF-8 of AbstractC2334hX.a (an 84-char string:
    33 spaces + "*" + 28 spaces + "'" + 12 spaces + "." + 8 spaces);
    format = Base64(nonce[12] || ciphertext || tag[16]) (Android
    Base64.DEFAULT, newlines every 76 chars); encryption uses a random
    12-byte nonce. Inner profile fields are also individually
    C2692j30.b-encrypted (same key, fresh random nonce each):
    Payload, SNIHost, ProxyHost, ProxyPort, DNSHost, UDPhost, UDPobfs,
    UDPauth, UDPUpMbps, UDPDownMbps, UDPPort, v2rayConfig, v2raySni,
    WireGuardConfig. They are decrypted lazily on use by
    AbstractC1201Wq0.h (try/catch, raw value on failure); this decoder
    applies the same try/fallback rule up front.
  * Export — ExportActivity.m(): JSONObject E -> this.N.b(appName +
    E.toString()); file export writes m() via CREATE_DOCUMENT with
    mime *text/plain* and filename "<name>.wsuiou"; the manifest VIEW
    filter matches ".sup" instead (app quirk: exported files are
    .wsuiou, the tap-to-open filter is .sup; the in-app picker accepts
    any file). The QR export encodes m() itself as the QR content.
    The cloud export uploads m() to Firebase Storage as
    "<xfsd-id>.wsuiou" and shows "CONFIG KEY:  xfsd://<20 chars>";
    import ("Import Cloud Config", hint "Config Key") downloads that
    object and feeds it to Main.M. The xfsd:// text is a key, not a
    registered URI scheme; the dialog uses the typed text verbatim, so
    the 20-char key is typed without the "xfsd://" prefix.
  * Policies checked AFTER decryption in Main.M (they do not derive the
    key): "ExpireDate" (epoch ms; "expired" if now >= it),
    "RootBlock" (rooted device), "DeviceID" (must equal this device's
    ID, AbstractC3148mf.j(), when non-empty), "PSInstall" (installer
    must be Play), "isPassON" (password dialog; FA compares the typed
    password with "MyPass"). This decoder returns every stored field
    without enforcing the policies.
  * Export quirk (code as written): for TunnelType 5, "v2rayConfig" is
    written "" and "v2raySni" encrypted; for TunnelType 9 it is the
    other way round. The decoder decrypts whichever field is non-empty.

!!! NOT VERIFIED END-TO-END: no real .sup/.wsuiou file exported by
Click Tunnel 1.0 exists yet. The key and algorithm are proven from the
app's own code (C2692j30 + AbstractC2334hX.a), and the round-trip
self-test below verifies the implementation against itself, but a real
export is still the pending confirmation. !!!
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import math
import os
from pathlib import Path
import re
import sys

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ImportError as exc:  # pycryptodome, in the venv named in the docstring
    raise SystemExit(
        "Falta pycryptodome (Crypto.Cipher.AES). Usa "
        "~/workspace/http-custom-update/venv/bin/python."
    ) from exc

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
# Profile key seed AbstractC2334hX.a, extracted verbatim (Cp0.j) and
# written as explicit runs so the space counts cannot drift:
# 33 spaces + "*" + 28 spaces + "'" + 12 spaces + "." + 8 spaces = 84 chars.
# Format constant, not a user password. The AES key is the first 32 bytes
# of its UTF-8 (32 spaces).
PROFILE_SEED = " " * 33 + "*" + " " * 28 + "'" + " " * 12 + "." + " " * 8
PROFILE_KEY = PROFILE_SEED.encode("utf-8")[:32]
APP_NAME = "Click Tunnel"
# Inner fields that ExportActivity.m() encrypts with C2692j30.b (fresh
# random nonce each); every other stored field is plaintext.
ENCRYPTED_FIELDS = (
    "Payload", "SNIHost", "ProxyHost", "ProxyPort", "DNSHost",
    "UDPhost", "UDPobfs", "UDPauth", "UDPUpMbps", "UDPDownMbps", "UDPPort",
    "v2rayConfig", "v2raySni", "WireGuardConfig",
)


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _text(data: bytes | str) -> str:
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


def _gcm_decrypt(text: str) -> str:
    """C2692j30.a: Base64(nonce[12] || ciphertext || tag[16]) -> UTF-8."""
    compact = re.sub(r"[ \t\r\n]", "", text)
    if not compact or len(compact) % 4 == 1 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        raise DecodeError("FORMAT_ERROR", "Se esperaba Base64 estándar de un perfil .sup/.wsuiou.")
    try:
        raw = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR", "Base64 inválido.") from exc
    if len(raw) < 12 + 16:
        raise DecodeError("TRUNCATED", "El perfil no contiene nonce ni etiqueta GCM completos.")
    nonce, rest = raw[:12], raw[12:]
    ciphertext, tag = rest[:-16], rest[-16:]
    try:
        cipher = AES.new(PROFILE_KEY, AES.MODE_GCM, nonce=nonce)
        plain = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise DecodeError("DECRYPT_FAILED", "La etiqueta GCM no verifica para esta aplicación.") from exc
    try:
        return plain.decode("utf-8")
    except UnicodeError as exc:
        raise DecodeError("DECRYPT_FAILED", "El perfil no contiene texto UTF-8 válido.") from exc


def _gcm_encrypt(text: str) -> str:
    """C2692j30.b (mirrors ExportActivity.m): random nonce, Base64 output."""
    nonce = get_random_bytes(12)
    cipher = AES.new(PROFILE_KEY, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode("utf-8"))
    return base64.b64encode(nonce + ciphertext + tag).decode("ascii")


def encrypt_profile_text(text: str) -> str:
    """Inverse of the outer layer; for round-trip tests only."""
    return _gcm_encrypt(text)


def _try_field(value: str) -> str:
    """AbstractC1201Wq0.h: decrypt, or keep the raw value on failure."""
    if not value:
        return value
    try:
        return _gcm_decrypt(value)
    except DecodeError:
        return value


def decode(data: bytes | str) -> dict:
    """Return every stored field (inner GCM fields decrypted, policies
    NOT enforced, names/passwords unchanged)."""
    plain = _gcm_decrypt(_text(data))
    if not plain.startswith(APP_NAME):
        raise DecodeError("NOT_THIS_APP", "El perfil no pertenece a Click Tunnel.")
    doc = _json(plain[len(APP_NAME):])
    for key in ENCRYPTED_FIELDS:
        if isinstance(doc.get(key), str):
            doc[key] = _try_field(doc[key])
    return doc


def run(file_bytes: bytes | str) -> str | None:
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


def _read(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def _write_output(path: Path, rendered: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, rendered.encode("utf-8"))
    finally:
        os.close(fd)


def _encrypt_profile(profile: dict) -> str:
    """Build an exported file exactly like ExportActivity.m(): inner
    GCM fields encrypted, then the whole "Click Tunnel" + JSON encrypted."""
    inner = dict(profile)
    for key in ENCRYPTED_FIELDS:
        if isinstance(inner.get(key), str) and inner[key]:
            inner[key] = _gcm_encrypt(inner[key])
    return _gcm_encrypt(APP_NAME + json.dumps(inner, ensure_ascii=False, separators=(",", ":")))


def _self_test() -> int:
    """Round-trip check (encrypt -> decrypt returns the input).

    Prints only pass/fail counts and field counts, never profile values.
    Returns 0 when every synthetic profile round-trips.
    """
    base = {"PSInstall": False, "DeviceID": "", "RootBlock": False, "MobileData": False,
            "ExpireDate": 0, "isMsg": False, "CFGMessage": "", "isPassON": False,
            "MyPass": "", "TunnelType": 0, "useCloudFront": False, "DNSHost": "",
            "UDPhost": "", "UDPobfs": "", "UDPauth": "", "UDPUpMbps": "", "UDPDownMbps": "",
            "UDPPort": "", "UDPMode": 0, "v2rayConfig": "", "v2raySni": "", "isUri": False,
            "PreserveSNI": False, "TLS": False, "WireGuardConfig": "", "Server": "",
            "NoobDev": 1}
    cases = []
    p = dict(base, TunnelType=1, Payload="GET / HTTP/1.1[crlf]Host: [app_host][crlf][crlf]",
             SNIHost="example.com", ProxyHost="1.2.3.4", ProxyPort="8080")
    cases.append(p)
    cases.append(dict(base, TunnelType=6, DNSHost="dns.example.com"))
    cases.append(dict(base, TunnelType=7, UDPhost="udp.example.com", UDPobfs="obfs",
                      UDPauth="auth", UDPUpMbps="2", UDPDownMbps="4", UDPPort="20000-50000",
                      UDPMode=0))
    cases.append(dict(base, TunnelType=9, v2rayConfig='{"v": "2"}', v2raySni=""))
    cases.append(dict(base, TunnelType=5, v2rayConfig="", v2raySni="sni.example.com",
                      isUri=True, PreserveSNI=True, TLS=True))
    cases.append(dict(base, TunnelType=8, WireGuardConfig="[Interface]\nPrivateKey = abc"))
    cases.append(dict(base, TunnelType=2, Payload="Café — ünïcode ✓ \U0001F600",
                      SNIHost="", ProxyHost="", ProxyPort="", isPassON=True, MyPass="secret",
                      ExpireDate=1893456000000, DeviceID="deadbeef", isMsg=True,
                      CFGMessage="Hola", Server='{"Name": "X"}'))
    cases.append(dict(base))  # all empty/default
    passed = 0
    for profile in cases:
        encoded = _encrypt_profile(profile)
        if decode(encoded) == profile:
            passed += 1
    print(json.dumps({"self_test": "pass" if passed == len(cases) else "fail",
                      "profiles": len(cases), "passed": passed,
                      "field_counts": [len(c) for c in cases]}, ensure_ascii=False))
    return 0 if passed == len(cases) else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, help="Archivo .sup/.wsuiou o texto cifrado guardado")
    source.add_argument("--text", help="Contenido Base64 de un perfil .sup/.wsuiou (también texto de QR)")
    source.add_argument("--self-test", action="store_true",
                        help="Round-trip sintético (cifrar -> descifrar); no usa archivos reales")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; no sobrescribe")
    parser.add_argument("--summary", action="store_true",
                        help="Solo claves y recuento de campos, sin valores descifrados")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    try:
        doc = decode(args.text if args.text is not None else _read(args.file))
        if args.summary:
            rendered = json.dumps({"fields": sorted(doc.keys()), "field_count": len(doc)},
                                  ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        else:
            rendered = json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            _write_output(args.output, rendered)
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
