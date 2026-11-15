#!/usr/bin/env python3
"""TRM Tunnel (com.trm.tunnel, versionCode 19, versionName 2.8): .hxt files and their encrypted hexadecimal text.

Standalone Python 3.10+, standard library only, no network access.
For catalogs use TRM_Tunnel.py. TRM Tunnel has no live custom text/link
scheme (see README.md). See README.md in this directory.

Flow verified by decompiling this APK (jadx 1.5.3, LSParanoid strings
recovered from the DEX bytecode):
  * Import — OpenVPNClient.onCreate (VIEW intent forwarded by
    ImportTweakActivity) and onActivityResult (requestCode 1, file picker):
    ContentResolver.openInputStream(Uri) -> BufferedReader.readLine() ->
    PUtils.pDecrypt(context, line) -> new JSONObject(). If
    "tweak_password" is non-empty -> Y() ("Password Lock" dialog);
    otherwise -> B() directly. On failure: "Invalid or Corrupted File!".
  * Export — OpenVPNClient.X(String, JSONObject): JSONObject.toString() ->
    PUtils.pEncrypt(context, json) -> "SAVE TWEAK?" dialog. The file suffix
    is ".hxt" (OpenVPNClient.D0).
  * Policies checked AFTER decryption in B()/Y() (they do not derive the
    key): "tweak_expiry" (yyyy-MM-dd-HH-mm; "Tweak already expired!"),
    "hwid_lock" ("You are not allowed to use this tweak!"), "block_rooted"
    ("This tweak is blocked for rooted devices!"). On success B()
    de-duplicates "friendly_name" (" (n)") and saves into gremlin.json
    ("Imported File Successfully!"). This decoder returns every stored
    field without enforcing the policies.
  * Manifest: ImportTweakActivity, VIEW, schemes content/file, mimeType
    */*, pathPattern .*\\.hxt. No custom URI scheme is registered.

!!! VERIFIED AGAINST TRM's OWN libputils.so (2026-11-13) !!!
PUtils.pDecrypt/pEncrypt are native (System.loadLibrary("putils")).
The split APK's libputils.so was recovered and analysed directly
(SHA-256 ceba6a18...1ea53f, ELF64 AArch64, stripped): pEncrypt
@0x148928 and pDecrypt @0x148c5c are JNI wrappers that (after a
checkSignature call and a getCallingPackageName == "com.trm.tunnel"
gate, else they return a joke string) call the local helpers
xorWithKey @0x1476d4, stringToHex @0x1472cc and hexToString @0x147550.
xorWithKey builds the 12-byte key from .rodata 0xc4d24 (first 8 bytes
loaded with LDR at 0x147768, last 4 as immediates at 0x14773c/0x147764)
and XORs input[i] ^ key[i % 12] (UDIV/MSUB modulo, EOR at 0x147840).
pEncrypt = xorWithKey -> stringToHex (lowercase hex); pDecrypt =
hexToString (strtol base 16) -> xorWithKey. No AES, no salt/IV/MAC,
no other transformation. Verified by round-trip self-test (see
--self-test) and by an independent re-implementation fed with the key
bytes read straight from TRM's .rodata. Full evidence in
work/NOTES_libputils.md. Still no real TRM .hxt export exists to test
end-to-end, but the key and algorithm are now proven from TRM's own
library, not borrowed from HX Tunnel.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import re
import sys

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
# XOR key for .hxt profiles, verified against TRM Tunnel 2.8's OWN
# libputils.so (xorWithKey @0x1476d4 loads it from .rodata 0xc4d24).
# 12-byte format constant, not a user password. See module docstring
# and work/NOTES_libputils.md for the disassembly evidence.
PROFILE_KEY = b"4%PdXch>fkP]"


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


def _modified_utf8(data: bytes) -> str:
    # JNI GetStringUTFChars encodes UTF-16 surrogate pairs separately (CESU-8).
    # DataOutputStream.writeUTF uses the same modified UTF-8 representation.
    try:
        if any(byte >= 0xF0 for byte in data):
            raise UnicodeError("four-byte UTF-8 is not JNI modified UTF-8")
        text = data.replace(b"\xc0\x80", b"\0").decode("utf-8", errors="surrogatepass")
        return text.encode("utf-16-le", errors="surrogatepass").decode("utf-16-le")
    except UnicodeError as exc:
        raise DecodeError("DECRYPT_FAILED", "El perfil no contiene texto JNI válido.") from exc


def _to_modified_utf8(text: str) -> bytes:
    # Inverse of _modified_utf8: UTF-16 code units, each as CESU-8.
    raw = text.encode("utf-16-le", errors="surrogatepass")
    out = bytearray()
    for i in range(0, len(raw), 2):
        unit = raw[i] | (raw[i + 1] << 8)
        if unit == 0:
            out += b"\xc0\x80"
        elif unit < 0x80:
            out.append(unit)
        elif unit < 0x800:
            out.append(0xC0 | (unit >> 6))
            out.append(0x80 | (unit & 0x3F))
        else:
            out.append(0xE0 | (unit >> 12))
            out.append(0x80 | ((unit >> 6) & 0x3F))
            out.append(0x80 | (unit & 0x3F))
    return bytes(out)


def decrypt_profile_text(data: bytes | str) -> str:
    compact = re.sub(r"[ \t\r\n]", "", _text(data))
    if not compact or len(compact) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", compact):
        raise DecodeError("FORMAT_ERROR", "Se esperaba hexadecimal de longitud par de un archivo .hxt.")
    encrypted = bytes.fromhex(compact)
    plain = bytes(value ^ PROFILE_KEY[i % len(PROFILE_KEY)] for i, value in enumerate(encrypted))
    return _modified_utf8(plain)


def encrypt_profile_text(text: str) -> str:
    """Inverse of decrypt_profile_text (mirrors PUtils.pEncrypt); for round-trip tests."""
    plain = _to_modified_utf8(text)
    return bytes(value ^ PROFILE_KEY[i % len(PROFILE_KEY)] for i, value in enumerate(plain)).hex()


def decode(data: bytes | str) -> dict:
    """Return every stored field without changing names, passwords or policies."""
    return _json(decrypt_profile_text(data))


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


def _self_test() -> int:
    """Round-trip check (encrypt -> decrypt returns the input).

    Prints only pass/fail counts and field counts, never profile values.
    Returns 0 when every synthetic profile round-trips and the
    independent re-implementation of the XOR agrees.
    """
    cases = [
        {"friendly_name": "Test", "tweak_password": "", "tweak_expiry": "2027-01-01-00-00",
         "hwid_lock": "", "block_rooted": "0", "server": "1.2.3.4", "port": "443",
         "user": "u", "password": "p", "payload": "GET / HTTP/1.1", "sni": "example.com",
         "dns": "1.1.1.1", "mode": "ssl", "extra": "x", "count": "7"},
        {"friendly_name": "Café — ünïcode ✓", "note": "emoji \U0001F600 fuera del BMP",
         "empty": "", "n": "0"},
        {"friendly_name": "NUL\u0000dentro", "a": "x" * 200, "b": "y" * 5},
        {"solo": "1"},
        {"friendly_name": "Largo " + "z" * 5000, "k": "v"},
    ]
    passed = 0
    for profile in cases:
        text = json.dumps(profile, ensure_ascii=False, separators=(",", ":"))
        encoded = encrypt_profile_text(text)
        if decode(encoded) == profile and decode(encoded.upper()) == profile:
            passed += 1
    print(json.dumps({"self_test": "pass" if passed == len(cases) else "fail",
                      "profiles": len(cases), "passed": passed,
                      "field_counts": [len(c) for c in cases]}, ensure_ascii=False))
    return 0 if passed == len(cases) else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, help="Archivo .hxt o texto cifrado guardado")
    source.add_argument("--text", help="Contenido hexadecimal de un perfil .hxt")
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
