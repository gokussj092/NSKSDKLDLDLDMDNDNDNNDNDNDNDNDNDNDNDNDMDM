#!/usr/bin/env python3
"""Fx Tunnel (com.fx.tunnel, versionCode 39, versionName 4.8): .fxt files and their encrypted hexadecimal text.

Standalone Python 3.10+, standard library only, no network access.
For catalogs use Fx_Tunnel.py. Fx Tunnel has no live custom text/link
scheme (see README.md).

Flow (family template, verified against THIS APK where the code is
statically present; the UI layer itself is LIAPP-protected, see README):
  * Import — ImportTweakActivity forwards the VIEW intent to
    OpenVPNClient; onCreate (VIEW) and onActivityResult (file picker)
    both do: ContentResolver.openInputStream(Uri) ->
    BufferedReader.readLine() -> PUtils.pDecrypt(context, line) ->
    new JSONObject(). If "tweak_password" is non-empty -> "Password
    Lock" dialog; otherwise the profile is imported directly. On
    failure: "Invalid or Corrupted File!". The profile field names
    (tweak_password, friendly_name, tweak_expiry, hwid_lock,
    block_rooted, Payloads, "Custom Tweak") are LSParanoid strings
    recovered from THIS APK's DEX.
  * Export — OpenVPNClient.X(String, JSONObject): JSONObject.toString()
    -> PUtils.pEncrypt(context, json) -> "SAVE TWEAK?" dialog. The file
    suffix is ".fxt" (AndroidManifest pathPattern .*\\.fxt, VIEW intent,
    schemes content/file, mimeType */*).
  * Policies checked AFTER decryption (they do not derive the key):
    "tweak_expiry" (yyyy-MM-dd-HH-mm), "hwid_lock",
    "block_rooted". On success the profile is de-duplicated by
    "friendly_name" (" (n)") and saved into gremlin.json
    ("Imported File Successfully!"). This decoder returns every stored
    field without enforcing the policies.
  * Manifest: ImportTweakActivity, VIEW, schemes content/file, mimeType
    */*, pathPattern .*\\.fxt. No custom URI scheme is registered.

!!! VERIFIED AGAINST Fx Tunnel's OWN libputils.so (2026-11-17) !!!
PUtils.pDecrypt/pEncrypt are native (System.loadLibrary("putils")).
The arm64 split's libputils.so was analysed directly (SHA-256
e3e8d9e0...1c758, ELF64 AArch64, stripped): pEncrypt @0x14a928 and
pDecrypt @0x14aed0 are JNI wrappers that (after a checkSignature call
and a getCallingPackageName == "com.fx.tunnel" gate, else they return
a joke string) call the local helpers xorWithKey @0x1496d4,
stringToHex @0x1492cc and hexToString @0x149550.
xorWithKey builds the 12-byte key from .rodata 0xc53a6 (first 8 bytes
loaded with LDR at 0x149768, last 4 as immediates MOV w28, #0x6b66 /
MOVK w28, #0x5d50, lsl #16) and XORs input[i] ^ key[i % 12].
pEncrypt = xorWithKey -> stringToHex (lowercase hex); pDecrypt =
hexToString (strtol base 16, trailing lone nibble parses as one
digit) -> xorWithKey. No AES, no salt/IV/MAC, no other transformation.

Proof with real bundled data (no real .fxt export exists yet):
the "server.psi" asset (SHA-256 8d087d9c..., byte-identical in all
five apps of this family) decrypts with this key through the
vendor's double-hex framing (drop 1 leading hex nibble, XOR phase 7,
hex-decode the recovered hex text, split on newlines, hex-decode each
segment) to 22 valid Psiphon JSON server entries (17 fields each;
the first of 23 segments is truncated at its opening '{"').
Use --psi to run that check on any server.psi asset. That proves the
key bytes and their order; the single-layer .fxt framing rests on the
Java flow plus the pEncrypt/pDecrypt disassembly above.
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
# XOR key for .fxt profiles, verified against Fx Tunnel 4.8's OWN
# libputils.so (xorWithKey @0x1496d4 loads it from .rodata 0xc53a6).
# 12-byte format constant, not a user password. See module docstring.
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


def _hex_to_bytes(compact: str) -> bytes:
    # Mirrors native hexToString: pairs via std::stoi(chunk, 16); a
    # trailing lone nibble (odd-length input) parses as one digit.
    out = bytearray()
    end = len(compact) - 1 if len(compact) % 2 else len(compact)
    for i in range(0, end, 2):
        out.append(int(compact[i:i + 2], 16))
    if len(compact) % 2:
        out.append(int(compact[-1], 16))
    return bytes(out)


def decrypt_profile_text(data: bytes | str) -> str:
    compact = re.sub(r"[ \t\r\n]", "", _text(data))
    if not compact or not re.fullmatch(r"[0-9a-fA-F]+", compact):
        raise DecodeError("FORMAT_ERROR", "Se esperaba hexadecimal de un archivo .fxt.")
    encrypted = _hex_to_bytes(compact)
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


def decode_server_psi(data: bytes | str) -> list:
    """Decode the bundled assets/server.psi asset into Psiphon server entries.

    Vendor framing (NOT the .fxt format): double hex with a one-nibble
    shift and a displaced XOR phase. Drop 1 leading hex char, hex-decode,
    XOR with PROFILE_KEY starting at phase 7, split the recovered hex
    text on newlines, hex-decode each segment and parse the concatenated
    JSON objects. The first segment is truncated at its opening '{"',
    so one entry fewer than the segment count is expected.
    """
    compact = re.sub(r"[ \t\r\n]", "", _text(data))
    if not compact or not re.fullmatch(r"[0-9a-fA-F]+", compact):
        raise DecodeError("FORMAT_ERROR", "Se esperaba hexadecimal de un asset server.psi.")
    raw = bytes.fromhex(compact[1:])
    recovered = bytes(value ^ PROFILE_KEY[(i + 7) % len(PROFILE_KEY)] for i, value in enumerate(raw))
    try:
        inner = b"".join(bytes.fromhex(part.decode("ascii"))
                         for part in recovered.split(b"\n") if part)
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("DECRYPT_FAILED", "El asset server.psi no contiene texto hex tras el XOR.") from exc
    text = inner.decode("utf-8", errors="strict") if all(b < 0x80 for b in inner) else None
    if text is None:
        raise DecodeError("DECRYPT_FAILED", "El asset server.psi no descifró a texto UTF-8.")
    decoder = json.JSONDecoder()
    entries, idx = [], 0
    while idx < len(text):
        while idx < len(text) and text[idx] not in "{":
            idx += 1
        if idx >= len(text):
            break
        try:
            obj, end = decoder.raw_decode(text, idx)
        except (ValueError, RecursionError):
            break
        if isinstance(obj, dict):
            entries.append(obj)
        idx = end
    if not entries:
        raise DecodeError("DECRYPT_FAILED", "El asset server.psi no contiene entradas JSON válidas.")
    return entries


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
    """Round-trip check (encrypt -> decrypt returns the input) + server.psi proof.

    Prints only pass/fail counts and field counts, never profile values.
    Returns 0 when every synthetic profile round-trips and the bundled
    server.psi asset (if present next to this script's work dir) yields
    at least 20 valid Psiphon entries.
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
    psi_entries = None
    psi_path = Path(__file__).with_name("server.psi")
    if not psi_path.exists():
        psi_path = Path("extracted/base/assets/server.psi")
    if psi_path.exists():
        try:
            psi_entries = len(decode_server_psi(_read(psi_path)))
        except DecodeError:
            psi_entries = 0
    ok = passed == len(cases) and (psi_entries is None or psi_entries >= 20)
    print(json.dumps({"self_test": "pass" if ok else "fail",
                      "profiles": len(cases), "passed": passed,
                      "field_counts": [len(c) for c in cases],
                      "server_psi_entries": psi_entries}, ensure_ascii=False))
    return 0 if ok else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, help="Archivo .fxt o texto cifrado guardado")
    source.add_argument("--text", help="Contenido hexadecimal de un perfil .fxt")
    source.add_argument("--self-test", action="store_true",
                        help="Round-trip sintético (cifrar -> descifrar) + prueba server.psi; no usa archivos reales")
    parser.add_argument("--psi", action="store_true",
                        help="Decodifica un asset server.psi (doble hex) en vez de un perfil .fxt")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; no sobrescribe")
    parser.add_argument("--summary", action="store_true",
                        help="Solo claves y recuento de campos, sin valores descifrados")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    try:
        if args.psi:
            if args.text is not None:
                data = args.text
            elif args.file is not None:
                data = _read(args.file)
            else:
                parser.error("--psi necesita un archivo o --text")
            entries = decode_server_psi(data)
            if args.summary:
                regions = sorted({e.get("region", "?") for e in entries if isinstance(e, dict)})
                rendered = json.dumps({"entries": len(entries), "regions": regions,
                                       "fields": sorted(entries[0].keys()) if entries else []},
                                      ensure_ascii=False, indent=2, allow_nan=False) + "\n"
            else:
                rendered = json.dumps(entries, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
            if args.output:
                _write_output(args.output, rendered)
            else:
                sys.stdout.write(rendered)
            return 0
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
