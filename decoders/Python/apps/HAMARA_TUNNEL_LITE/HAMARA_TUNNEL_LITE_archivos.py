#!/usr/bin/env python3
"""HAMARA TUNNEL LITE (com.hamarateam.litetunnel, versionCode 20, versionName 2.9):
.hamaratnl files, offline catalog-update files and hamaratnl:// text.

Standalone Python 3.10+, standard library only, no network access.
For catalogs use HAMARA_TUNNEL_LITE.py.

Flow verified by decompiling this APK (jadx 1.5.3, LSParanoid strings
recovered from the DEX bytecode):
  * Single profile (.hamaratnl) — OpenVPNClient.onCreate (VIEW intent
    forwarded by ImportTweakActivity) and onActivityResult (requestCode
    1001, file picker): ContentResolver.openInputStream(Uri) ->
    BufferedReader.readLine() -> PUtils.pDecrypt(context, line) ->
    new JSONObject(). If "tweak_password" is non-empty -> f0() (password
    dialog, the entered text must equal tweak_password); otherwise -> N()
    (save as custom profile). On failure: "Invalid or Corrupted File!".
  * Export — OpenVPNClient.d0(JSONObject, ...): JSONObject.toString() ->
    PUtils.pEncrypt(context, json) -> shown in an EditText as
    "hamaratnl://" + hex. The file suffix is ".hamaratnl"
    (OpenVPNClient.<init>: ".hamaratnl", P0 = "hamaratnl://").
  * Text import — ViewOnClickListenerC4060mL case 0: the pasted text is
    split on "hamaratnl://", [1] is pDecrypted -> profile JSON -> N() or
    f0() by tweak_password. NOTE: "hamaratnl://" is NOT registered as an
    Android deep link in the manifest (no <data android:scheme=
    "hamaratnl">); it only works as text pasted inside the app.
  * Offline catalog update — OpenVPNClient.onRequestPermissionsResult
    (requestCode 99): ACTION_GET_CONTENT, type */*, startActivityForResult
    (..., 0). onActivityResult (requestCode 0): the whole file is read,
    Kn.c(text, Kn.a) = Base64 -> XXTEA ("...|...") -> JSON; if it contains
    "Version" the raw text is saved as filesDir + "/janu.json" and the app
    restarts; otherwise "Offline Update Error!". Same envelope as the
    catalog (see HAMARA_TUNNEL_LITE.py).
  * Policies checked AFTER decryption in N()/f0() (they do not derive the
    key): "tweak_expiry" (yyyy-MM-dd-HH-mm; "Tweak already expired!"),
    "tweak_password" (see above), "hwid_lock" ("You are not allowed to
    use this tweak!"), "block_rooted" ("This tweak is blocked for rooted
    devices!"). On success N() de-duplicates "friendly_name" (" (n)") and
    saves into janu.json ("Imported File Successfully!"). This decoder
    returns every stored field without enforcing the policies.

!!! VERIFIED AGAINST HAMARA's OWN libputils.so (2026-11-13) !!!
PUtils.pDecrypt/pEncrypt are native (System.loadLibrary("putils")).
The split APK's config.arm64_v8a.apk libputils.so was analysed directly
(SHA-256 of the XAPK 6fbecfda...; ELF64 AArch64, stripped): the XOR helper
@0x1466d4 loads the 12-byte key from .rodata 0xbfe2c (adrp x9, #0xbf000;
add x9, x9, #0xe2c; ldr x21, [x9]) and XORs input[i] ^ key[i % 12]
(UDIV/MSUB modulo at 0x14682c/0x14683c, EOR at 0x146850). The 12 bytes at
0xbfe2c read verbatim "4%PdXch>fkP]" — the same key as TRM/HX/RJC, proven
from THIS app's own library. pEncrypt = xorWithKey -> stringToHex
(lowercase hex); pDecrypt = hexToString (strtol base 16) -> xorWithKey.
No AES, no salt/IV/MAC, no other transformation. Verified by round-trip
self-test (see --self-test). Still no real .hamaratnl export exists to
test end-to-end, but the key and algorithm are now proven from HAMARA's
own library.
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

# Reuse the catalog envelope for offline-update files.
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from HAMARA_TUNNEL_LITE import decode as _decode_catalog, CatalogError
except Exception:  # pragma: no cover - catalog module lives next to this file
    _decode_catalog = None  # type: ignore
    CatalogError = ValueError  # type: ignore

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
# XOR key for .hamaratnl profiles, verified against HAMARA TUNNEL LITE 2.9's
# OWN libputils.so (xor helper @0x1466d4 loads it from .rodata 0xbfe2c).
# 12-byte format constant, not a user password. See module docstring.
PROFILE_KEY = b"4%PdXch>fkP]"
SCHEME = "hamaratnl://"


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
        raise DecodeError("FORMAT_ERROR", "Se esperaba texto o bytes UTF-8.") from exc
    return value.strip()


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


def _unique(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("duplicate key")
        result[k] = v
    return result


def _nonfinite(_value):
    raise ValueError("nonfinite number")


def _modified_utf8(data: bytes) -> str:
    # JNI GetStringUTFChars encodes UTF-16 surrogate pairs separately (CESU-8).
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
    if compact.startswith(SCHEME):
        compact = compact[len(SCHEME):]
    if not compact or len(compact) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", compact):
        raise DecodeError("FORMAT_ERROR", "Se esperaba hexadecimal de longitud par de un archivo .hamaratnl.")
    encrypted = bytes.fromhex(compact)
    plain = bytes(value ^ PROFILE_KEY[i % len(PROFILE_KEY)] for i, value in enumerate(encrypted))
    return _modified_utf8(plain)


def encrypt_profile_text(text: str) -> str:
    """Inverse of decrypt_profile_text (mirrors PUtils.pEncrypt); for round-trip tests."""
    plain = _to_modified_utf8(text)
    return bytes(value ^ PROFILE_KEY[i % len(PROFILE_KEY)] for i, value in enumerate(plain)).hex()


def decode_profile(data: bytes | str) -> dict:
    """Decode one .hamaratnl profile (or hamaratnl:// text) into its JSON fields."""
    return _json(decrypt_profile_text(data))


def decode_catalog_file(data: bytes | str) -> dict:
    """Decode an offline catalog-update file (XXTEA Base64 blob, must contain Version)."""
    if _decode_catalog is None:
        raise DecodeError("CATALOG_MODULE", "No se pudo cargar HAMARA_TUNNEL_LITE.py.")
    try:
        doc = _decode_catalog(data)
    except CatalogError as exc:
        raise DecodeError("CATALOG_DECRYPT_FAILED", str(exc)) from exc
    if "Version" not in doc:
        raise DecodeError("WRONG_DOCUMENT", "El catálogo no contiene 'Version'.")
    return doc


def decode(data: bytes | str) -> dict:
    """Return every stored field without changing names, passwords or policies.

    Tries the .hamaratnl profile format first (hex/XOR, optionally after
    "hamaratnl://"), then the offline catalog-update envelope (XXTEA/Base64).
    """
    text = _text(data)
    stripped = text[len(SCHEME):] if text.startswith(SCHEME) else text
    single_line = re.sub(r"[ \t\r\n]", "", stripped)
    if single_line and len(single_line) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", single_line):
        return decode_profile(data)
    return decode_catalog_file(data)


def decode_kind(data: bytes | str) -> tuple[str, dict]:
    """Like decode(), but also reports which of the two formats opened."""
    text = _text(data)
    stripped = text[len(SCHEME):] if text.startswith(SCHEME) else text
    single_line = re.sub(r"[ \t\r\n]", "", stripped)
    if single_line and len(single_line) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", single_line):
        try:
            return ("hamaratnl-profile", decode_profile(data))
        except DecodeError:
            pass
    return ("catalog-update", decode_catalog_file(data))


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
    """Round-trip checks (encrypt -> decrypt returns the input) + bundled asset.

    Prints only pass/fail counts and field counts, never profile values.
    Returns 0 when every synthetic profile round-trips, the hamaratnl://
    text form round-trips, and the bundled janu.json catalog opens.
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
        if decode_profile(encoded) == profile and decode_profile(encoded.upper()) == profile:
            passed += 1
    # hamaratnl:// text form round-trips as well.
    text0 = json.dumps(cases[0], ensure_ascii=False, separators=(",", ":"))
    scheme_ok = decode_profile(SCHEME + encrypt_profile_text(text0)) == cases[0]
    # Bundled catalog asset opens through the catalog-update path.
    here = Path(__file__).resolve().parent
    asset = here / "janu.json"
    catalog_ok = False
    if asset.is_file():
        try:
            doc = decode_catalog_file(asset.read_bytes())
            catalog_ok = doc.get("Version") == "322" and len(doc["Free_servers"]) == 23
        except DecodeError:
            catalog_ok = False
    ok = passed == len(cases) and scheme_ok and catalog_ok
    print(json.dumps({"self_test": "pass" if ok else "fail",
                      "profiles": len(cases), "passed": passed,
                      "hamaratnl_scheme": scheme_ok,
                      "bundled_catalog": catalog_ok,
                      "field_counts": [len(c) for c in cases]}, ensure_ascii=False))
    return 0 if ok else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path,
                        help="Archivo .hamaratnl o archivo de actualización de catálogo")
    source.add_argument("--text", help="Contenido hexadecimal de un perfil .hamaratnl o texto hamaratnl://")
    source.add_argument("--self-test", action="store_true",
                        help="Round-trip sintético (cifrar -> descifrar) + catálogo incluido; no usa archivos reales")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; no sobrescribe")
    parser.add_argument("--summary", action="store_true",
                        help="Solo claves y recuento de campos, sin valores descifrados")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    try:
        raw = args.text if args.text is not None else _read(args.file)
        kind, doc = decode_kind(raw)
        if args.summary:
            rendered = json.dumps({"kind": kind, "fields": sorted(doc.keys()),
                                   "field_count": len(doc)}, ensure_ascii=False, indent=2,
                                  allow_nan=False) + "\n"
        else:
            rendered = json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            _write_output(args.output, rendered)
            print(f"[{kind}] Wrote {len(rendered)} bytes to {args.output}")
        else:
            sys.stdout.write(rendered)
        return 0
    except DecodeError as exc:
        print(f"ERROR [{exc.code}]: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
