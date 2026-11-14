#!/usr/bin/env python3
"""RJC Tunnel VPN (com.rjctunnel.vpn, versionCode 19, versionName RJC-19):
.rjc files and their encrypted hexadecimal text.

Standalone Python 3.10+, standard library only, no network access.
For catalogs use RJC_Tunnel_VPN.py. See README.md in this directory.

Flow verified against THIS APK (jadx 1.5.3, LSParanoid strings recovered
from the DEX bytecode, libputils.so disassembled with Capstone):
  * Import — ImportTweakActivity forwards the VIEW intent to
    OpenVPNClient; onCreate (VIEW) and onActivityResult (requestCode
    1001, file picker) both do: ContentResolver.openInputStream(Uri) ->
    BufferedReader.readLine() -> PUtils.pDecrypt(context, line) ->
    new JSONObject(). If "tweak_password" is non-empty -> Z()
    ("Password Lock" dialog); otherwise -> B() directly. On failure:
    "Invalid or Corrupted File!".
  * Export — OpenVPNClient.X(String, JSONObject): JSONObject.toString()
    -> PUtils.pEncrypt(context, json) -> file written as
    "<friendly_name>.rjc" in Downloads/RJCTUNNEL, mime
    application/octet-stream.
  * Policies checked AFTER decryption in B()/Z() (they do not derive the
    key): "tweak_expiry" (yyyy-MM-dd-HH-mm; "Tweak already expired!"),
    "hwid_lock" ("You are not allowed to use this tweak!"),
    "block_rooted" ("This tweak is blocked for rooted devices!"). On
    success B() de-duplicates "friendly_name" (" (n)") and saves into
    gremlin.json ("Payloads" array, "Imported File Successfully!").
    This decoder returns every stored field without enforcing the
    policies.
  * Manifest: ImportTweakActivity, VIEW, schemes content/file, mimeType
    */*, pathPattern .*\\.rjc. No custom text/link URI scheme for
    profiles is registered (no rjc:// or similar).
  * Secondary use: TunnelVpnManagerPsi.startPsiphon() passes the
    "server.psi" asset through PUtils.pDecrypt() when the Psiphon
    config is "auto".

Native method (libputils.so, SHA-256 43a1aeda...; see
work/NOTES_libputils.md for the full evidence):
  * pEncrypt (0x149924) = stringToHex(xorWithKey(UTF-8 input));
    pDecrypt (0x149c54) = xorWithKey(hexToString(input)).
  * xorWithKey (0x1486d0): out[i] = in[i] XOR key[i % 12]; the 12-byte
    format key lives in .rodata at 0xc505e and is loaded with
    adrp+add plus an immediate for the tail bytes.
  * stringToHex (0x1482c8): std::ostringstream with std::hex, setw(2),
    setfill('0') -> lowercase hex, two chars per byte.
  * hexToString (0x14854c): for each 2-char chunk, std::stoi(chunk, 16)
    -> push_back(char). A trailing lone nibble (odd-length input) is
    parsed as a single hex digit, mirroring the native code; this
    decoder accepts it.
  * Both JNI entries first call checkSignature() and then require
    getCallingPackageName() == "com.rjctunnel.vpn", otherwise they
    return a fixed joke string instead of transforming. Those are
    anti-repack gates: they do not affect the transform itself, so
    offline decoding needs neither a signature nor a package name.

Key evidence (no real .rjc export was available anywhere to test
against — none in the SP-DECODE repo branch feat/nuevas-integraciones,
none in this workspace):
  * The key above is taken from RJC's OWN libputils.so by disassembly
    (not borrowed from a sibling app): xorWithKey references .rodata
    0xc505e directly.
  * The same key unlocks real data bundled in THIS apk: the
    "server.psi" asset decrypts (through the vendor's double-hex
    framing of that asset, which is NOT the .rjc format) to 22 valid
    Psiphon JSON server entries. That proves the key bytes and their
    order; it does not by itself prove the single-layer .rjc framing,
    which rests on the Java flow plus the pEncrypt/pDecrypt
    disassembly above.
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
# Shared-family format constant from THIS apk's libputils.so (.rodata
# 0xc505e, loaded by xorWithKey), not a user password.
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
        raise DecodeError("FORMAT_ERROR", "Se esperaba hexadecimal de un archivo .rjc.")
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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("file", nargs="?", type=Path, help="Archivo .rjc o texto cifrado guardado")
    source.add_argument("--text", help="Contenido hexadecimal de un perfil .rjc")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; no sobrescribe")
    parser.add_argument("--summary", action="store_true",
                        help="Solo claves y recuento de campos, sin valores descifrados")
    args = parser.parse_args(argv)
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
