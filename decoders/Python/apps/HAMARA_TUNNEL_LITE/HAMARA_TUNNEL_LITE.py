#!/usr/bin/env python3
"""HAMARA TUNNEL LITE (com.hamarateam.litetunnel, versionCode 20, versionName 2.9):
catalog decoder, local or explicit HTTPS.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
For .hamaratnl files, offline catalog-update files or hamaratnl:// text use
HAMARA_TUNNEL_LITE_archivos.py.

Method verified by decompiling this APK (jadx 1.5.3; LSParanoid strings
recovered from the DEX bytecode with the verified TRM port of
RandomHelper.next/seed — 1,060 call sites, 988 printable; the reference
paranoid-deobfuscator 3.0.2 refuses this APK: "more than one potential
get string method"):
  * Download: OpenVPNClient.M() builds a Volley request (C3861kY) for the
    fixed updater URL below and queues it (Eh0.r); the response listener is
    BR -> RunnableC3666ih case 2. C3861kY.e() returns no custom headers and
    the request is a GET; the transport (HurlStack/HttpURLConnection) sends
    no app headers, so the download is a plain GET. The server answers 200
    to any User-Agent (verified with Dalvik and Mozilla); this script sends
    "Dalvik/2.1.0" + "Accept-Encoding: identity", the platform-agent family
    the app's stack produces.
  * Handler (RunnableC3666ih case 2): response.replace(" ", "").replace(
    "\\n", ""), then Kn.c(response, Kn.a) = Base64 -> XXTEA (delta
    0x9E5729B1, key "...|...") -> JSON. If "Version" equals the local one:
    "No Update Available!"; otherwise local Payloads whose "message" starts
    with "Custom Tweak" are kept, remote Payloads are merged by
    "friendly_name" (case-insensitive), and the merged JSON is re-encrypted
    with H30.b = Kn.e (XXTEA + Base64) into filesDir + "/janu.json". The
    bundled asset assets/janu.json is the same format (version 322 at
    build time). Kn is the XXTEA class (AbstractC0345Kn; in classes.dex);
    Kn.a is the fixed format key "...|...", Kn.b/Kn.d the byte encrypt /
    decrypt cores, Kn.c/Kn.e the String wrappers (Base64 + XXTEA).
  * The cipher is byte-for-byte the APNA Tunnel Lite one (same delta, same
    key, same host family paperonboard.com/updater/<token>); only the token
    differs. The catalog JSON also carries an "UpdaterLink" field
    (https://amtun.xyz/updater/<token>); this app version never fetches it
    (no reference in the DEX), so it is reported but not followed.
  * The format has no MAC; structural validation is not cryptographic
    authentication.

The server (LiteSpeed) often closes the connection mid-body
("transfer closed with N bytes remaining", cuts at 16 KiB multiples, same
behaviour as APNA Tunnel Lite). This script first tries the plain GET the
app makes (3 attempts) and, only if it does not complete, resumes by
ranges ("Range: bytes=...") with the same headers, validating the result
by Content-Length and by successful decryption. That fallback is a
transport workaround, not part of the app's request.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from http.client import IncompleteRead
import io
import json
import os
from pathlib import Path
import re
import struct
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
MAX_INPUT = 32 * 1024 * 1024
MAX_BUNDLE = 256 * 1024 * 1024
MASK = 0xFFFFFFFF
DELTA = 0x9E5729B1  # Modified XXTEA delta (AbstractC0345Kn.b: -1638454863).
# Shared format constant in AbstractC0345Kn.a, not an account credential.
CATALOG_KEY = b"...|..."
CATALOG_URL = "https://paperonboard.com/updater/d146deb8a1d4f91cc0a7bbdac230da"
USER_AGENT = "Dalvik/2.1.0"  # Platform-agent family of the app's HTTP stack.
ROOT_KEYS = ("Free_servers", "Premium_servers", "Vip_servers", "Private_servers", "Payloads")
BUNDLED_ASSET = "assets/janu.json"


class DecodeError(ValueError):
    def __init__(self, code: str = "ERROR", message: str = ""):
        # One-arg form: DecodeError("message") -> code "ERROR".
        if not message:
            message, code = code, "ERROR"
        super().__init__(message)
        self.code = code


class CatalogError(DecodeError):
    pass


def _words(raw: bytes) -> list[int]:
    if not raw:
        return []
    padded = raw.ljust((len(raw) + 3) // 4 * 4, b"\0")
    return list(struct.unpack("<" + "I" * (len(padded) // 4), padded))


def _mx(total: int, y: int, z: int, index: int, e: int, key: list[int]) -> int:
    return (
        (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
        ^ ((total ^ y) + (key[(index & 3) ^ e] ^ z))
    ) & MASK


def decrypt_binary(ciphertext: bytes) -> bytes:
    """Decrypt HAMARA's little-endian XXTEA envelope with last-word length."""
    if len(ciphertext) < 8 or len(ciphertext) % 4 or len(ciphertext) > MAX_INPUT:
        raise CatalogError("Invalid XXTEA length")
    values = _words(ciphertext)
    key = _words(CATALOG_KEY.ljust(16, b"\0"))
    if len(key) != 4 or len(values) < 2:
        raise CatalogError("Invalid XXTEA key/input")
    end = len(values) - 1
    total = ((6 + 52 // len(values)) * DELTA) & MASK
    y = values[0]
    while total:
        e = (total >> 2) & 3
        for index in range(end, 0, -1):
            z = values[index - 1]
            values[index] = (values[index] - _mx(total, y, z, index, e, key)) & MASK
            y = values[index]
        z = values[end]
        values[0] = (values[0] - _mx(total, y, z, 0, e, key)) & MASK
        y = values[0]
        total = (total - DELTA) & MASK
    output_size = (len(values) - 1) * 4
    plain_size = values[-1]
    if not output_size - 3 <= plain_size <= output_size:
        raise CatalogError("Invalid plaintext length or format variant")
    return struct.pack("<" + "I" * len(values), *values)[:plain_size]


def _parse(plaintext: bytes) -> dict:
    try:
        parsed = json.loads(plaintext.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise CatalogError("Plaintext is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise CatalogError("Unexpected catalog schema")
    if not isinstance(parsed.get("Version"), str) or not parsed["Version"]:
        raise CatalogError("Unexpected catalog schema: missing Version")
    for section in ROOT_KEYS:
        if not isinstance(parsed.get(section), list):
            raise CatalogError(f"Unexpected catalog schema: {section} is not a list")
        if any(not isinstance(item, dict) for item in parsed[section]):
            raise CatalogError(f"Unexpected catalog records in {section}")
    return parsed


def decode(data: bytes | str) -> dict:
    """Decode an encrypted catalog body (Base64 text) into the JSON document."""
    if isinstance(data, str):
        raw = data.encode("utf-8", "surrogatepass")
    elif isinstance(data, bytes):
        raw = data
    else:
        raise CatalogError("Invalid input type")
    if not raw or len(raw) > MAX_INPUT:
        raise CatalogError("Invalid input size")
    try:
        normalized = re.sub(rb"\s+", b"", raw)
        if not normalized or len(normalized) > MAX_INPUT:
            raise CatalogError("Invalid Base64 input length")
        ciphertext = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CatalogError("Invalid Base64 catalog") from exc
    return _parse(decrypt_binary(ciphertext))


def decode_json_bytes(data: bytes) -> bytes:
    """Return the complete, original UTF-8 JSON bytes without field filtering."""
    doc = decode(data)
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def run(data: bytes) -> str:
    """Catalog worker contract; output is complete unmodified JSON."""
    return decode_json_bytes(data).decode("utf-8")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CatalogError("Fixed source attempted a redirect")


def _plain_get(url: str, timeout: int = 25) -> bytes:
    """One plain GET exactly as the app makes it (no Range, no extra headers).

    Returns the body only when its length matches Content-Length (when the
    server sends one); raises CatalogError / IncompleteRead otherwise.
    """
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"})
    with build_opener(_NoRedirect()).open(request, timeout=timeout) as response:
        if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
            raise CatalogError("Invalid remote response")
        declared = response.headers.get("Content-Length")
        data = response.read(MAX_INPUT + 1)
    if not data or len(data) > MAX_INPUT:
        raise CatalogError("Remote response exceeds limits")
    if declared is not None and len(data) != int(declared):
        raise CatalogError("Truncated remote response")
    return data


def _ranged_get(url: str, timeout: int = 25) -> bytes:
    """Transport fallback: resume a dropped transfer with Range requests.

    The app itself never sends Range; this is only used here when a plain GET
    cannot complete (the updater host drops connections mid-body from some
    networks). Each resumed piece still carries the same User-Agent and
    Accept-Encoding: identity headers, and the assembled bytes are validated
    by length and by the XXTEA/JSON decode afterwards.
    """
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"})
    with build_opener(_NoRedirect()).open(request, timeout=timeout) as response:
        total = int(response.headers["Content-Length"])
        response.read(0)
    if not total or total > MAX_INPUT:
        raise CatalogError("Invalid remote response length")
    out = bytearray()
    chunk = 16 * 1024
    for start in range(0, total, chunk):
        end = min(start + chunk - 1, total - 1)
        cursor = start
        attempts = 0
        while cursor <= end:
            attempts += 1
            if attempts > 30:
                raise CatalogError("Ranged resume failed")
            ranged = Request(url, headers={
                "User-Agent": USER_AGENT,
                "Accept-Encoding": "identity",
                "Range": f"bytes={cursor}-{end}",
            })
            try:
                with build_opener(_NoRedirect()).open(ranged, timeout=timeout) as response:
                    if response.status != 206:
                        raise CatalogError("Range request rejected")
                    body = response.read()
                out += body
                cursor += len(body)
            except IncompleteRead as exc:
                out += exc.partial
                cursor += len(exc.partial)
            except OSError:
                time.sleep(1)
            if cursor <= end:
                time.sleep(0.3)
    if len(out) != total:
        raise CatalogError("Truncated remote response")
    return bytes(out)


def download(url: str = CATALOG_URL) -> bytes:
    """Download the fixed official catalog, replicating the app's GET first."""
    last_error: Exception | None = None
    for _ in range(3):
        try:
            return _plain_get(url)
        except (CatalogError, OSError) as exc:
            last_error = exc
            time.sleep(1)
    try:
        return _ranged_get(url)
    except (CatalogError, OSError) as exc:
        raise CatalogError("Unable to download official HAMARA TUNNEL LITE catalog") from (exc or last_error)


def _member(archive: zipfile.ZipFile, name: str, limit: int) -> bytes:
    files = [item for item in archive.infolist() if item.filename == name]
    if len(files) != 1 or files[0].file_size > limit:
        raise CatalogError("Missing/duplicate/oversized APK member")
    with archive.open(files[0]) as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise CatalogError("APK member size exceeds limit")
    return data


def from_apks(path: Path) -> bytes:
    """Read only exact assets/janu.json from the base APK, never execute APK contents.

    Accepts a lone .apk, a .apks bundle (base.apk member) or an .xapk
    (APKPure bundle: the base APK is the non-config *.apk member).
    """
    try:
        if path.stat().st_size > MAX_BUNDLE:
            raise CatalogError("Bundle size exceeds limit")
        with zipfile.ZipFile(path) as outer:
            if path.suffix.lower() == ".apk":
                return _member(outer, "assets/janu.json", MAX_INPUT)
            names = outer.namelist()
            if "base.apk" in names:
                base_apk = _member(outer, "base.apk", MAX_BUNDLE)
            else:
                candidates = [n for n in names
                              if n.endswith(".apk") and "/config." not in n
                              and not n.startswith("config.")]
                if len(candidates) != 1:
                    raise CatalogError("Invalid APK/APKS: base APK not identified")
                base_apk = _member(outer, candidates[0], MAX_BUNDLE)
        with zipfile.ZipFile(io.BytesIO(base_apk)) as inner:
            return _member(inner, "assets/janu.json", MAX_INPUT)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise CatalogError("Invalid APK/APKS") from exc


def summary(plaintext: bytes) -> dict:
    """Counts only: avoid leaking stored users, passwords or payloads."""
    document = json.loads(plaintext)
    return {
        "provider": "hamara-tunnel-lite",
        "complete": True,
        "version": document.get("Version") if isinstance(document.get("Version"), str) else None,
        "sections": list(document),
        "serverCounts": {
            group: len(document[group])
            for group in ("Free_servers", "Premium_servers", "Vip_servers", "Private_servers")
            if isinstance(document.get(group), list)
        },
        "payloadCount": len(document["Payloads"]),
        "plaintextBytes": len(plaintext),
    }


def _self_test() -> int:
    """Decrypt the bundled asset and re-encrypt round-trip checks."""
    here = Path(__file__).resolve().parent
    asset = here / "janu.json"
    if not asset.is_file():
        print("SELF-TEST FAIL: bundled janu.json missing")
        return 1
    doc = decode(asset.read_bytes())
    if doc.get("Version") != "322":
        print(f"SELF-TEST FAIL: bundled Version is {doc.get('Version')!r}, expected '322'")
        return 1
    free = len(doc["Free_servers"])
    payloads = len(doc["Payloads"])
    if free != 23 or payloads != 504:
        print(f"SELF-TEST FAIL: bundled counts Free={free} Payloads={payloads}, expected 23/504")
        return 1
    # XXTEA round-trip on a synthetic document (encrypt core mirrors Kn.d).
    import struct as _s
    plain = json.dumps({"Version": "1", "Free_servers": [], "Premium_servers": [],
                        "Vip_servers": [], "Private_servers": [], "Payloads": []}).encode()
    padded = plain + b"\0" * ((4 - len(plain) % 4) % 4)
    values = list(_s.unpack("<" + "I" * (len(padded) // 4), padded)) + [len(plain)]
    key = _words(CATALOG_KEY.ljust(16, b"\0"))
    total = 0
    n = len(values)
    rounds = 6 + 52 // n
    z = values[n - 1]
    for _ in range(rounds):
        total = (total + DELTA) & MASK
        e = (total >> 2) & 3
        for p in range(n - 1):
            y = values[p + 1]
            values[p] = (values[p] + _mx(total, y, z, p, e, key)) & MASK
            z = values[p]
        y = values[0]
        values[n - 1] = (values[n - 1] + _mx(total, y, z, n - 1, e, key)) & MASK
        z = values[n - 1]
    cipher = _s.pack("<" + "I" * n, *values)
    back = decrypt_binary(cipher)
    if back != plain:
        print("SELF-TEST FAIL: XXTEA encrypt/decrypt round-trip mismatch")
        return 1
    print(f"SELF-TEST OK: bundled janu.json Version 322, {free} free servers, "
          f"{payloads} payloads; XXTEA round-trip OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=CATALOG_URL,
                        help="Fixed official catalog URL (default: the Lite updater URL)")
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--apks", type=Path, help="Read embedded janu.json from APK/APKS")
    src.add_argument("--input", type=Path, help="Read encrypted janu.json")
    src.add_argument("--stdin", action="store_true", help="Read encrypted Base64 on stdin")
    parser.add_argument("--summary", action="store_true", help="Print metadata without credentials")
    parser.add_argument("--output", type=Path, help="Write output in a private 0600 file")
    parser.add_argument("--self-test", action="store_true", help="Verify bundled asset + XXTEA round-trip")
    args = parser.parse_args()

    if args.self_test:
        return _self_test()

    try:
        if args.apks is not None:
            raw = from_apks(args.apks)
        elif args.input is not None:
            raw = args.input.read_bytes()
        elif args.stdin:
            raw = sys.stdin.buffer.read()
        else:
            raw = download(args.url)
        plaintext = decode_json_bytes(raw)
    except (CatalogError, OSError, HTTPError, URLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.summary:
        print(json.dumps(summary(plaintext), ensure_ascii=False, indent=2))
        return 0
    if args.output is not None:
        args.output.write_bytes(plaintext)
        try:
            os.chmod(args.output, 0o600)
        except OSError:
            pass
        print(f"Wrote {len(plaintext)} bytes to {args.output}")
        return 0
    sys.stdout.write(plaintext.decode("utf-8"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
