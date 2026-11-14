#!/usr/bin/env python3
"""PUKANG VPN file decoder for SP-DECODE.

The app has no exportable profile file type of its own. After a
successful catalog download it saves the catalog (decrypted, then
re-encrypted with the same envelope) as filesDir/profile.json:

    profile.json = Base64( XXTEA( catalog JSON, key "pukangvpn270@" ) )

On startup the app reads filesDir/profile.json back with the same
envelope (ky0.a() in the app): Base64 -> XXTEA decrypt -> JSON, then
it migrates a few server field names in memory (no format change on
disk). This script decodes such a file, and can also re-encode a
catalog JSON back to the profile.json envelope (--encode).

The envelope is identical to the catalog download, so a raw catalog
blob file can be decoded here too; see PUKANG_VPN.py for the live
download. No .sks support (the app has no .sks format).

Pure Python standard library.
"""

import argparse
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from PUKANG_VPN import decode, decode_fields, xxtea_encrypt  # noqa: E402


def decode_file(path):
    """Decode a profile.json / catalog blob file to a catalog dict."""
    with open(path, "rb") as fh:
        raw = fh.read()
    text = raw.decode("utf-8", "ignore").strip()
    if text.startswith("{"):
        # already-decrypted JSON (e.g. an exported catalog)
        catalog = json.loads(text, strict=False)
        return decode_fields(catalog)
    return decode(raw)


def encode_file(catalog):
    """Encode a catalog dict to the profile.json envelope (str)."""
    if isinstance(catalog, dict):
        data = json.dumps(catalog, ensure_ascii=False).encode("utf-8")
    elif isinstance(catalog, (bytes, bytearray)):
        data = bytes(catalog)
    else:
        data = str(catalog).encode("utf-8")
    return base64.b64encode(xxtea_encrypt(data)).decode("ascii")


def self_test():
    sample = {
        "Version": "144",
        "Message": "test",
        "Servers": [
            {
                "ServerName": "Server-01",
                "ServerIP": base64.b64encode(b"nn01.pukangvpn.xyz").decode(),
            }
        ],
        "Networks": [
            {
                "PayloadName": "Global network",
                "Payload": base64.b64encode(b"GET / HTTP/1.1").decode(),
            }
        ],
    }
    encoded = encode_file(sample)
    decoded = decode(encoded)
    assert decoded["Version"] == "144", decoded
    assert decoded["Servers"][0]["ServerIP"] == "nn01.pukangvpn.xyz"
    assert decoded["Networks"][0]["Payload"] == "GET / HTTP/1.1"
    # the included live sample body decodes as a profile.json would
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "catalog_sample.b64"), "rb") as fh:
        live = decode(fh.read())
    assert live["Version"] == "144", live.get("Version")
    assert len(live["Servers"]) == 17
    return True


def run():
    ap = argparse.ArgumentParser(
        description="PUKANG VPN file decoder (profile.json, SP-DECODE)."
    )
    ap.add_argument("file", nargs="?", metavar="PATH",
                    help="profile.json / catalog blob to decode")
    ap.add_argument("--encode", metavar="JSON_PATH",
                    help="encode a decoded catalog JSON to the "
                         "profile.json envelope and print it")
    ap.add_argument("--self-test", action="store_true",
                    help="run the built-in self-test and exit")
    ap.add_argument("-o", "--output", metavar="PATH",
                    help="write the decoded catalog JSON to PATH")
    args = ap.parse_args()

    if args.self_test:
        ok = self_test()
        print("self-test: PASS" if ok else "self-test: FAIL")
        return 0 if ok else 1

    if args.encode:
        with open(args.encode, "r", encoding="utf-8") as fh:
            catalog = json.load(fh)
        print(encode_file(catalog))
        return 0

    if not args.file:
        ap.error("nothing to do: pass a file, --encode or --self-test")

    try:
        catalog = decode_file(args.file)
    except (ValueError, OSError) as exc:
        print("DECODE_FAILED: %s" % exc, file=sys.stderr)
        return 2

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(catalog, fh, ensure_ascii=False, indent=2)
    print("Version: %s" % catalog.get("Version"))
    print("Servers: %d" % len(catalog.get("Servers") or []))
    print("Networks: %d" % len(catalog.get("Networks") or []))
    return 0


if __name__ == "__main__":
    sys.exit(run())
