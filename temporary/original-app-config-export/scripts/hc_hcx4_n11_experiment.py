#!/usr/bin/env python3
"""TEMPORARY: HCX4/HCCFG10/n11 laboratory re-encryption; not a vendor-certified exporter.

Usage (repository root):
 python temporary/original-app-config-export/scripts/hc_hcx4_n11_experiment.py \
   --source temporary/original-app-config-export/fixtures/http_custom/source_original.hc \
   --edited temporary/original-app-config-export/fixtures/http_custom/edited_preview.json \
   --output /tmp/hc-experiment.hc
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

from Crypto.Cipher import ChaCha20_Poly1305
from decoders.Python.apps.HTTP_Custom import codec
from decoders.Python import _hc_hccfg as hc


def seal(key: bytes, aad: bytes, plaintext: bytes) -> tuple[str, str]:
    import secrets
    nonce = secrets.token_bytes(24)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(aad)
    return nonce.hex(), (cipher.encrypt(plaintext) + cipher.digest()).hex()


def carrier_depth(original: bytes) -> int:
    for depth, logical in enumerate(hc._carriers(original)):
        try:
            decoded = hc._xdec(codec.OUTER_KEY, logical[:24], codec.OUTER_AAD, logical[24:])
            if json.loads(decoded).get("a") == "HCCFG":
                return depth
        except (ValueError, UnicodeError, TypeError, AttributeError):
            continue
    raise ValueError("HCX4 outer layer did not authenticate")


def check_changes(original: dict, edited: dict) -> None:
    if not isinstance(edited, dict) or set(edited) != set(original):
        raise ValueError("Edited JSON root is incomplete or adds fields")
    for name in ("config", "other_sections", "app_version"):
        if edited[name] != original[name]:
            raise ValueError("Unexpected changes in "+name)
    for name, value in original["main"].items():
        if name not in ("g", "u") and edited["main"].get(name) != value:
            raise ValueError("Unexpected change in main."+name)
    if set(original["main"]) != set(edited["main"]):
        raise ValueError("Main keys were added or removed")
    old_g, new_g = original["main"]["g"], edited["main"]["g"]
    if set(old_g) != set(new_g):
        raise ValueError("Protection keys were added or removed")
    for name, value in old_g.items():
        if name not in ("a", "v") and new_g[name] != value:
            raise ValueError("Unexpected change in main.g."+name)
    if edited["protections"] != hc._norm_prot(new_g):
        raise ValueError("Presentation protections do not match main.g")


def rewrap(raw: bytes, edited: dict) -> bytes:
    decoded = codec.decrypt(raw)
    check_changes(decoded, edited)
    envelope = codec.open_envelope(raw)
    if (envelope.get("b"), envelope.get("c"), envelope.get("d"), envelope.get("e")) != (10, "s1", "h1", "n11"):
        raise ValueError("Only HCX4 HCCFG10 n11 supported")
    if bool(envelope.get("h", False)):
        raise ValueError("Protected files require an authorized separate workflow")
    key, aad = codec.derive(envelope, None, None)
    original_section = envelope["i"]
    label = original_section["a"]
    section_aad = aad + b"\x00" + label.encode("utf-8")
    clear = hc._xdec(key, bytes.fromhex(original_section["b"]),
                     section_aad, bytes.fromhex(original_section["c"]))
    if json.loads(clear) != decoded["main"]:
        raise ValueError("Original main differs from decoder output")
    replacement = copy.deepcopy(envelope)
    new_section = copy.deepcopy(original_section)
    new_section["b"], new_section["c"] = seal(
        key, section_aad, json.dumps(edited["main"], ensure_ascii=False,
                                    separators=(",", ":")).encode("utf-8"))
    replacement["i"] = new_section
    outer_json = json.dumps(replacement, ensure_ascii=False,
                            separators=(",", ":")).encode("utf-8")
    nonce, encrypted = seal(codec.OUTER_KEY, codec.OUTER_AAD, outer_json)
    result = bytes.fromhex(nonce+encrypted)
    for _ in range(carrier_depth(raw)):
        result = result.decode("latin-1").encode("utf-8")
    if codec.decrypt(result) != edited:
        raise AssertionError("Local decrypted JSON differs from edited JSON")
    if codec.open_envelope(result)["j"] != envelope["j"]:
        raise AssertionError("Encrypted profile sections changed unexpectedly")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--edited", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve() or args.output.exists():
        parser.error("Refusing to overwrite existing input/output")
    raw = args.source.read_bytes()
    edited = json.loads(args.edited.read_text(encoding="utf-8"))
    output = rewrap(raw, edited)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    print(json.dumps({
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "output_sha256": hashlib.sha256(output).hexdigest(),
        "output_bytes": len(output), "local_crypto_roundtrip": True,
        "original_app_import": "NOT VALIDATED; previously reported INVALID_JSON"
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
