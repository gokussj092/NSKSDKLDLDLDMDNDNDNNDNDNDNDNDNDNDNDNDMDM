"""Generate sanitized SSC fixtures + expected mapped JSON.

All plaintexts are synthetic: RFC 2606 example.org, dummy-user and
dummy-not-a-real-secret. No real server, user or password is used.
Run from the dossier tools dir or the repo root:
    python3 analysis/dev.epro.ssc/96/tools/make_fixtures.py
Outputs tests/fixtures/*.ssc|*.txt and tests/expected/*.json.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOSSIER = HERE.parent
FIX = DOSSIER / "tests" / "fixtures"
EXP = DOSSIER / "tests" / "expected"

sys.path.insert(0, str(HERE))
from ssc_oracle import (  # noqa: E402
    L1_KEY, FIXED_NONCE, chacha20, decode_mapped, encrypt_inner_field,
    encrypt_layer1, encrypt_layer2,
)

USER_KEY = "00112233445566778899aabbccddeeff"  # 32 hex chars, synthetic

CONFIG_FULL = {
    "e": "SSC synthetic profile",
    "l": "example.org",
    "m": 443,
    "o": "dummy-user",
    "p": "dummy-not-a-real-secret",
    "g": "GET http://example.org/ HTTP/1.1[crlf]Host: example.org[crlf]",
    "j": "SSH",
    "r": "TCP",
    "v": "8.8.8.8",
    "s": "4.3.13",
    "q": 30,
    "y": True,
    "z": 1080,
}
CONFIG_MINIMAL = {"e": "SSC minimal", "l": "example.org", "m": 80}


def _dump_json(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _write(name: str, data: bytes) -> Path:
    p = FIX / name
    p.write_bytes(data)
    return p


def _expect(name: str, mapped: dict) -> None:
    (EXP / name).write_text(
        json.dumps(mapped, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")


def main() -> int:
    FIX.mkdir(parents=True, exist_ok=True)
    EXP.mkdir(parents=True, exist_ok=True)

    # 1. Single layer, two configs (full + minimal), top-level NOTE.
    plain1 = {"a": [CONFIG_FULL, CONFIG_MINIMAL], "b": "Offline test"}
    raw1 = encrypt_layer1(_dump_json(plain1))
    _write("single_layer.ssc", raw1)
    _expect("single_layer.json", decode_mapped(raw1))

    # 2. Two layers: L1 {"a": nonce16, "c": L2hex}; L2 has configs + expiry.
    plain2 = {"a": [CONFIG_FULL], "b": "Two-layer test",
              "c": "2027-01-01", "s": "4.3.13"}
    l2_hex = encrypt_layer2(_dump_json(plain2), "0123456789abcdef")
    outer2 = {"a": "0123456789abcdef", "c": l2_hex}
    raw2 = encrypt_layer1(_dump_json(outer2))
    _write("two_layer.ssc", raw2)
    _expect("two_layer.json", decode_mapped(raw2))

    # 3. Single layer with L3 inner-encrypted fields ("b" = user key).
    inner = dict(CONFIG_FULL)
    inner["b"] = USER_KEY
    for field in ("l", "o", "p", "v", "h", "w"):
        value = {"l": "example.org", "o": "dummy-user",
                 "p": "dummy-not-a-real-secret", "v": "8.8.8.8",
                 "h": "10.0.0.1", "w": "9.9.9.9"}[field]
        inner[field] = encrypt_inner_field(USER_KEY, value)
    plain3 = {"a": [inner], "b": "Inner-encrypted test"}
    raw3 = encrypt_layer1(_dump_json(plain3))
    _write("inner_encrypted.ssc", raw3)
    _expect("inner_encrypted.json", decode_mapped(raw3))

    # 4. ssc:// text link: "ssc://" + reversed hex of a single-layer file.
    raw4 = b"ssc://" + raw1[::-1]
    _write("ssc_link.txt", raw4)
    _expect("ssc_link.json", decode_mapped(raw4))

    # 5. ChaCha20 known-answer vector (L1 key + fixed nonce, counter 1):
    #    plaintext is fixed; the harness must reproduce this ciphertext.
    kat_plain = b"The quick brown fox jumps over the lazy dog. 0123456789"
    kat_cipher = chacha20(L1_KEY, FIXED_NONCE, kat_plain)
    _write("chacha20_kat.bin", kat_cipher)
    (EXP / "chacha20_kat.json").write_text(json.dumps({
        "plaintext_hex": kat_plain.hex(),
        "ciphertext_hex": kat_cipher.hex(),
        "key_hex": L1_KEY.hex(),
        "nonce_hex": FIXED_NONCE.hex(),
        "counter_start": 1,
    }, indent=2) + "\n", encoding="utf-8")

    # 6. Negatives (must all fail to decode).
    _write("truncated.ssc", raw1[:len(raw1) // 2])          # cut ciphertext
    _write("bad_hex.ssc", b"zz" * 32)                        # not hex at all
    _write("garbage.ssc", b"hello world, this is not an ssc file")
    _write("empty.ssc", b"")
    _write("odd_hex.ssc", b"abc")                            # odd hex length
    not_json = chacha20(L1_KEY, FIXED_NONCE,
                        b"this is not json at all, just bytes")
    _write("valid_l1_no_json.ssc", not_json.hex().encode("ascii"))

    for name in ("single_layer", "two_layer", "inner_encrypted", "ssc_link"):
        assert (EXP / f"{name}.json").exists(), name
    print("fixtures written to", FIX)
    print("expected written to", EXP)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
