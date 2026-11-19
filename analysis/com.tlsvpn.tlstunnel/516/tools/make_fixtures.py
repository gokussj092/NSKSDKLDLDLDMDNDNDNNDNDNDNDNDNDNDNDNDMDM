"""Generate the sanitized synthetic .tls fixtures for this dossier.

Seals fake plaintexts with the six known AES-256-GCM configuration-key
profiles using the exact container layout of decoders/Python/TLS.py
(Ldd.o([B)[B): reversed outer Base64, 12-byte head, C1 + IV1(18) + C2 +
IV2(18) + 84-byte tail, each fragment reversed, nonce = IV1+IV2 (36 B),
tag = last 16 bytes of C1+C2. All values are invented (example.org,
test users); no real credential, server or account appears here.

Usage:
  <venv python> tools/make_fixtures.py [--out DIR]
Default out: analysis/com.tlsvpn.tlstunnel/516/tests/fixtures
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path

from Crypto.Cipher import AES

import importlib.util

REPO_ROOT = Path(__file__).resolve().parents[4]
TLS_PY = REPO_ROOT / "decoders" / "Python" / "TLS.py"
spec = importlib.util.spec_from_file_location("tls_decoder", TLS_PY)
tls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tls)

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures"


def b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode()


def export_fixture(key: bytes, plaintext: bytes, suffix: str = ":::::") -> str:
    # Same layout as tests/test_tls_decoder.py::export_fixture.
    nonce = bytes(range(36))
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    ct += tag
    half = len(ct) // 2
    raw = bytes(12) + ct[:half][::-1] + nonce[:18][::-1]
    raw += ct[half:][::-1] + nonce[18:][::-1] + bytes(84)
    return base64.b64encode(raw).decode().rstrip("=")[::-1] + suffix


def modern_parts(variant: int) -> list:
    """28-field modern (8.5.0) plaintext; indices 20-23 are booleans."""
    parts = [""] * 28
    parts[0:4] = ["516", "4", "443", "true"]
    parts[4] = b64("usuario-prueba")
    parts[5] = b64("clave-prueba")
    parts[6] = b64("ejemplo.test")
    parts[7] = b64("443")
    parts[9] = b64("22")
    parts[10] = "1"
    parts[11] = "false"
    parts[12] = b64("GET / HTTP/1.1\r\nHost: ejemplo.test\r\n\r\n")
    parts[13] = "false"
    parts[14] = b64("sni.ejemplo.test")
    parts[15] = "false"
    parts[16] = b64("payload-at-ejemplo")
    parts[17] = "false"
    parts[18] = b64("proxy.ejemplo.test")
    parts[19] = b64("8080")
    parts[20:24] = ["true", "false", "false", "false"]
    parts[24] = b64("clave-publica-prueba")
    parts[25] = "false"
    parts[27] = b64(f"mensaje de prueba variante {variant}")
    return parts


def legacy_parts() -> list:
    """Historic (profile 6) plaintext; indices 20-23 are the old DNS fields."""
    parts = [""] * 28
    parts[0:4] = ["300", "1", "443", "true"]
    parts[4] = b64("usuario-antiguo")
    parts[5] = b64("clave-antigua")
    parts[6] = b64("antiguo.ejemplo.test")
    parts[7] = b64("443")
    parts[9] = b64("22")
    parts[10] = "2"
    parts[11] = "true"
    parts[12] = b64("payload-antiguo")
    parts[13] = "true"
    parts[14] = b64("sni.antiguo.test")
    parts[15] = "false"
    parts[16] = b64("")
    parts[17] = "false"
    parts[18] = b64("proxy.antiguo.test")
    parts[19] = b64("3128")
    parts[20] = "2"
    parts[21] = b64("dns.ejemplo.test")
    parts[22] = b64("53")
    parts[23] = b64("8.8.8.8")
    parts[24] = b64("clave-publica-antigua")
    parts[25] = "true"
    parts[27] = b64("mensaje antiguo")
    return parts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(FIXTURES))
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    manifest = {}

    # One fixture per key profile (1-5 modern, 6 legacy). Profile 2 uses
    # an odd-length plaintext to exercise the unequal C1/C2 split.
    for index, key in enumerate(tls.CONFIG_KEYS):
        profile = index + 1
        if profile == 6:
            parts = legacy_parts()
            name = "tls-profile6-legacy.tls"
        else:
            parts = modern_parts(profile)
            if profile == 2:
                parts[27] = b64("mensaje impar!")  # odd total length
            name = f"tls-profile{profile}.tls"
        token = export_fixture(key, ":".join(parts).encode("utf-8"))
        (out / name).write_text(token, encoding="utf-8")
        manifest[name] = {
            "profile": profile,
            "sha256": hashlib.sha256(token.encode()).hexdigest(),
            "plaintext_fields": len(parts),
        }

    # tls:// text link (profile 1), no trailing ":::::" suffix.
    token1 = export_fixture(tls.CONFIG_KEYS[0],
                            ":".join(modern_parts(1)).encode("utf-8"),
                            suffix="")
    (out / "tls-link.txt").write_text("tls://" + token1, encoding="utf-8")
    manifest["tls-link.txt"] = {
        "profile": 1,
        "sha256": hashlib.sha256(("tls://" + token1).encode()).hexdigest(),
    }

    # Short plaintext (only 5 fields): oracle fills the rest with defaults.
    short = ":".join(["516", "4", "443", "false", b64("solo-usuario")])
    token_short = export_fixture(tls.CONFIG_KEYS[0], short.encode("utf-8"))
    (out / "tls-short.tls").write_text(token_short, encoding="utf-8")
    manifest["tls-short.tls"] = {
        "profile": 1,
        "sha256": hashlib.sha256(token_short.encode()).hexdigest(),
        "plaintext_fields": 5,
    }

    # Invalid inner Base64 in a B64 field: oracle preserves it as-is.
    parts = modern_parts(3)
    parts[4] = "!!!no-es-base64!!!"
    token_bad = export_fixture(tls.CONFIG_KEYS[2], ":".join(parts).encode("utf-8"))
    (out / "tls-profile3-bad-inner-b64.tls").write_text(token_bad, encoding="utf-8")
    manifest["tls-profile3-bad-inner-b64.tls"] = {
        "profile": 3,
        "sha256": hashlib.sha256(token_bad.encode()).hexdigest(),
    }

    # Negative fixtures (never open).
    good = (out / "tls-profile1.tls").read_text(encoding="utf-8")
    raw = bytearray(base64.b64decode(good.rstrip(":")[::-1] + "=" * (-len(good.rstrip(":")) % 4)))
    raw[20] ^= 0x01  # flip one ciphertext byte -> GCM tag must fail
    tampered = base64.b64encode(bytes(raw)).decode().rstrip("=")[::-1] + ":::::"
    (out / "tls-tampered.tls").write_text(tampered, encoding="utf-8")
    manifest["tls-tampered.tls"] = {
        "negative": "tampered ciphertext, expect TLS_AUTH_FAILED",
        "sha256": hashlib.sha256(tampered.encode()).hexdigest(),
    }
    (out / "tls-truncated.tls").write_text(good[:40], encoding="utf-8")
    manifest["tls-truncated.tls"] = {
        "negative": "truncated container, expect TLS_CONTAINER_TOO_SHORT",
        "sha256": hashlib.sha256(good[:40].encode()).hexdigest(),
    }
    (out / "tls-garbage.tls").write_text("esto no es base64 ni un .tls válido ###", encoding="utf-8")
    manifest["tls-garbage.tls"] = {
        "negative": "not base64, expect TLS_INVALID_BASE64",
        "sha256": hashlib.sha256(
            "esto no es base64 ni un .tls válido ###".encode("utf-8")).hexdigest(),
    }
    (out / "tls-empty.tls").write_text("", encoding="utf-8")
    manifest["tls-empty.tls"] = {
        "negative": "empty input, expect TLS_EMPTY_INPUT",
        "sha256": hashlib.sha256(b"").hexdigest(),
    }

    (out / "fixtures.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8")
    for name in sorted(manifest):
        print(f"{name}  {manifest[name].get('profile', manifest[name].get('negative', ''))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
