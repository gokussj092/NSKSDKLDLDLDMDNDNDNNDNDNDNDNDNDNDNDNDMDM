#!/usr/bin/env python3
"""Generate a synthetic 1FTunnel CFG1 v6 + lockMode 2 fixture (0.7.3 dossier).

Shape: the same as Pedro's real 0.7.3 export (1FT1 v3 envelope, CFG1 v6,
SlowDNS inject, lockMode 2 / password) but with fixed salt/nonce and dummy
example.org values. The password is the synthetic string "test-only" and is
recorded in the expected JSON on purpose: it is a test vector, not a real
credential. NEVER point this script at a real user file.

Seals with the repo decoder's own derive_key (1FTunnel.py), so the fixture
only passes if the decoder's KDF/ROOT_KEY/labels are correct.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import struct
import sys
from pathlib import Path

from Crypto.Cipher import AES

REPO = Path(__file__).resolve().parents[4]
DECODER = REPO / "decoders" / "Python" / "apps" / "OneFTunnel" / "1FTunnel.py"
HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / "tests" / "fixtures"

PASSWORD = "test-only"
SALT = bytes(range(16))
NONCE = bytes(range(12))
CREATED_AT = 1792000000000
EXPIRED_AT = 1794600000000


def _load_decoder():
    spec = importlib.util.spec_from_file_location("ftunnel_decoder", DECODER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _s(value: str | None, *, short: bool = False) -> bytes:
    if value is None:
        return struct.pack(">i", -1)
    raw = value.encode("utf-8")
    return struct.pack(">H" if short else ">i", len(raw)) + raw


def _n(fmt: str, value: int) -> bytes:
    return struct.pack(">" + fmt, value)


def _b(value: bool) -> bytes:
    return struct.pack(">B", 1 if value else 0)


def _choice(names, value: str) -> bytes:
    return struct.pack(">B", names.index(value))


def build_cfg1() -> bytes:
    ft = _load_decoder()
    out = bytearray()
    out += b"CFG1"
    out += _n("B", 6)
    out += _s("test-id-073-0001")
    out += _s("Fixture v6 SlowDNS")
    out += _n("q", CREATED_AT)
    out += _s(None)  # message
    out += _n("i", 0)  # fieldLockMask
    out += _b(True)  # hasSSH
    out += _s("ssh.ejemplo.test") + _n("i", 22)
    out += _s("usuario-prueba") + _s("clave-prueba")
    out += _b(True)  # hasInject
    out += _choice(ft.INJECT_MODES, "SLOWDNS")
    out += _s(None) + _s(None) + _n("i", -1) + _s(None) + _s(None)
    out += _b(False)  # hasDNS
    out += _b(False)  # hasXray
    out += _b(True)  # hasSlowDns (v6)
    out += _s("ns.ejemplo.test") + _s("ejemplo.test")
    out += _s("clave-publica-prueba")
    out += _choice(ft.SLOWDNS_RECORD_TYPES, "A")
    return bytes(out)


def build_aad(ft) -> bytes:
    # d5d66658...: first fingerprint in the repo decoder (also the one in the
    # self-test vectors and in Pedro's real 0.7.3 export).
    cert = next(s for s in ft.SIGNATURES if s.startswith("d5d66658"))
    out = bytearray()
    out += _n("B", 3)
    out += _s(ft.PACKAGE, short=True)
    out += _s(cert, short=True)
    out += _n("I", 1)  # configVersion
    out += _n("I", 1)  # keySlot
    out += _n("q", 129)  # minimumAppBuild (0.7.3)
    out += _n("q", CREATED_AT)
    out += _n("q", EXPIRED_AT)
    out += _choice(ft.TYPES, "SSH")
    out += _n("B", 2)  # lockMode 2 = password
    out += _b(True)  # blockRoot
    return bytes(out)


def main() -> int:
    ft = _load_decoder()
    aad = build_aad(ft)
    plaintext = build_cfg1()
    key = ft.derive_key(3, SALT, aad, PASSWORD)
    cipher = AES.new(key, AES.MODE_GCM, nonce=NONCE, mac_len=16)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    envelope = b"".join([
        b"1FT1", _n("B", 3), _n("B", 1), _n("B", 1), _n("B", 0),
        SALT, NONCE, _n("I", len(aad)), _n("I", len(ciphertext) + 16),
        aad, ciphertext, tag,
    ])
    text = "1FTnl." + base64.urlsafe_b64encode(envelope[4:]).rstrip(b"=").decode()
    FIXTURES.mkdir(parents=True, exist_ok=True)
    fixture = FIXTURES / "v6_password.1ftnl"
    fixture.write_text(text + "\n", encoding="utf-8")
    expected = {
        "format": "1FT1",
        "password": PASSWORD,
        "envelopeVersion": 3,
        "keySlot": 1,
        "minimumAppBuild": 129,
        "lockMode": 2,
        "configType": "SSH",
        "payloadVersion": 6,
        "sections": {"ssh": True, "inject": True, "dns": False,
                     "xray": False, "slowDns": True},
        "injectMode": "SLOWDNS",
        "slowDnsRecordType": "A",
        "authenticated": True,
        "isPartial": False,
    }
    (FIXTURES / "v6_password.expected.json").write_text(
        json.dumps(expected, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8")
    print("wrote", fixture)
    print("wrote", FIXTURES / "v6_password.expected.json")
    # Round-trip check through the repo decoder (both entry points).
    result = ft.decode(text, password=PASSWORD)
    assert result["config"]["payloadVersion"] == 6
    assert result["metadata"]["authenticated"] is True
    assert result["config"]["slowDns"]["recordType"] == "A"
    print("round-trip OK via 1FTunnel.decode")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
