#!/usr/bin/env python3
"""Deterministic tests for the Sentinel Tunnel 4.0.0 stage decoders.

All fixtures are SYNTHETIC (TEST-NET addresses, fabricated .ovpn text,
round-trip .st blobs built by the decoder itself). They prove the
implemented logic, not compatibility with a real app export or the live
feed; live evidence is recorded in RESULTS.md. Run from the repo root:

  python3 analysis/online.zarray.sentineltunnel/64/tests/test_sentinel_tunnel.py
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
DOSSIER = HERE.parents[1]
APP_DIR = (DOSSIER.parents[2] / "decoders" / "Python" / "apps"
           / "Sentinel_Tunnel")


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_vpngate_fixture() -> None:
    decoder = _load("sentinel_server_catalog",
                    APP_DIR / "server_catalog_decoder.py")
    raw = (HERE.parent / "fixtures" / "vpngate-sample.csv").read_bytes()
    result = json.loads(decoder.run(raw))
    assert result["serverCount"] == 3, result["serverCount"]
    assert result["countries"] == {"JP": 1, "BY": 1, "KR": 1}, result["countries"]
    by_host = {s["hostName"]: s for s in result["servers"]}
    # Row 2 carries Ping "-" in the live feed; the parser must not crash.
    assert by_host["public-vpn-002"]["ping"] == -1
    assert by_host["public-vpn-002"]["protocol"] == "TCP"
    assert by_host["public-vpn-002"]["port"] == 443
    assert by_host["public-vpn-001"]["protocol"] == "UDP"
    assert by_host["public-vpn-001"]["port"] == 1194
    assert by_host["public-vpn-003"]["port"] == 1944
    # No download API / endpoint may leak into the result JSON.
    blob = json.dumps(result)
    assert "vpngate.net" not in blob and "api/iphone" not in blob
    assert "http://" not in blob and "https://" not in blob


def test_vpngate_negatives() -> None:
    decoder = _load("sentinel_server_catalog_neg",
                    APP_DIR / "server_catalog_decoder.py")
    for bad in (b"", b"no header here\n", b"#HostName,IP\n"):
        try:
            decoder.run(bad)
        except ValueError:
            continue
        raise AssertionError("expected ValueError for %r" % (bad[:20],))


def test_st_roundtrip_and_negatives() -> None:
    fd = _load("sentinel_file_decoder", APP_DIR / "file_decoder.py")
    assert fd.selftest() == 0
    # Truncated / tampered / foreign bytes must not decode.
    blob = fd._encode_for_selftest(
        {"configType": "CUSTOM_SSH", "name": "t"},
        {"sshHost": "203.0.113.10", "sshPort": 22}, password=None)
    assert fd.run(blob) is not None
    assert fd.run(blob[:20]) is None
    assert fd.run(b"not a sentinel file at all........") is None
    bad = bytearray(blob)
    bad[len(bad) // 2] ^= 1
    assert fd.run(bytes(bad)) is None
    # Password-protected without a password must raise PASSWORD_REQUIRED.
    locked = fd._encode_for_selftest(
        {"configType": "CUSTOM_SSH", "name": "t"},
        {"sshHost": "203.0.113.10", "sshPort": 22},
        password="test-password-123")
    try:
        fd.run(locked)
    except fd.SentinelDecodeError as exc:
        assert exc.code == "PASSWORD_REQUIRED", exc.code
    else:
        raise AssertionError("expected PASSWORD_REQUIRED")
    assert fd.run(locked, password="test-password-123") is not None
    try:
        fd.run(locked, password="wrong-password")
    except fd.SentinelDecodeError as exc:
        assert exc.code == "AUTH_FAILED", exc.code
    else:
        raise AssertionError("expected AUTH_FAILED for wrong password")


def main() -> int:
    for test in (test_vpngate_fixture, test_vpngate_negatives,
                 test_st_roundtrip_and_negatives):
        test()
        print("PASS %s" % test.__name__)
    print("ALL TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
