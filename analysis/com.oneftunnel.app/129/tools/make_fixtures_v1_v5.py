#!/usr/bin/env python3
"""Generate synthetic 1FTunnel CFG1 v1-v5 + lockMode 2 fixtures (0.7.3 dossier).

Regression set for the codec.py fix (CFG1 v6 added WITHOUT removing v1-v5):
Pedro's explicit requirement is that the fix ADDS v6 support; every earlier
payload version must keep opening. These fixtures prove it through the exact
server worker path (file_decoder.py -> codec.py).

Shape: same envelope as the v6 fixture (1FT1 v3, lockMode 2 / password,
fixed salt/nonce, dummy example.org values, password "test-only" — a test
vector, not a real credential). Only the CFG1 payload version and the
sections it gates differ:

  v1: SSH + DIRECT, no mask field, no dns/xray/slowDns.
  v2: SSH + PROXY + DNS, mask present.
  v3: SSH + PROXY_SNI + Xray (allowInsecure/alpn, v>=3 fields).
  v4: VLESS + Xray (flow/fingerprint/realityPublicKey/shortId/spiderX,
      v>=4 fields), no SSH section (configType VLESS).
  v5: SSH + SSH_PAYLOAD + DNS + Xray (mode, v>=5 field).

Seals with the repo decoder's own derive_key (1FTunnel.py), so a fixture
only passes if the decoder's KDF/ROOT_KEY/labels are correct. The CFG1
bytes are built by hand, in the parser's exact read order, so the fixtures
also pin the version gates of codec.py::parse_config.
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


def _xray(ft, version: int, spec: dict) -> bytes:
    out = bytearray()
    out += _choice(ft.TYPES[1:], spec["protocol"])
    out += _s(spec["host"]) + _n("i", spec["port"])
    out += _s(spec.get("uuid")) + _s(spec.get("password"))
    out += _choice(("TLS", "NONE", "REALITY"), spec["security"])
    out += _choice(("WS", "GRPC", "RAW", "XHTTP", "HTTPUPGRADE"),
                   spec["network"])
    for key in ("path", "serviceName", "sni", "hostHeader", "wildcardHost"):
        out += _s(spec.get(key))
    if version >= 3:
        out += _b(spec.get("allowInsecure", False))
        out += _s(spec.get("alpn"))
    if version >= 4:
        for key in ("flow", "fingerprint", "realityPublicKey", "shortId",
                    "spiderX"):
            out += _s(spec.get(key))
    if version >= 5:
        out += _s(spec.get("mode"))
    return bytes(out)


def build_cfg1(ft, version: int, spec: dict) -> bytes:
    out = bytearray()
    out += b"CFG1"
    out += _n("B", version)
    out += _s(spec["id"]) + _s(spec["name"]) + _n("q", CREATED_AT)
    out += _s(None)  # message
    if version >= 2:
        out += _n("i", spec.get("fieldLockMask", 0))
    if spec.get("ssh"):
        out += _b(True)
        ssh = spec["ssh"]
        out += _s(ssh["host"]) + _n("i", ssh["port"])
        out += _s(ssh["username"]) + _s(ssh["password"])
    else:
        out += _b(False)
    if spec.get("inject"):
        out += _b(True)
        inj = spec["inject"]
        out += _choice(ft.INJECT_MODES, inj["mode"])
        out += _s(inj.get("payload")) + _s(inj.get("proxyHost"))
        out += _n("i", inj.get("proxyPort", -1))
        out += _s(inj.get("sni")) + _s(inj.get("wildcardHost"))
    else:
        out += _b(False)
    if spec.get("dns"):
        out += _b(True)
        out += _s(spec["dns"][0]) + _s(spec["dns"][1])
    else:
        out += _b(False)
    if spec.get("xray"):
        out += _b(True)
        out += _xray(ft, version, spec["xray"])
    else:
        out += _b(False)
    # No slowDns section below v6.
    return bytes(out)


def build_aad(ft, spec: dict) -> bytes:
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
    out += _choice(ft.TYPES, spec["configType"])
    out += _n("B", 2)  # lockMode 2 = password
    out += _b(True)  # blockRoot
    return bytes(out)


SPECS = {
    1: {"configType": "SSH", "id": "test-id-073-v1", "name": "Fixture v1",
        "ssh": {"host": "ssh.ejemplo.test", "port": 22,
                "username": "usuario-prueba", "password": "clave-prueba"},
        "inject": {"mode": "DIRECT"}},
    2: {"configType": "SSH", "id": "test-id-073-v2", "name": "Fixture v2",
        "ssh": {"host": "ssh.ejemplo.test", "port": 22,
                "username": "usuario-prueba", "password": "clave-prueba"},
        "inject": {"mode": "PROXY", "proxyHost": "proxy.ejemplo.test",
                   "proxyPort": 8080},
        "dns": ("8.8.8.8", "8.8.4.4")},
    3: {"configType": "SSH", "id": "test-id-073-v3", "name": "Fixture v3",
        "ssh": {"host": "ssh.ejemplo.test", "port": 22,
                "username": "usuario-prueba", "password": "clave-prueba"},
        "inject": {"mode": "PROXY_SNI", "sni": "sni.ejemplo.test"},
        "xray": {"protocol": "VLESS", "host": "xray.ejemplo.test",
                 "port": 443, "uuid": "uuid-prueba-v3", "security": "TLS",
                 "network": "WS", "path": "/ws",
                 "allowInsecure": True, "alpn": "h2"}},
    4: {"configType": "VLESS", "id": "test-id-073-v4", "name": "Fixture v4",
        "xray": {"protocol": "VLESS", "host": "xray.ejemplo.test",
                 "port": 443, "uuid": "uuid-prueba-v4",
                 "password": "clave-xray", "security": "REALITY",
                 "network": "RAW", "sni": "sni.ejemplo.test",
                 "allowInsecure": False, "flow": "xtls-rprx-vision",
                 "fingerprint": "chrome",
                 "realityPublicKey": "reality-pub-prueba",
                 "shortId": "abc123", "spiderX": "spider-prueba"}},
    5: {"configType": "SSH", "id": "test-id-073-v5", "name": "Fixture v5",
        "ssh": {"host": "ssh.ejemplo.test", "port": 22,
                "username": "usuario-prueba", "password": "clave-prueba"},
        "inject": {"mode": "SSH_PAYLOAD", "payload": "payload-prueba-v5"},
        "dns": ("1.1.1.1", "1.0.0.1"),
        "xray": {"protocol": "VLESS", "host": "xray.ejemplo.test",
                 "port": 443, "uuid": "uuid-prueba-v5", "security": "TLS",
                 "network": "WS", "mode": "test-mode-v5"}},
}


def main() -> int:
    ft = _load_decoder()
    FIXTURES.mkdir(parents=True, exist_ok=True)
    for version in (1, 2, 3, 4, 5):
        spec = SPECS[version]
        aad = build_aad(ft, spec)
        plaintext = build_cfg1(ft, version, spec)
        key = ft.derive_key(3, SALT, aad, PASSWORD)
        cipher = AES.new(key, AES.MODE_GCM, nonce=NONCE, mac_len=16)
        cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        envelope = b"".join([
            b"1FT1", _n("B", 3), _n("B", 1), _n("B", 1), _n("B", 0),
            SALT, NONCE, _n("I", len(aad)), _n("I", len(ciphertext) + 16),
            aad, ciphertext, tag,
        ])
        text = "1FTnl." + base64.urlsafe_b64encode(
            envelope[4:]).rstrip(b"=").decode()
        fixture = FIXTURES / f"v{version}_password.1ftnl"
        fixture.write_text(text + "\n", encoding="utf-8")
        expected = {
            "format": "1FT1",
            "password": PASSWORD,
            "envelopeVersion": 3,
            "keySlot": 1,
            "minimumAppBuild": 129,
            "lockMode": 2,
            "configType": spec["configType"],
            "payloadVersion": version,
            "sections": {"ssh": bool(spec.get("ssh")),
                         "inject": bool(spec.get("inject")),
                         "dns": bool(spec.get("dns")),
                         "xray": bool(spec.get("xray")),
                         "slowDns": False},
            "injectMode": (spec.get("inject") or {}).get("mode"),
            "authenticated": True,
            "isPartial": False,
        }
        (FIXTURES / f"v{version}_password.expected.json").write_text(
            json.dumps(expected, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")
        print("wrote", fixture)
        # Round-trip check through BOTH decoders: the reference (1FTunnel.py)
        # and the worker codec (codec.py) must agree on every version.
        import sys as _sys
        _sys.path.insert(0, str(DECODER.parent))
        import codec as worker_codec
        r1 = ft.decode(text, password=PASSWORD)
        r2 = worker_codec.decode(text, password=PASSWORD)
        assert r1["config"]["payloadVersion"] == version
        assert r2["config"]["payloadVersion"] == version
        assert r1["metadata"]["authenticated"] is True
        assert r2["metadata"]["authenticated"] is True
        # The worker codec (codec.py) only emits "slowDns" for v6, to keep
        # the v1-v5 JSON contract byte-identical; the reference decoder
        # always emits it (None below v6). Compare everything else exactly.
        assert {k: v for k, v in r1["config"].items() if k != "slowDns"} == \
            {k: v for k, v in r2["config"].items() if k != "slowDns"}, \
            "codec/1FTunnel config mismatch"
        assert r1["config"]["slowDns"] is None
        assert "slowDns" not in r2["config"]
        print(f"round-trip OK v{version} via 1FTunnel.decode + codec.decode")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
