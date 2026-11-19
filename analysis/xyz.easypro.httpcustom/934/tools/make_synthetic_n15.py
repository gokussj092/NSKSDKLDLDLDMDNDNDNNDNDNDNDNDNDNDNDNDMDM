"""Build sanitized synthetic HCCFG 12/n15 fixtures for the offline C++ decoder.

Uses ONLY synthetic data: fixed synthetic seed/nonces from a seeded RNG,
synthetic profile fields, and the synthetic password
"synthetic-n15-test-password" (defined in tests/test_hc_n15.py, never a real
credential). The reference server codec (decoders/Python/apps/HTTP_Custom/
codec.py) supplies _derive_n15 / OUTER_KEY; encryption is XChaCha20-Poly1305
via PyCryptodome, mirroring the format exactly.

Outputs (into tests/fixtures/):
  synthetic_n15_open.hc        h=0, one plain HPC1 profile (s0) + sidecar
  synthetic_n15_protected.hc   h=1 (ARGON2ID13 l=2 m=67108864, same params as
                               the real protected 934 samples), one HPR1-wrapped
                               HPC1 profile (s1) + one plain profile (s0)
  synthetic_n15_tampered.hc    copy of the open fixture with the last byte flipped
  synthetic_n15_truncated.hc   first 39 bytes of the open fixture

Run: <venv python> tools/make_synthetic_n15.py
"""
import json
import random
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
DOSSIER = HERE.parents[1]
PATCH = Path("/home/hatch/workspace/spdecode-patch")
sys.path.insert(0, str(PATCH / "decoders/Python/apps/HTTP_Custom"))
sys.path.insert(0, str(PATCH / "decoders/Python"))
import importlib.util

spec = importlib.util.spec_from_file_location(
    "hc_codec", PATCH / "decoders/Python/apps/HTTP_Custom/codec.py")
codec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(codec)
from Crypto.Cipher import ChaCha20_Poly1305  # noqa: E402

OUT = DOSSIER / "tests" / "fixtures"
RNG = random.Random(934)  # deterministic synthetic material


def _nonce():
    return bytes(RNG.randrange(256) for _ in range(24))


def _xenc(key, nonce, aad, plain):
    c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    c.update(aad)
    ct, tag = c.encrypt_and_digest(plain)
    return ct + tag


def _hpc1(name, protocol, host, port, username, password, payload, options, mode):
    def t(text):
        b = text.encode()
        return struct.pack(">I", len(b)) + b

    opts = json.dumps(options, separators=(",", ":"))
    return (b"HPC1" + struct.pack(">I", 11)
            + t(name) + t(protocol) + t(host) + struct.pack(">I", port)
            + t(username) + t(password) + t(payload) + t(opts)
            + struct.pack(">I", 0) + struct.pack(">Q", 1700000000000) + t(mode))


def _section(key, aad, label, plain, sidecar=None, sidecar_key=None):
    nonce = _nonce()
    sec = {"a": label, "b": nonce.hex(),
           "c": _xenc(key, nonce, aad + b"\x00" + label.encode(), plain).hex()}
    if sidecar is not None:
        snonce = _nonce()
        sec["d"] = {"a": snonce.hex(),
                    "b": _xenc(sidecar_key, snonce,
                               aad + b"\x00" + label.encode() + b":x",
                               sidecar).hex()}
    return sec


def build(protected, password=None):
    seed = bytes(RNG.randrange(256) for _ in range(32))
    env = {"a": "HCCFG", "b": 12, "c": "s1", "d": "h1", "e": "n15",
           "f": ["ssh", "profiles"], "g": seed.hex(), "h": 1 if protected else 0,
           "n": 934}
    if protected:
        env.update({"k": "a1", "l": 2, "m": 67108864})
    key, aad = codec._derive_n15(env, password)

    def skey(label, extra=b""):
        return codec.historical._hkdf(key, b"hc-config-part-v12",
                                     aad + b"\x00" + label.encode() + extra)

    main = json.dumps({"g": {"accessMode": 0}, "a": "synthetic"},
                      separators=(",", ":")).encode()
    env["i"] = _section(skey("m"), aad, "m", main)
    profile = _hpc1("synthetic-slowdns", "SlowDNS", "203.0.113.10", 53,
                    "synthetic-user", "synthetic-pass", "synthetic-payload",
                    {"slowdnsEnabled": True, "dnsResolver": "1.1.1.1"}, "SlowDNS")
    sections = []
    if protected:
        # HPR1-wrapped profile exercises the :r section key.
        inner_nonce = _nonce()
        inner = _xenc(skey("s1", b":r"), inner_nonce,
                      aad + b"\x00" + b"s1:r",
                      profile)
        wrapped = b"HPR1" + inner_nonce + inner
        sections.append(_section(skey("s1"), aad, "s1", wrapped))
        sections.append(_section(skey("s0"), aad, "s0", profile))
    else:
        # Plain profile with a sidecar exercises the :x section key.
        sections.append(_section(skey("s0"), aad, "s0", profile,
                                 sidecar=b"synthetic-custom-payload",
                                 sidecar_key=skey("s0", b":x")))
    env["j"] = sections
    outer_nonce = _nonce()
    sealed = _xenc(codec.OUTER_KEY, outer_nonce, codec.OUTER_AAD,
                   json.dumps(env, separators=(",", ":")).encode())
    return outer_nonce + sealed


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    open_data = build(protected=False)
    (OUT / "synthetic_n15_open.hc").write_bytes(open_data)
    prot_data = build(protected=True, password="synthetic-n15-test-password")
    (OUT / "synthetic_n15_protected.hc").write_bytes(prot_data)
    tampered = bytearray(open_data)
    tampered[-1] ^= 1
    (OUT / "synthetic_n15_tampered.hc").write_bytes(bytes(tampered))
    (OUT / "synthetic_n15_truncated.hc").write_bytes(open_data[:39])
    print(f"wrote 4 fixtures to {OUT}")


if __name__ == "__main__":
    main()
