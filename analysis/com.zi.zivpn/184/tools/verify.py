#!/usr/bin/env python3
"""Verify the ZIVPN offline dossier (com.zi.zivpn / 184).

Offline, synthetic vectors only, no network, no secrets beyond the
app-embedded format constants already in tools/zivpn_reference.py.
Run from this dossier directory:

    python3 tools/verify.py [--harness /path/to/host_zivpn_test]

Checks:
  1. FIPS 46-3 DES and FIPS 197 AES-128 known answers via the OpenSSL
     CLI oracle (DES needs the legacy provider on OpenSSL 3.0).
  2. .ziv round-trips (legacy DES / export-style / legacy password) and
     zivpn:// round-trips (XML and JSON plaintext) via the reference oracle.
  3. Fixture self-check: every tests/fixtures file re-opens (or fails,
     for the negative fixtures) through the reference oracle.
  4. Negatives: wrong password, tampered GCM tag, truncated envelope,
     bad Base64, bad zivpn:// token.
  5. Optional: the compiled C++ host harness (tools/build_host_harness.sh)
     against the same fixtures.
"""
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DOSSIER = os.path.dirname(HERE)
FIXTURES = os.path.join(DOSSIER, "tests", "fixtures")
sys.path.insert(0, HERE)

import zivpn_reference as ref  # noqa: E402

PROPS = {
    "tunnelType": "4",
    "udpserver": "udp-test.example",
    "sshServer": "ssh-test.example",
    "sshPort": "443",
    "sshPortaLocal": "1080",
    "file.appVersionCode": "184",
    "file.askLogin": "0",
    "alpha": "0",
    "beta": "0",
    "gamma": "0",
}
SALT = bytes(range(32))
IV = bytes(range(12))


def _openssl_cipher(args, data):
    proc = subprocess.run(["openssl", "enc"] + args,
                          input=data, capture_output=True, timeout=30)
    if proc.returncode != 0:
        raise RuntimeError("openssl failed: %s" % proc.stderr.decode()[:200])
    return proc.stdout


def check_fips_vectors():
    des = _openssl_cipher(
        ["-des-ecb", "-provider", "legacy", "-provider", "default",
         "-K", "133457799BBCDFF1", "-nopad", "-nosalt"],
        bytes.fromhex("0123456789ABCDEF"))
    assert des.hex() == "85e813540f0ab405", des.hex()
    print("PASS FIPS 46-3 DES-ECB vector (openssl oracle)")
    aes = _openssl_cipher(
        ["-aes-128-ecb", "-K", "000102030405060708090a0b0c0d0e0f",
         "-nopad", "-nosalt"],
        bytes.fromhex("00112233445566778899aabbccddeeff"))
    assert aes.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", aes.hex()
    print("PASS FIPS 197 AES-128 vector (openssl oracle)")


def check_roundtrips():
    for legacy in (True, False):
        sealed = ref.seal_ziv(PROPS, ref.LF1_PASSWORDS[0], SALT, IV, legacy=legacy)
        props, _xml, info = ref.open_ziv(sealed)
        assert props == PROPS and info["des_layer"] is legacy
        print("PASS .ziv round-trip legacy=%s" % legacy)
    sealed = ref.seal_ziv(PROPS, ref.LF1_PASSWORDS[1], SALT, IV, legacy=False)
    props, _xml, info = ref.open_ziv(sealed)
    assert props == PROPS and info["des_layer"] is False
    print("PASS .ziv round-trip legacy password")
    xml = ref.properties_xml(PROPS).decode("utf-8")
    token = ref.seal_zivpn_text(xml)
    assert ref.decode_zivpn(token) == xml
    print("PASS zivpn:// round-trip (XML)")
    doc = {"host": "json-test.example", "port": 443}
    token = ref.seal_zivpn_text(json.dumps(doc))
    assert json.loads(ref.decode_zivpn(token)) == doc
    print("PASS zivpn:// round-trip (JSON)")


def check_fixtures():
    for name in ("ziv-legacy.ziv", "ziv-export.ziv",
                 "ziv-legacy-password.ziv", "ziv-golden.ziv",
                 "ziv-emoji.ziv"):
        with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
            props, _xml, info = ref.open_ziv(fh.read())
        expected_name = name.replace(".ziv", ".expected.json")
        with open(os.path.join(FIXTURES, expected_name), encoding="utf-8") as fh:
            assert props == json.load(fh), name
        print("PASS fixture %s des_layer=%s" % (name, info["des_layer"]))
    with open(os.path.join(FIXTURES, "ziv-plain.xml"), "rb") as fh:
        props, _xml = ref.parse_properties_xml(fh.read())
    assert props == PROPS
    print("PASS fixture ziv-plain.xml")
    for name, want in (("zivpn-link.txt", PROPS),
                       ("zivpn-json-link.txt", {"host": "json-test.example", "port": 443})):
        with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
            clear = ref.decode_zivpn(fh.read().strip())
        assert clear is not None, name
        if name.endswith("link.txt") and "json" not in name:
            props, _xml = ref.parse_properties_xml(clear.encode("utf-8"))
            assert props == want, name
        else:
            assert json.loads(clear) == want, name
        print("PASS fixture %s" % name)


def check_negatives():
    sealed = ref.seal_ziv(PROPS, ref.LF1_PASSWORDS[0], SALT, IV, legacy=False)
    tampered = sealed.split(".")
    tampered[2] = ("A" if tampered[2][0] != "A" else "B") + tampered[2][1:]
    with open(os.path.join(FIXTURES, "ziv-lone-surrogate.ziv"),
              encoding="utf-8") as fh:
        lone_surrogate = fh.read()
    for label, fn in (
            ("wrong password", lambda: ref.open_ziv(
                ref.seal_ziv(PROPS, "wrong-password-test", SALT, IV, legacy=False))),
            ("tampered GCM tag", lambda: ref.open_ziv(".".join(tampered))),
            ("two-part envelope", lambda: ref.open_ziv("AAAA.AAAA")),
            ("bad base64", lambda: ref.open_ziv("!!!.!!!.!!!")),
            ("lone surrogate", lambda: ref.open_ziv(lone_surrogate)),
    ):
        try:
            fn()
        except Exception:
            print("PASS negative: %s rejected" % label)
        else:
            raise AssertionError("negative accepted: %s" % label)
    # decode_zivpn signals rejection by returning None, not by raising.
    if ref.decode_zivpn("zivpn://!!") is None:
        print("PASS negative: bad zivpn token rejected")
    else:
        raise AssertionError("negative accepted: bad zivpn token")


def check_harness(path):
    proc = subprocess.run([path, FIXTURES], capture_output=True,
                          text=True, timeout=120)
    print(proc.stdout, end="")
    if proc.returncode != 0:
        raise RuntimeError("C++ host harness failed:\n%s" % proc.stderr)
    print("PASS C++ host harness (%s)" % path)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    harness = None
    if argv and argv[0] == "--harness":
        harness = argv[1]
    check_fips_vectors()
    check_roundtrips()
    check_fixtures()
    check_negatives()
    if harness:
        check_harness(harness)
    print("VERIFY OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
