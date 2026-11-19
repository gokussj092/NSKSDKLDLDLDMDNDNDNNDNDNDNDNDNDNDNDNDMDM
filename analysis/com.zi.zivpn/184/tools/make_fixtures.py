#!/usr/bin/env python3
"""Generate the synthetic ZIVPN fixtures for this dossier (deterministic).

All values are synthetic (TEST / .example domains, TEST-NET style). No real
server, credential or user profile. Fixed salt/iv so the fixtures are
byte-identical on every run; re-run to regenerate after any change:

    python3 tools/make_fixtures.py

Outputs (tests/fixtures/):
  ziv-legacy.ziv            legacy import format: XML -> DES -> LF1, fixed password
  ziv-export.ziv            as the app exports:  XML -> LF1 only, fixed password
  ziv-legacy-password.ziv   export-style, legacy password (fallback candidate)
  ziv-plain.xml             unencrypted Properties XML (catalog-XML form)
  zivpn-link.txt            zivpn:// token (AES-256-CBC, Properties XML)
  zivpn-json-link.txt       zivpn:// token (AES-256-CBC, JSON plaintext)
  *.expected.json           expected decoded properties / JSON per fixture
"""
import json
import os
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

# Fixed salt/iv (same style as the reference golden vector): deterministic.
SALT = bytes(range(32))
IV = bytes(range(12))

JSON_PROPS = {"host": "json-test.example", "port": 443}


def _tamper(envelope):
    """Flip one Base64 character inside the ciphertext part (breaks the tag)."""
    parts = envelope.split(".")
    ct = parts[2]
    alt = "A" if ct[0] != "A" else "B"
    parts[2] = alt + ct[1:]
    return ".".join(parts)


def _write(name, data):
    path = os.path.join(FIXTURES, name)
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(path, mode, encoding=None if isinstance(data, bytes) else "utf-8") as fh:
        fh.write(data)
    print("wrote %s (%d bytes)" % (name, len(data)))


def _java_escape_astral(xml_bytes):
    """Mimic java.util.Properties: write astral characters (emoji) as
    surrogate-pair numeric references ("&#55356;&#56808;") instead of raw
    UTF-8, the shape seen in a real app export (file.msg)."""
    out = []
    for ch in xml_bytes.decode("utf-8"):
        cp = ord(ch)
        if cp > 0xFFFF:
            cp -= 0x10000
            out.append("&#%d;&#%d;" % (0xD800 + (cp >> 10),
                                       0xDC00 + (cp & 0x3FF)))
        else:
            out.append(ch)
    return "".join(out).encode("utf-8")


def main():
    os.makedirs(FIXTURES, exist_ok=True)
    xml_bytes = ref.properties_xml(PROPS)
    fixed = ref.LF1_PASSWORDS[0]
    legacy_pw = ref.LF1_PASSWORDS[1]

    _write("ziv-legacy.ziv",
           ref.seal_ziv(PROPS, fixed, SALT, IV, legacy=True))
    _write("ziv-export.ziv",
           ref.seal_ziv(PROPS, fixed, SALT, IV, legacy=False))
    _write("ziv-legacy-password.ziv",
           ref.seal_ziv(PROPS, legacy_pw, SALT, IV, legacy=False))
    # Frozen golden vector from the online reference (ZIVPN_archivos.py
    # _GOLDEN_ZIV): reproduced byte-for-byte by this oracle (same props,
    # same fixed salt/iv, legacy style). Vendor hostname from the research
    # notes, not a user profile.
    golden_props = {"tunnelType": "4", "udpserver": "udpsg1.zivpn.com",
                    "sshPortaLocal": "1080", "file.appVersionCode": "24",
                    "file.askLogin": "0", "alpha": "0", "beta": "0",
                    "gamma": "0"}
    _write("ziv-golden.ziv",
           ref.seal_ziv(golden_props, fixed, SALT, IV, legacy=True))
    _write("ziv-plain.xml", xml_bytes)
    _write("zivpn-link.txt",
           ref.seal_zivpn_text(xml_bytes.decode("utf-8")))
    _write("zivpn-json-link.txt",
           ref.seal_zivpn_text(json.dumps(JSON_PROPS)))

    # Emoji fixture: file.msg holds astral characters written the way
    # java.util.Properties writes them — surrogate-pair numeric references
    # (&#55356;&#56808;), as seen in a real app export. Export-style
    # (LF1 only), like the real file.
    emoji_props = dict(PROPS)
    emoji_props["file.msg"] = "test flag \U0001F1E8\U0001F1F2 ok"
    _write("ziv-emoji.ziv",
           ref.lf1_encrypt(_java_escape_astral(ref.properties_xml(emoji_props)),
                           fixed, SALT, IV))
    _write("ziv-emoji.expected.json",
           json.dumps(emoji_props, ensure_ascii=False, indent=2,
                      sort_keys=True) + "\n")
    # Negative: a lone high surrogate with no low partner must still fail.
    lone_props = dict(PROPS)
    lone_xml = ref.properties_xml(lone_props).decode("utf-8").replace(
        "</properties>",
        '<entry key="file.msg">test &#55356; lone</entry>\n</properties>')
    _write("ziv-lone-surrogate.ziv",
           ref.lf1_encrypt(lone_xml.encode("utf-8"), fixed, SALT, IV))

    # Negative fixtures (must FAIL to decode).
    _write("ziv-wrong-password.ziv",
           ref.lf1_encrypt(ref.properties_xml(PROPS), "wrong-password-test",
                           SALT, IV))
    # Flip one character inside the Base64 ciphertext part (breaks the tag).
    _write("ziv-tampered-tag.ziv",
           _tamper(ref.seal_ziv(PROPS, fixed, SALT, IV, legacy=False)))

    expected = dict(PROPS)
    for name in ("ziv-legacy", "ziv-export", "ziv-legacy-password", "ziv-plain"):
        _write(name + ".expected.json",
               json.dumps(expected, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    _write("ziv-golden.expected.json",
           json.dumps({"tunnelType": "4", "udpserver": "udpsg1.zivpn.com",
                       "sshPortaLocal": "1080", "file.appVersionCode": "24",
                       "file.askLogin": "0", "alpha": "0", "beta": "0",
                       "gamma": "0"},
                      ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    _write("zivpn-link.expected.json",
           json.dumps(expected, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    _write("zivpn-json-link.expected.json",
           json.dumps(JSON_PROPS, ensure_ascii=False, indent=2, sort_keys=True) + "\n")

    # Self-check: every fixture re-opens through the reference oracle.
    for name in ("ziv-legacy.ziv", "ziv-export.ziv", "ziv-legacy-password.ziv"):
        with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
            props, _xml, info = ref.open_ziv(fh.read())
        assert props == expected, name
        print("verified %s des_layer=%s" % (name, info["des_layer"]))
    with open(os.path.join(FIXTURES, "ziv-emoji.ziv"), encoding="utf-8") as fh:
        props, _xml, info = ref.open_ziv(fh.read())
    assert props == emoji_props and info["des_layer"] is False
    print("verified ziv-emoji.ziv des_layer=False")
    with open(os.path.join(FIXTURES, "ziv-lone-surrogate.ziv"),
              encoding="utf-8") as fh:
        lone = fh.read()
    try:
        ref.open_ziv(lone)
    except ref.DecodeError:
        print("verified ziv-lone-surrogate.ziv rejected")
    else:
        raise AssertionError("lone surrogate accepted")
    with open(os.path.join(FIXTURES, "ziv-plain.xml"), "rb") as fh:
        props, _xml = ref.parse_properties_xml(fh.read())
    assert props == expected
    for name in ("zivpn-link.txt", "zivpn-json-link.txt"):
        with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
            clear = ref.decode_zivpn(fh.read().strip())
        assert clear is not None, name
        print("verified %s" % name)
    print("fixtures OK")


if __name__ == "__main__":
    main()
