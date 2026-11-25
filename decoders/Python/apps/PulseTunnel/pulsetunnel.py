#!/usr/bin/env python3
"""PULSE TUNNEL VPN 1.7 (com.alinaj.plusetunnel, versionCode 7) -- SP-DECODE decoder.

Live catalog
------------
GET https://xxxbeeghub.com/api/app?json=a1c4f329af86d98a93ed
Plain GET, no body. The app (jr0 / AppHttp.get, OkHttp) also sends optional
headers X-Integrity-Token (Play Integrity), X-App-Sig, X-App-Pkg,
X-App-Ver=7 and X-Install-Id, but the server answers a plain GET too
(verified live 2026-11-25: HTTP 200, 1,863,116 bytes, identical to the
fixture captured earlier). The app first tries a 300-byte Range prefix
check against its cached Servers_v3.js and skips the full download when
the prefix matches; the script always does the full GET.

Envelope (Utils.Parser.parseToString + SecureSig.unwrap + BAES.decrypt)
----------------------------------------------------------------------
  S1.<base64 RSA-SHA256 signature>.<genCode(base64(RBG1 || IV || AES-GCM ct+tag))>
  - Signature: RSA PKCS#1 v1.5 / SHA-256 over the payload part, verified
    against the app's embedded RSA-2048 public key (REQUIRE_SIGNATURE).
  - genCode/genString: each byte of the base64 text is written as two
    letters A-P (high nibble, low nibble) over the alphabet "ABCDEFGHIJKLMNOP".
  - BAES: AES/GCM/NoPadding, 12-byte IV, key =
    SHA-256( SALT + ( genUser() + hex(key_arg) ) )
    SALT = "ZTsalt_1cd46aad9854da58357eca6d"
    genUser() = base64("@technore24") (with trailing newline, as Android
    Base64.encodeToString(..., 0) produces)
    key_arg (catalog) = "ZT_g1_551022964e8b3db3fd739a451adc"
  - Plaintext starting with "GZ1:" is base64+gzip; the live catalog is
    plain JSON after the GCM layer.

Per-field cipher (OpenVPNClient.G0 / TeaBase64)
-----------------------------------------------
Most string fields inside the catalog JSON are XXTEA-encrypted and then
base64-encoded (TeaBase64, key "ng#7b3f9fb1e09a", standard XXTEA with the
length word). Decoded fields: servers ServerIPHost, ServerCloudFrontHost,
ServerHTTPHost, Username, Password, Payload, Nameserver, PublicKey,
V2rayID, OVPNCert (an OpenVPN client config with embedded CA certs);
networks SNIHost, Payload, ProxySettings.Squid, ProxySettings.Host; and
the TOP-LEVEL OVPNCert (a default/template OpenVPN client config, read
by the app itself with G0 in we1.t()). Plain (not encoded): Name, Flag,
ports, Category, Info, ServerHostDNS ("cf"/"http"/"ws"),
ProxySettings.Port. Decoded values are real UTF-8: some payloads contain
NBSP (U+00A0), accented chars or '×' (U+00D7) as part of the template, so
no ASCII-only check is applied. Server Payloads carry a fixed 15-char
'~!~~!~~!~~!~~!~' filler suffix left by the panel encoder (an empty
payload is filler only); it is stripped, so empty payloads decode to "".
Examples (live catalog v1.0.102): ServerIPHost -> "all.xxxbeeghub.com",
Username/Password -> per-server credentials, SNIHost -> "www.tiktok.com",
Payload -> HTTP payload templates / a vless:// link / a Hysteria2 JSON.

Own file format: .pulse (UserExport, ConfigImportActivity)
---------------------------------------------------------
Exported config file, one network per file. Envelope JSON:
  {"fmt":2, "app":"tourvpn", "minAppVersion":7, "exportedAt":<ms>,
   "protect":bool, "passworded":bool, "message":str, "rules":{...},
   "expiry":0, "blockRoot":bool, "Networks":[ <one network object> ]}
Wire form (no password):
  "TOURUX1:" + BAES.encrypt(EXPORT_PASS, envelope_json)
Wire form (password-protected):
  "TOURUX1P:" + BAES.encrypt(EXPORT_PASS + "|" + password, envelope_json)
  EXPORT_PASS = "TR_UX1_c1f8e2a94d6b3075e8a1f4c29d7b6e13_tourvpn"
The same TOURUX1:/TOURUX1P: wire text can be pasted as text (extractWire);
there is no custom URI scheme (the manifest declares no intent filters)
and no vmess/vless/ss/trojan import was found. The app also reads a
manual_servers.js file with the same S1. signed-catalog format as the
live endpoint. .sks files are not used by this app.

Usage
-----
  python3 pulsetunnel.py                 # fetch live, print summary
  python3 pulsetunnel.py --decoded-out catalog-full.json --redacted-out catalog.json
  python3 pulsetunnel.py --local file.raw --decoded-out out.json
  python3 pulsetunnel.py --self-test    # .pulse + XXTEA round trips (synthetic)

Requires: pycryptodome (AES-GCM). RSA verification needs `cryptography`
and is skipped with a warning when it is unavailable.
"""

import argparse
import base64
import gzip
import hashlib
import json
import re
import sys
import urllib.request

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover
    AES = None

CATALOG_URL = "https://xxxbeeghub.com/api/app?json=a1c4f329af86d98a93ed"
USER_AGENT = "SP-DECODE/1.0 (+https://spdecode.xyz)"

# --- BAES constants (recovered from the LSParanoid deobfuscator) ---------
ALPHABET = "ABCDEFGHIJKLMNOP"
KEY_ARG_CATALOG = "ZT_g1_551022964e8b3db3fd739a451adc"
EXPORT_PASS = "TR_UX1_c1f8e2a94d6b3075e8a1f4c29d7b6e13_tourvpn"
SALT = "ZTsalt_1cd46aad9854da58357eca6d"
MAGIC = b"RBG1"
PULSE_MAGIC = "TOURUX1:"
PULSE_MAGIC_P = "TOURUX1P:"
PUBKEY_B64 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs9GPH5hB2OSWZQMS+Th5TLCQMoaL3Rjx/"
    "xd5IX6INkIRu27iemHmwuAZxjWyVw4lTLM08h2VhMYbCw7EwyQU2BIODTxgQULAEbSyL4LXmIcjciEw4g"
    "WXG/ANtY5BIA2EPQUxTjebAx3SnFOSUJwJ86ti2GOOzEwc7EEvG1yQ8oVInkQtWg9wmap6efLIRfyHSBQ"
    "okcaUyCtgjVfBAjsAhNRJE3FRyG74fcRYPQ9Sj+5KN6FI6OpFsC+VmGxqizE/2ovKCibi8kN+2gvt72d5P"
    "9dOCg4RKmwCeDQrHE5L/T0Q2Jtdh3ELU/fxvONluW0qwqurPaLkMeBlc+nMyPYq0wIDAQAB"
)

# --- XXTEA (TeaBase64, key from OpenVPNClient.G0) --------------------------
XXTEA_KEY = "ng#7b3f9fb1e09a"
_DELTA = 0x9E3779B9
_M32 = 0xFFFFFFFF


def _i32(x):
    x &= _M32
    return x - 0x100000000 if x >= 0x80000000 else x


def _xxtea_mx(s, y, z, p, e, k):
    return _i32(
        (((s ^ y) + (k[(p & 3) ^ e] ^ z)) & _M32)
        ^ (((((z & _M32) >> 5) ^ ((y << 2) & _M32)) + (((y & _M32) >> 3) ^ ((z << 4) & _M32))) & _M32)
    )


def _to_ints(data, include_len):
    n = len(data)
    ln = n // 4 if n % 4 == 0 else n // 4 + 1
    out = [0] * (ln + (1 if include_len else 0))
    if include_len:
        out[ln] = n
    for i, b in enumerate(data):
        out[i >> 2] |= (b & 0xFF) << ((i & 3) << 3)
    return [_i32(x) for x in out]


def _to_bytes(v, include_len):
    n = len(v) * 4
    if include_len:
        m = v[-1]
        if m < n - 7 or m > n - 4:
            return None
        n = m
    out = bytearray()
    for i in range(n):
        out.append((v[i >> 2] >> ((i & 3) << 3)) & 0xFF)
    return bytes(out)


def _strip_filler(text):
    """Strip the panel's trailing filler from a decoded field.

    Server Payloads carry a fixed 15-char '~!~~!~~!~~!~~!~' suffix (an
    empty payload is filler only); other fields may end with an even
    '~!' run. A trailing run of 2+ '~'/'!' chars is filler by
    construction; a single trailing '~' or '!' is kept, since it could
    be real payload text.
    """
    return re.sub(r"[~!]{2,}$", "", text)


def xxtea_decrypt_b64(s):
    """TeaBase64.decryptBase64StringToString(s, XXTEA_KEY); None on failure.

    Returns "" (not None) when the plaintext is genuinely empty after
    the filler strip, e.g. an empty server Payload, whose ciphertext
    decrypts to the filler alone. Decoded text is real UTF-8: payloads
    legitimately contain NBSP (U+00A0), accented chars and '×'
    (U+00D7), so the decode is strict UTF-8 instead of an ASCII-only
    check (the old check silently left such payloads encrypted).
    """
    if not s:
        return None
    try:
        data = base64.b64decode(s)
    except Exception:
        return None
    if not data:
        return None
    k = _to_ints((XXTEA_KEY.encode() + b"\0" * 16)[:16], False)
    v = _to_ints(data, False)
    n = len(v)
    if n < 2:
        out = _to_bytes(v, True)
        if out is None:
            return None
        try:
            return _strip_filler(out.decode("utf-8"))
        except UnicodeDecodeError:
            return None
    rounds = (52 // n) + 6
    # DELTA as signed int32 is -1640531527
    ssum = _i32(rounds * -1640531527)
    y = v[0]
    while ssum != 0:
        e = ((ssum & _M32) >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = _i32(v[p] - _xxtea_mx(ssum, y, z, p, e, k))
            y = v[p]
        z = v[n - 1]
        v[0] = _i32(v[0] - _xxtea_mx(ssum, y, z, 0, e, k))
        y = v[0]
        ssum = _i32(ssum - -1640531527)
    out = _to_bytes(v, True)
    if out is None:
        return None
    try:
        return _strip_filler(out.decode("utf-8"))
    except UnicodeDecodeError:
        return None


def xxtea_encrypt_b64(text):
    """TeaBase64.encryptToBase64String(text, XXTEA_KEY)."""
    data = text.encode("utf-8")
    if not data:
        return ""
    k = _to_ints((XXTEA_KEY.encode() + b"\0" * 16)[:16], False)
    v = _to_ints(data, True)
    n = len(v)
    rounds = (52 // n) + 6
    ssum = 0
    z = v[n - 1]
    for _ in range(rounds):
        ssum = _i32(ssum + -1640531527)
        e = ((ssum & _M32) >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            v[p] = _i32(v[p] + _xxtea_mx(ssum, y, z, p, e, k))
            z = v[p]
        y = v[0]
        v[n - 1] = _i32(v[n - 1] + _xxtea_mx(ssum, y, z, n - 1, e, k))
        z = v[n - 1]
    return base64.b64encode(_to_bytes(v, False)).decode("ascii")


def _looks_b64(s):
    return (
        isinstance(s, str)
        and len(s) >= 8
        and len(s) % 4 == 0
        and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s) is not None
    )


def _try_xxtea(value):
    """XXTEA-decode a catalog field; return the original on any doubt.

    A successful decode to "" (empty after the filler strip) is a real
    result, not a failure: an empty server Payload decrypts to the
    filler alone, so None (failure) and "" (empty plaintext) differ.
    """
    if not _looks_b64(value):
        return value
    dec = xxtea_decrypt_b64(value)
    if dec is None or dec == value:
        return value
    if "\x00" in dec or any(ord(c) < 32 and c not in "\n\r\t" for c in dec):
        return value
    return dec


# --- BAES (AES-GCM envelope) ----------------------------------------------
def _gen_user_b64():
    # BAES.genUser(): Base64.encodeToString("@technore24".getBytes(), 0)
    return base64.b64encode(b"@technore24").decode("ascii") + "\n"


def _derive_key(key_arg):
    material = SALT + (_gen_user_b64() + key_arg.encode("utf-8").hex().upper())
    return hashlib.sha256(material.encode("utf-8")).digest()


def _gen_string(coded):
    out = bytearray()
    for i in range(0, len(coded), 2):
        out.append((ALPHABET.index(coded[i]) * 16 + ALPHABET.index(coded[i + 1])) & 0xFF)
    return bytes(out).decode("ascii")


def _gen_code(b64text):
    out = []
    for b in b64text.encode("ascii"):
        out.append(ALPHABET[(b & 0xF0) >> 4])
        out.append(ALPHABET[b & 0x0F])
    return "".join(out)


def baes_decrypt(coded, key_arg):
    if AES is None:
        raise RuntimeError("pycryptodome is required (Crypto.Cipher.AES)")
    raw = base64.b64decode(_gen_string(coded))
    if raw[:4] != MAGIC:
        raise ValueError("bad magic: %r" % raw[:4])
    iv, ct_tag = raw[4:16], raw[16:]
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    cipher = AES.new(_derive_key(key_arg), AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ct, tag).decode("utf-8")


def baes_encrypt(plaintext, key_arg):
    if AES is None:
        raise RuntimeError("pycryptodome is required (Crypto.Cipher.AES)")
    import os

    iv = os.urandom(12)
    cipher = AES.new(_derive_key(key_arg), AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return _gen_code(base64.b64encode(MAGIC + iv + ct + tag).decode("ascii"))


def verify_signature(blob):
    """Verify the RSA-SHA256 signature of an S1. blob. True/False/None (no lib)."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:
        return None
    s = "".join(blob.split())
    if not s.startswith("S1."):
        return False
    i = s.index(".", 3)
    sig = base64.b64decode(s[3:i])
    payload = s[i + 1 :]
    pub = serialization.load_der_public_key(base64.b64decode(PUBKEY_B64))
    try:
        pub.verify(sig, payload.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def parse_signed_catalog(blob, key_arg=KEY_ARG_CATALOG):
    """S1. blob -> plaintext JSON string (verifies the signature first)."""
    s = "".join(blob.split())
    if not s.startswith("S1."):
        raise ValueError("not an S1. signed blob")
    i = s.index(".", 3)
    payload = s[i + 1 :]
    plain = baes_decrypt(payload, key_arg)
    if plain.startswith("GZ1:"):
        return gzip.decompress(base64.b64decode(plain[4:])).decode("utf-8")
    return plain


# --- catalog field decoding ----------------------------------------------
SERVER_XXTEA_FIELDS = [
    "ServerIPHost", "ServerCloudFrontHost", "ServerHTTPHost",
    "Username", "Password", "Payload", "Nameserver", "PublicKey",
    "V2rayID", "OVPNCert",
]
NETWORK_XXTEA_FIELDS = ["SNIHost", "Payload"]
PROXY_XXTEA_FIELDS = ["Squid", "Host", "User", "Pass"]


def decode_catalog_fields(data):
    """Return a copy of the catalog dict with XXTEA fields decoded."""
    data = json.loads(json.dumps(data))
    # Top-level OVPNCert is XXTEA too: the app reads it with G0 in
    # we1.t() (OpenVPNClient.n1.setOVPNCert(G0(optString("OVPNCert")))).
    # It is a default/template OpenVPN client config (Cebu CA), distinct
    # from the per-server OVPNCerts below.
    if data.get("OVPNCert"):
        data["OVPNCert"] = _try_xxtea(data["OVPNCert"])
    for srv in data.get("Servers", []):
        for f in SERVER_XXTEA_FIELDS:
            if srv.get(f):
                srv[f] = _try_xxtea(srv[f])
    for net in data.get("Networks", []):
        for f in NETWORK_XXTEA_FIELDS:
            if net.get(f):
                net[f] = _try_xxtea(net[f])
        proxy = net.get("ProxySettings")
        if isinstance(proxy, dict):
            for f in PROXY_XXTEA_FIELDS:
                if proxy.get(f):
                    proxy[f] = _try_xxtea(proxy[f])
    return data


def collect_credentials(decoded):
    creds = set()
    for srv in decoded.get("Servers", []):
        for f in ("Username", "Password", "V2rayID"):
            if srv.get(f):
                creds.add(srv[f])
    return {c for c in creds if c}


def redact_catalog(decoded):
    """Copy with credentials replaced by '***' (safe for the repo/Drive)."""
    data = json.loads(json.dumps(decoded))
    creds = collect_credentials(data)
    for srv in data.get("Servers", []):
        for f in ("Username", "Password", "V2rayID"):
            if srv.get(f):
                srv[f] = "***"
    if creds:
        def scrub(text):
            for c in sorted(creds, key=len, reverse=True):
                # mask "user:pass" pairs inside payload JSON as well
                text = text.replace(c, "***")
            return text

        def walk(obj):
            if isinstance(obj, dict):
                return {k: walk(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [walk(v) for v in obj]
            if isinstance(obj, str):
                return scrub(obj)
            return obj

        data = walk(data)
    return data


# --- .pulse files ---------------------------------------------------------
def encode_pulse(networks, password=None, message=""):
    """Build a .pulse wire string from a list with exactly one network dict."""
    if len(networks) != 1:
        raise ValueError("a .pulse file holds exactly one network")
    import time

    envelope = {
        "fmt": 2,
        "app": "tourvpn",
        "minAppVersion": 7,
        "exportedAt": int(time.time() * 1000),
        "protect": bool(password),
        "passworded": bool(password),
        "message": message,
        "rules": {},
        "expiry": 0,
        "blockRoot": False,
        "Networks": networks,
    }
    if password:
        return PULSE_MAGIC_P + baes_encrypt(json.dumps(envelope), EXPORT_PASS + "|" + password)
    return PULSE_MAGIC + baes_encrypt(json.dumps(envelope), EXPORT_PASS)


def decode_pulse(text, password=None):
    """Decode a .pulse wire string (or pasted text containing one) -> envelope dict."""
    wire = extract_pulse_wire(text)
    if wire is None:
        raise ValueError("no TOURUX1:/TOURUX1P: wire found in text")
    if wire.startswith(PULSE_MAGIC_P):
        if not password:
            raise ValueError("password-protected .pulse (TOURUX1P:) needs a password")
        return json.loads(baes_decrypt(wire[len(PULSE_MAGIC_P):], EXPORT_PASS + "|" + password))
    if wire.startswith(PULSE_MAGIC):
        return json.loads(baes_decrypt(wire[len(PULSE_MAGIC):], EXPORT_PASS))
    raise ValueError("unknown .pulse magic")


def extract_pulse_wire(text):
    """UserExport.extractWire: find the TOURUX1: wire inside pasted text."""
    if text is None:
        return None
    t = text.replace("\r", "").replace("\n", "").replace(" ", "").replace("\t", "").strip()
    for magic in (PULSE_MAGIC_P, PULSE_MAGIC):
        i = t.find(magic)
        if i >= 0:
            j = i + len(magic)
            while j < len(t) and "A" <= t[j] <= "P":
                j += 1
            if j > i + len(magic):
                return t[i:j]
    return None


# --- live download ---------------------------------------------------------
def fetch_catalog(url=CATALOG_URL, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError("HTTP %s fetching %s" % (resp.status, url))
        return resp.read().decode("utf-8")


def summarize(decoded):
    servers = decoded.get("Servers", [])
    networks = decoded.get("Networks", [])
    free = [s for s in servers if s.get("Category", "").upper() == "FREE"]
    payloads = {s.get("Payload") for s in servers if s.get("Payload")}
    payloads |= {n.get("Payload") for n in networks if n.get("Payload")}
    return {
        "catalog_version": decoded.get("Version"),
        "servers": len(servers),
        "free_servers": len(free),
        "server_categories": sorted({s.get("Category", "") for s in servers}),
        "networks": len(networks),
        "ssl_networks": len(decoded.get("SSLNetworks", [])),
        "distinct_payloads": len(payloads),
    }


def self_test():
    net = {
        "Name": "Synthetic Test",
        "Group": "",
        "Info": "",
        "TunnelType": 3,
        "Protocol": 0,
        "Priority": 0,
        "ServerHostDNS": "cf",
        "GenRow": 3,
        "SNIHost": "www.example.com",
        "Payload": "GET / HTTP/1.1[crlf]Host: [alinaj][crlf][crlf]",
        "TlsVersion": "Default",
        "ProxySettings": {"Squid": "[Default]", "Port": "80"},
    }
    wire = encode_pulse([net])
    assert wire.startswith(PULSE_MAGIC), wire[:16]
    back = decode_pulse("pasted text around it:\n" + wire + "\nend")
    assert back["Networks"][0]["Name"] == "Synthetic Test", back
    assert back["fmt"] == 2 and back["app"] == "tourvpn"
    wire_p = encode_pulse([net], password="secret123")
    assert wire_p.startswith(PULSE_MAGIC_P)
    assert decode_pulse(wire_p, password="secret123")["Networks"][0]["Name"] == "Synthetic Test"
    enc = xxtea_encrypt_b64("www.tiktok.com")
    assert xxtea_decrypt_b64(enc) == "www.tiktok.com", (enc, xxtea_decrypt_b64(enc))
    assert xxtea_decrypt_b64("FaYCaMG3XbS7HGybj/3F6e2m6QDsMM6f") == "all.xxxbeeghub.com"
    # Correction 2026-11-25 (fase 2): non-ASCII payloads must decode
    # (NBSP / accented chars / '×' are real template text, not binary).
    nnbsp = "POST / HTTP/1.1[crlf]Connection:\xa0\xa0Close[crlf]Content-length:\xa0\xa0999"
    assert xxtea_decrypt_b64(xxtea_encrypt_b64(nnbsp)) == nnbsp
    acc = "Contrucción de polígono regulares [lf]Host: [alinaj]"
    assert xxtea_decrypt_b64(xxtea_encrypt_b64(acc)) == acc
    sep = "162.159.153.247×sep×GET / HTTP/1.1[crlf]Host: [alinaj][crlf][crlf]"
    assert xxtea_decrypt_b64(xxtea_encrypt_b64(sep)) == sep
    # Server-payload filler: 15-char '~!~~!~~!~~!~~!~' suffix is
    # stripped; a filler-only (empty) payload decodes to "".
    assert _try_xxtea(xxtea_encrypt_b64("GET / HTTP/1.1[crlf]Host: x[crlf][crlf]" + "~!~~!~~!~~!~~!~")) == "GET / HTTP/1.1[crlf]Host: x[crlf][crlf]"
    assert _try_xxtea(xxtea_encrypt_b64("~!~~!~~!~~!~~!~")) == ""
    assert xxtea_decrypt_b64(xxtea_encrypt_b64("~!~~!~~!~~!~~!~")) == ""
    # Top-level OVPNCert is XXTEA too (app reads it with G0, we1.t()).
    top = decode_catalog_fields({"OVPNCert": xxtea_encrypt_b64("client\ndev tun\nproto tcp-client\n"), "Servers": [], "Networks": []})
    assert top["OVPNCert"] == "client\ndev tun\nproto tcp-client\n", top["OVPNCert"]
    print("self-test OK: .pulse (plain + passworded) and XXTEA round trips pass")


def main(argv=None):
    ap = argparse.ArgumentParser(description="PULSE TUNNEL VPN 1.7 catalog decoder (SP-DECODE)")
    ap.add_argument("--url", default=CATALOG_URL)
    ap.add_argument("--local", help="decode a local S1. file instead of fetching")
    ap.add_argument("--raw-out", help="save the raw S1. blob")
    ap.add_argument("--decrypted-out", help="save the BAES-decrypted JSON (fields still XXTEA-encoded)")
    ap.add_argument("--decoded-out", help="save the fully field-decoded catalog (WITH credentials)")
    ap.add_argument("--redacted-out", help="save the field-decoded catalog with credentials redacted")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    if args.local:
        blob = open(args.local, encoding="utf-8", errors="replace").read()
    else:
        blob = fetch_catalog(args.url)
    if args.raw_out:
        open(args.raw_out, "w", encoding="utf-8").write(blob)
    sig = verify_signature(blob)
    print("signature RSA-SHA256:", {True: "VALID", False: "INVALID", None: "not checked (cryptography missing)"}[sig])
    plain = parse_signed_catalog(blob)
    data = json.loads(plain)
    if args.decrypted_out:
        open(args.decrypted_out, "w", encoding="utf-8").write(json.dumps(data, ensure_ascii=False, indent=1))
    decoded = decode_catalog_fields(data)
    if args.decoded_out:
        open(args.decoded_out, "w", encoding="utf-8").write(json.dumps(decoded, ensure_ascii=False, indent=1))
    if args.redacted_out:
        red = redact_catalog(decoded)
        open(args.redacted_out, "w", encoding="utf-8").write(json.dumps(red, ensure_ascii=False, indent=1))
    print(json.dumps(summarize(decoded), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
