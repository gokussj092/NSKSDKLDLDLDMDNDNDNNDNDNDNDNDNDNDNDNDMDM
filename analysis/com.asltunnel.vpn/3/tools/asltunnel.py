#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ASL TUNNEL 3.0 (com.asltunnel.vpn, versionCode 3) - catalog + file decoders.
SP-DECODE catalog batch 15, app 4 of 6. Verified live 2026-11-27.

Catalog (live):
  GET https://raw.githubusercontent.com/th3fre/Testing/refs/heads/main/Alt
  Plain HTTP GET, no headers, no auth. Body = one line of Base64.
  Envelope: Base64 -> XXTEA (custom delta 0x9A7393B4, key = first 16 bytes
  of UTF-8 of U+3164 x33) -> JSON (still field-encrypted).
  Field encryption (servers + top level, Lln.H / LpR0.a):
  AES/CFB/NoPadding, key = SHA-256(UTF-8(" "*61 + "'" + " "*12 + "." + " "*8)),
  IV = 4e6a2c8153d9b4a7903f685ca1ef2479. Input Base64 (padding may be missing).
  Tweak encryption (Lln.I / LyT0.b):
  AES/CBC/PKCS7, key = ASCII hex (32 chars) of MD5(UTF-8(" "*29 + "." + " "*33)),
  IV = 3c7f1a9d55e3c0b28e216d4a97ff1362. Tweak Flag is PLAINTEXT ("NOOB_DEV").
  Nested server objects (V2ray.UUID/Path, SlowDNS.DNSTTNS/DNSTTKey,
  UDP.UDPObfs/UDPOpenPort) are also Lln.H-encrypted.

.asl file / CONFIG KEY (NoobCrypt.Nbdecrypt mode 1, native libwg-pro.so):
  Base64 -> IV[16] + AES-256-CBC(PKCS7) -> "ASL TUNNEL VPN" + JSON.
  Key = ASCII "0123456789abcdef1032547698badcfe" (32 bytes, libwg-pro.so
  .rodata 0x185223, shared by Nbencrypt/Nbdecrypt modes 0-3).
  The JSON is the imported server config; its string fields are PLAINTEXT
  (ASLTunnelMain.Q reads them directly). A second shape exists - the
  LCl.b custom-server object, whose string fields ARE Lln.M-encrypted
  (same AES/CFB scheme, Lln.H decrypts) - the decoder detects it by its
  keys (ServerIPHost, Username, V2ray, SlowDNS, ...) and decrypts exactly
  those fields, never guessing on the Q() shape.
  Import checks (ASLTunnelMain.S): marker "ASL TUNNEL VPN" must prefix the
  plaintext; ExpireDate (ms epoch, 0 = no expiry); DeviceID is a ';'
  separated allowlist of device fingerprints (LMA.a) - empty = any device;
  RootBlock=true refuses rooted devices; PSInstall=true requires install
  from Play (com.android.vending / com.google.android.feedback); isPassON
  =true prompts for the password in field MyPass. The decoder reports
  these fields; it does not enforce the device/root/install checks.

.ovpn: standard OpenVPN config text, no app-specific crypto (the app loads
it via OpenVPNService ProfileList from assets/imported/private storage).

Text links (verified in code, v2rayNG fork base):
  vmess://, vless://, trojan://, ss:// - standard clipboard/text import
  (LZ5 scheme table, Lrh.I import handler, ASLTunnelMain.G generates
  vless:// ... #Noob_XHTTP / #Noob_V2ray).
  asl://<20 random chars> is the app's own cloud-export link
  (ExportActivity.l) - its resolution endpoint is NOT verified (no real
  exported link sample), so it is documented, not implemented.

Usage:
  python3 asltunnel.py                 fetch live catalog, write
                                       catalogo-completo.json + print stats
  python3 asltunnel.py catalog [out]   same, custom output path
  python3 asltunnel.py asl <file.asl>  decode a .asl file / CONFIG KEY text
  python3 asltunnel.py asl-encode <config.json> <out.asl>
                                       build a synthetic .asl (round-trip test)
  python3 asltunnel.py ovpn <file.ovpn>  read/validate an .ovpn profile

Requires: pycryptodome. No other dependencies.
"""
import base64
import hashlib
import json
import os
import re
import struct
import sys
import urllib.request

# ---------------------------------------------------------------- catalog URL
CATALOG_URL = "https://raw.githubusercontent.com/th3fre/Testing/refs/heads/main/Alt"

# ---------------------------------------------------------------- XXTEA (Lfu0.a / LyF0.k)
XXTEA_DELTA = 0x9A7393B4
XXTEA_MASK = 0xFFFFFFFF
# U+3164 (Hangul filler) x33 in UTF-8 is E3 85 A4 repeated; first 16 bytes:
XXTEA_KEY16 = bytes.fromhex("e385a4" * 5 + "e3")


def _mx(z, y, s, p, e, k):
    return (((((z >> 5) ^ ((y << 2) & XXTEA_MASK)) & XXTEA_MASK)
             + (((y >> 3) ^ ((z << 4) & XXTEA_MASK)) & XXTEA_MASK)) & XXTEA_MASK) ^ \
           (((s ^ y) + ((k[(p & 3) ^ e] ^ z) & XXTEA_MASK)) & XXTEA_MASK)


def xxtea_decrypt(data, key16=XXTEA_KEY16):
    """XXTEA decrypt; plaintext length is stored in the last word.
    Returns bytes or None if the length check fails."""
    if len(data) == 0:
        return b""
    n = len(data) // 4
    v = list(struct.unpack("<%dI" % n, data[: n * 4]))
    k = list(struct.unpack("<4I", key16[:16].ljust(16, b"\x00")))
    rounds = 6 + 52 // n
    s = (rounds * XXTEA_DELTA) & XXTEA_MASK
    y = v[0]
    while s != 0:
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - _mx(z, y, s, p, e, k)) & XXTEA_MASK
            y = v[p]
        z = v[n - 1]
        v[0] = (v[0] - _mx(z, y, s, 0, e, k)) & XXTEA_MASK
        y = v[0]
        s = (s - XXTEA_DELTA) & XXTEA_MASK
    raw = struct.pack("<%dI" % n, *v)
    ln = v[n - 1]
    if ln < len(raw) - 7 or ln > len(raw) - 4:
        return None
    return raw[:ln]


def decrypt_alt(blob_text):
    """Lfu0.a: Base64 -> XXTEA -> bytes (JSON)."""
    raw = base64.b64decode("".join(blob_text.split()))
    return xxtea_decrypt(raw)


# ---------------------------------------------------------------- field crypto
# Lln.H / LpR0.a - AES/CFB/NoPadding (servers + top level + nested objects)
FIELD_KEY = hashlib.sha256((" " * 61 + "'" + " " * 12 + "." + " " * 8).encode("utf-8")).digest()
FIELD_IV = bytes.fromhex("4e6a2c8153d9b4a7903f685ca1ef2479")

# Lln.I / LyT0.b - AES/CBC/PKCS7 (tweaks)
TWEAK_KEY = hashlib.md5((" " * 29 + "." + " " * 33).encode("utf-8")).hexdigest().encode("ascii")
TWEAK_IV = bytes.fromhex("3c7f1a9d55e3c0b28e216d4a97ff1362")

# NoobCrypt.Nbdecrypt/Nbencrypt mode 1 - AES-256-CBC, IV prepended (16 bytes)
NB_KEY = b"0123456789abcdef1032547698badcfe"  # libwg-pro.so .rodata 0x185223


def _b64(s):
    b = s.strip()
    b += "=" * (-len(b) % 4)
    return base64.b64decode(b)


def field_decrypt(s):
    """Lln.H: AES/CFB decrypt a Base64 field value -> str."""
    from Crypto.Cipher import AES
    if s is None or s == "":
        return ""
    ct = _b64(s)
    return AES.new(FIELD_KEY, AES.MODE_CFB, iv=FIELD_IV, segment_size=128).decrypt(ct).decode("utf-8")


def field_encrypt(s):
    """Lln.M: AES/CFB encrypt (export direction of the same scheme)."""
    from Crypto.Cipher import AES
    if s is None or s == "":
        return ""
    ct = AES.new(FIELD_KEY, AES.MODE_CFB, iv=FIELD_IV, segment_size=128).encrypt(s.encode("utf-8"))
    return base64.b64encode(ct).decode()


def tweak_decrypt(s):
    """Lln.I: AES/CBC decrypt a Base64 tweak field value -> str."""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    if s is None or s == "":
        return ""
    ct = _b64(s)
    return unpad(AES.new(TWEAK_KEY, AES.MODE_CBC, iv=TWEAK_IV).decrypt(ct), 16).decode("utf-8")


def nbdecrypt_mode1(b64):
    """NoobCrypt.Nbdecrypt(input, 1): Base64 -> IV[16] + AES-256-CBC -> bytes."""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    raw = base64.b64decode("".join(b64.split()))
    if len(raw) < 17:
        raise ValueError("Nbdecrypt mode 1: input too short (%d bytes)" % len(raw))
    iv, ct = raw[:16], raw[16:]
    return unpad(AES.new(NB_KEY, AES.MODE_CBC, iv=iv).decrypt(ct), 16)


def nbencrypt_mode1(plain):
    """NoobCrypt.Nbencrypt(input, 1): random IV + AES-256-CBC -> Base64."""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    iv = os.urandom(16)
    ct = AES.new(NB_KEY, AES.MODE_CBC, iv=iv).encrypt(pad(plain, 16))
    return base64.b64encode(iv + ct).decode()


# ---------------------------------------------------------------- catalog
SERVER_STR_FIELDS = ["Name", "Flag", "Info", "ServerIPHost", "ServerHTTPHost",
                     "TCPPort", "SSLPort", "OpenVPNUDPPort", "DropBear", "ProxyPort",
                     "OpenVPNCertificate", "PrivateKey", "Username", "Password"]
SERVER_NESTED_STR_FIELDS = ["UUID", "Path", "DNSTTNS", "DNSTTKey", "UDPObfs", "UDPOpenPort"]
TWEAK_STR_FIELDS = ["Name", "Info", "Payload", "Sni", "ProxyHost", "ProxyPort",
                    "DNSHost", "UDPupMbps", "UDPdownMbps", "UDPrecvw", "v2rayjson", "v2Sni"]
TOP_STR_FIELDS_H = ["Version", "Message", "DefUpdateURL", "updater", "updatemsg",
                    "Banner_ID", "AppOpenAd", "Interstitial_ID", "RewardAd_ID", "RewardInter_ID",
                    "cardMessage", "cardLink"]
# Tweak.Flag is PLAINTEXT ("NOOB_DEV") - never decrypt it.


def decrypt_catalog(doc):
    """Decrypt every field of a parsed (still encrypted) catalog JSON.
    Returns a new dict with all values in clear text."""
    out = dict(doc)
    for k in TOP_STR_FIELDS_H:
        if isinstance(out.get(k), str) and out[k]:
            out[k] = field_decrypt(out[k])
    for s in out.get("Servers", []):
        for k in SERVER_STR_FIELDS:
            if isinstance(s.get(k), str) and s[k]:
                s[k] = field_decrypt(s[k])
        for nk in ("V2ray", "SlowDNS", "UDP"):
            sub = s.get(nk)
            if isinstance(sub, dict):
                for k in SERVER_NESTED_STR_FIELDS:
                    if isinstance(sub.get(k), str) and sub[k]:
                        sub[k] = field_decrypt(sub[k])
    for t in out.get("Tweaks", []):
        for k in TWEAK_STR_FIELDS:
            if isinstance(t.get(k), str) and t[k]:
                t[k] = tweak_decrypt(t[k])
    return out


def fetch_catalog_live(url=CATALOG_URL):
    """Plain HTTP GET, no headers, no auth (as the app does in LSu/LN.run)."""
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=60) as r:
        body = r.read().decode("utf-8", errors="replace")
    return body


def fetch_and_decrypt(url=CATALOG_URL):
    body = fetch_catalog_live(url)
    raw = decrypt_alt(body)
    if raw is None:
        raise ValueError("XXTEA decrypt of live catalog failed")
    doc = json.loads(raw.decode("utf-8"))
    return decrypt_catalog(doc)


def catalog_stats(doc):
    from collections import Counter
    servers = doc.get("Servers", [])
    tweaks = doc.get("Tweaks", [])
    free = sum(1 for s in servers if s.get("NoobLevel", 0) == 0)
    proto = Counter(s.get("Protocol") for s in servers)
    flags = Counter(s.get("Flag") for s in servers)
    modes = Counter(t.get("Mode") for t in tweaks)
    payloads = sum(1 for t in tweaks if t.get("Payload"))
    return {
        "Version": doc.get("Version"),
        "servers_total": len(servers),
        "servers_free_NoobLevel0": free,
        "servers_by_protocol": dict(sorted(proto.items(), key=lambda kv: str(kv[0]))),
        "servers_by_flag": dict(sorted(flags.items(), key=lambda kv: str(kv[0]))),
        "tweaks_total": len(tweaks),
        "tweaks_with_payload": payloads,
        "tweaks_by_mode": dict(sorted(modes.items(), key=lambda kv: str(kv[0]))),
    }


REDACTED = "[REDACTED]"
# Fields replaced by [REDACTED] in the shareable catalog: server addresses and
# credentials, plus every IPv4 literal anywhere (whole values like ProxyHost
# "34.43.46.91", or embedded in a payload such as an X-Forwarded-For spoof).
# Hostnames in Payloads/SNI/ProxyHost are kept (same convention as the
# TunnelDoom batch); v2rayjson links embed UUIDs, so they are redacted.
REDACT_SERVER_FIELDS = ["ServerIPHost", "ServerHTTPHost", "Username", "Password",
                        "PrivateKey", "OpenVPNCertificate"]
REDACT_NESTED_FIELDS = ["UUID", "DNSTTKey", "DNSTTNS"]
REDACT_TWEAK_FIELDS = ["v2rayjson"]

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _scrub_ips(obj):
    """Replace any IPv4 literal in any string (whole value or embedded in
    a payload) with [REDACTED], so the shareable catalog has no IPs at all."""
    if isinstance(obj, dict):
        return {k: _scrub_ips(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub_ips(v) for v in obj]
    if isinstance(obj, str):
        return _IPV4_RE.sub(REDACTED, obj)
    return obj


def redact_catalog(doc):
    """Deep copy of a decrypted catalog with IPs/credentials replaced."""
    out = json.loads(json.dumps(doc, ensure_ascii=False))
    for s in out.get("Servers", []):
        for k in REDACT_SERVER_FIELDS:
            if isinstance(s.get(k), str) and s[k]:
                s[k] = REDACTED
        for nk in ("V2ray", "SlowDNS", "UDP"):
            sub = s.get(nk)
            if isinstance(sub, dict):
                for k in REDACT_NESTED_FIELDS:
                    if isinstance(sub.get(k), str) and sub[k]:
                        sub[k] = REDACTED
    for t in out.get("Tweaks", []):
        for k in REDACT_TWEAK_FIELDS:
            if isinstance(t.get(k), str) and t[k]:
                t[k] = REDACTED
    return _scrub_ips(out)


# ---------------------------------------------------------------- .asl files
ASL_MARKER = "ASL TUNNEL VPN"
ASL_JSON_FIELDS = ["ExpireDate", "RootBlock", "DeviceID", "MobileData", "PSInstall",
                   "isMsg", "CFGMessage", "NoobDev", "SNIHost", "Payload", "ProxyHost",
                   "ProxyPort", "useCloudFront", "DNSHost", "UDPhost", "UDPobfs",
                   "UDPauth", "UDPDownMbps", "UDPUpMbps", "UDPPort", "UDPMode",
                   "v2rayConfig", "v2raySni", "isUri", "PreserveSNI", "TLS",
                   "WireGuardConfig", "TunnelType", "Server", "isPassON", "MyPass"]


def _decrypt_custom_server_doc(doc):
    """LCl.b builds a catalog-style server object whose string fields are
    Lln.M-encrypted (AES/CFB, same scheme as Lln.H decrypts). Apply
    field_decrypt to exactly those fields - never to the Q()-style config
    fields, where short plaintext values like ProxyPort "80" would otherwise
    false-positive as Base64."""
    for k in SERVER_STR_FIELDS:
        if isinstance(doc.get(k), str) and doc[k]:
            doc[k] = field_decrypt(doc[k])
    for nk in ("V2ray", "SlowDNS", "UDP"):
        sub = doc.get(nk)
        if isinstance(sub, dict):
            for k in SERVER_NESTED_STR_FIELDS:
                if isinstance(sub.get(k), str) and sub[k]:
                    sub[k] = field_decrypt(sub[k])
    return doc


def decode_asl_text(text):
    """Decode .asl file content or a pasted CONFIG KEY.
    Returns (config_dict, notes). Raises ValueError on bad input."""
    text = text.strip()
    if not text:
        raise ValueError("empty input")
    plain = nbdecrypt_mode1(text)
    try:
        s = plain.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError("Nbdecrypt output is not UTF-8: %s" % e)
    if not s.startswith(ASL_MARKER):
        raise ValueError("Invalid config: does not belong to this app "
                         "(plaintext does not start with %r)" % ASL_MARKER)
    doc = json.loads(s[len(ASL_MARKER):])
    # Two shapes exist: the Q() import config (plaintext fields) and the
    # LCl.b custom-server object (Lln.M-encrypted string fields). Tell them
    # apart by keys that only the server shape has (ProxyPort is shared by
    # both shapes, so it is NOT a discriminator); only the server shape
    # gets field decryption.
    server_only_keys = {"ServerIPHost", "ServerHTTPHost", "Username", "Password",
                        "OpenVPNCertificate", "PrivateKey", "TCPPort", "SSLPort",
                        "OpenVPNUDPPort", "DropBear", "Name", "Flag", "Info",
                        "NoobLevel", "Protocol", "AutoLogin", "ServerDnsMode",
                        "useCustomOvpnCert", "isKeyAuth", "overrideProxyPorts",
                        "isCustomServer", "CloudFrontDNS", "V2ray", "SlowDNS", "UDP"}
    if any(k in doc for k in server_only_keys):
        doc = _decrypt_custom_server_doc(doc)
    notes = []
    exp = doc.get("ExpireDate")
    if isinstance(exp, (int, float)) and exp:
        import datetime
        notes.append("ExpireDate: %s (epoch ms %s)" % (
            datetime.datetime.fromtimestamp(exp / 1000, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), exp))
    elif exp == 0:
        notes.append("ExpireDate: 0 (no expiry)")
    dev = doc.get("DeviceID")
    notes.append("DeviceID allowlist: %s" % ("empty (any device)" if not dev else dev))
    if doc.get("RootBlock"):
        notes.append("RootBlock: true (app refuses rooted devices)")
    if doc.get("PSInstall"):
        notes.append("PSInstall: true (requires Play install)")
    if doc.get("isPassON"):
        notes.append("isPassON: true (password required; field MyPass present: %s)"
                     % ("yes" if doc.get("MyPass") else "no"))
    return doc, notes


def decode_asl_file(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    # d0() reads the whole file as one string, lines concatenated.
    text = "".join(text.splitlines())
    return decode_asl_text(text)


def encode_asl(doc):
    """Build a synthetic .asl payload (Nbencrypt mode 1) for round-trip tests."""
    if isinstance(doc, dict):
        body = json.dumps(doc, ensure_ascii=False)
    else:
        body = str(doc)
    return nbencrypt_mode1((ASL_MARKER + body).encode("utf-8"))


# ---------------------------------------------------------------- .ovpn
def read_ovpn(path):
    """Standard OpenVPN profile: plain text, no app-specific crypto."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    keys = [ln.strip() for ln in text.splitlines()
            if ln.strip() and not ln.strip().startswith("#")]
    return text, keys


# ---------------------------------------------------------------- CLI
def main(argv):
    cmd = argv[1] if len(argv) > 1 else "catalog"
    if cmd == "catalog":
        out_path = argv[2] if len(argv) > 2 else "catalogo-completo.json"
        doc = fetch_and_decrypt()
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
        print("LIVE catalog written to %s" % out_path)
        print(json.dumps(catalog_stats(doc), indent=1, ensure_ascii=False))
        return 0
    if cmd == "asl":
        if len(argv) < 3:
            print("usage: asltunnel.py asl <file.asl|CONFIG KEY text>", file=sys.stderr)
            return 2
        arg = argv[2]
        if os.path.isfile(arg):
            doc, notes = decode_asl_file(arg)
        else:
            doc, notes = decode_asl_text(arg)
        print(json.dumps(doc, indent=1, ensure_ascii=False))
        for n in notes:
            print("# " + n, file=sys.stderr)
        return 0
    if cmd == "asl-encode":
        if len(argv) < 4:
            print("usage: asltunnel.py asl-encode <config.json> <out.asl>", file=sys.stderr)
            return 2
        with open(argv[2], "r", encoding="utf-8") as f:
            doc = json.load(f)
        with open(argv[3], "w", encoding="utf-8") as f:
            f.write(encode_asl(doc))
        print("wrote %s" % argv[3])
        return 0
    if cmd == "ovpn":
        if len(argv) < 3:
            print("usage: asltunnel.py ovpn <file.ovpn>", file=sys.stderr)
            return 2
        text, keys = read_ovpn(argv[2])
        print("lines: %d, directives: %d" % (len(text.splitlines()), len(keys)))
        for ln in keys[:20]:
            print("  " + ln)
        return 0
    print("unknown command: %s" % cmd, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
