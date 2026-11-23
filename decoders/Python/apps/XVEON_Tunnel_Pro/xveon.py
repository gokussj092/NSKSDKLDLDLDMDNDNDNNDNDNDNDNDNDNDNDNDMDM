#!/usr/bin/env python3
"""XVEON Tunnel Pro (com.xveon.tunnelpro, 8.1/code 8) - .xveon/.xvn file and
xveontunnel:// / xveon:// / xvn:// text-link decoder + encoder.

Format (reverse-engineered from classes.dex, Lb0.IIII / Lb0.v / Lb1.lI):

    xveontunnel://XVN1:<flag>:<b64 salt16>:<b64 iv12>:<b64 ciphertext>
    flag: "0" = unlocked (no password), "1" = creator-locked (password required)

    key   = PBKDF2-HMAC-SHA256(passphrase, salt, 10000 iterations, 32 bytes)
    passphrase = "XveonV7_SshVpn_" + "UltraLite_2026_" + "#Key!" + "::"
                 + (password[:15] if locked else "")
            (the three fixed parts are Lb1 string constants deobfuscated
             from the DEX; see _deobfuscate() and METHOD notes below)
    cipher = AES-256-GCM, IV = 12 random bytes, tag 128 bit,
             AAD = "XVN1:<flag>" (UTF-8)
    plaintext = GZIP(JSON envelope, UTF-8), max 512 KiB after decompression

    Envelope JSON (v=2): {"v":2, "mode":"ssh", "creator":..., "locked":bool,
        "hideSsh":bool, "hidePayload":bool, "hideProxy":bool, "hideSni":bool,
        "hideSlowDns":bool, "hideSlowDnsDns":bool, "hideSlowDnsNs":bool,
        "hideSlowDnsPubkey":bool, "hideOvpnConfig":bool,
        "expiryTimestamp":0, "creatorNote":"", "profiles":[ {...} ]}
    The app imports only profiles[0] (Lb0.IIII uses Math.min(len, 1));
    this decoder returns ALL profiles present in the envelope.
    A .xveon/.xvn file contains exactly the same 5-part string (optionally
    prefixed with xveontunnel://); see Lb0.I0O0 / Lb0.Il11.

    Profile JSON fields (Lf6.lI / Lb0.l1I1): name, mode
    (ssh|slowdns|xray|xray_slowdns|v2ray|openvpn|ovpn|udp_custom|...),
    sshHost, sshPort, sshUsername, sshPassword (or sshPasswordEnc),
    sshPrivateKey, sshTunnelEngine (hev_socks5/...), enableUdpgw, udpgwHost,
    udpgwPort, enablePayload, payload, enableProxy, proxyHost, proxyPort,
    proxyUser, proxyPass, enableSni, sniHostname, forcingTls, enableSlowDns,
    slowDnsServer, slowDnsNameserver, slowDnsPublicKey, slowDnsTransport,
    slowDnsQtype, slowDnsMtu, enableUdpCustom, udpCustomPortRange,
    enableOvpn, ovpnConfigFileName, ovpnConfigContent, enableXray,
    xrayProtocol, xrayTransport, xrayCipher, xrayWsPath, xrayWsHost,
    xrayFlow, xrayMux, xrayAllowInsecure, primaryDns, secondaryDns,
    creatorName, creatorNote, expiryTimestamp, lockedByCreator, hide* flags,
    subscriptionId, selectedPackages, ...

    There is NO built-in server catalog in this app: no catalog URL, no
    ads/billing SDK and no premium tier exist anywhere in the DEX strings
    or resources. Server lists only arrive as user-supplied V2Ray/Xray
    subscription URLs (vmess/vless/trojan/ss/socks lines). See
    xveon_catalog.py for that mechanism.

Usage:
    python3 xveon.py decode <uri-or-file> [--password PW] [--redact]
    python3 xveon.py encode <envelope.json> [--password PW] [--out FILE.xveon]
    python3 xveon.py --self-test
"""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import re
import secrets
import sys

MAGIC = "XVN1"
KDF_ITERATIONS = 10000
KDF_DKLEN = 32
# Fixed passphrase parts, deobfuscated from Lb1 via Lb1.lI (see _deobfuscate):
#   Lb1.o  key 1519467633 -> "XveonV7_SshVpn_"
#   Lb1.O  key 1047835293 -> "UltraLite_2026_"
#   Lb1.Il key 1908952595 -> "#Key!"
#   Lb1.lI key  528721003 -> "XVN1"
#   Lb1.ll key  698673175 -> "AES/GCM/NoPadding"
#   Lb1.Io key 1866144212 -> "PBKDF2WithHmacSHA256"
#   Lb1.lo key  479769461 -> "AES"
_PASSPHRASE_PREFIX = "XveonV7_SshVpn_" + "UltraLite_2026_" + "#Key!" + "::"

# Obfuscated byte arrays from Lb1.<clinit>, as stored in the DEX.
_LB1_ARRAYS = {
    "o":  [-21, -113, 100, -113, 26, 59, -110, 48, 71, 118, 47, -26, 72, -90, -40],
    "O":  [-83, 115, -17, 111, -81, 74, 91, 100, 56, -102, -127, -31, 87, 96, 16],
    "Il": [112, 1, -32, 7, 8],
    "lI": [71, 90, 77, 65],
    "ll": [68, 104, 101, -7, 36, 124, -29, 27, -21, 36, 9, 81, -102, 24, -48, -84, 124],
    "Io": [108, -113, 76, 17, 7, 118, -40, 108, -123, 95, -63, -105, 70, 20, 6, -40, 125, 83, -105, -112],
    "lo": [-119, 120, 36],
}


def _s32(x):
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x >= 0x80000000 else x


def _deobfuscate(data, key):
    """Faithful port of Lb1.lI(byte[], int) -> String.

    Lb1.Il() is always 0: ((l|1)+1)*(l|1) is even, &1 == 0, for any l.
    Lb1.O(k) is always True: ((k^l)|1) is odd, odd^2 & 3 == 1.
    Lb1.o(k) is always False: ((k^l)&-2) is even, even^2 & 3 == 0.
    So the state machine always takes the 16 -> 32 -> 16 path below.
    """
    state = ((key >> 8) & 0xFF) ^ 0
    out = bytearray()
    for i, b in enumerate(data):
        t = _s32(i * 73244475 ^ key)
        t = _s32(_s32(t ^ (t >> 16)) * 73244475)
        u = ((((t >> 16) ^ t) ^ (i * 61)) & 0xFF) ^ b
        v = (state ^ u) & 0xFF
        r = (i + key) & 7
        if r:
            v = ((v << (8 - r)) & 0xFF) | (v >> r)
        out.append(v)
        state = b
    return bytes(out).decode("utf-8")


def deobfuscated_constants():
    """Return the Lb1 string constants, deobfuscated at runtime."""
    return {name: _deobfuscate(bytes(x & 0xFF for x in arr), key)
            for name, (arr, key) in {
                "o": (_LB1_ARRAYS["o"], 1519467633),
                "O": (_LB1_ARRAYS["O"], 1047835293),
                "Il": (_LB1_ARRAYS["Il"], 1908952595),
                "lI": (_LB1_ARRAYS["lI"], 528721003),
                "ll": (_LB1_ARRAYS["ll"], 698673175),
                "Io": (_LB1_ARRAYS["Io"], 1866144212),
                "lo": (_LB1_ARRAYS["lo"], 479769461),
            }.items()}


class XveonError(Exception):
    pass


class NeedsPassword(XveonError):
    """The link/file is creator-locked (flag 1) and no password was given."""


def _derive_key(password, salt, locked):
    pw = (password or "")[:15] if locked else ""
    passphrase = _PASSPHRASE_PREFIX + pw
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"),
                               salt, KDF_ITERATIONS, dklen=KDF_DKLEN)


def _aes_gcm_decrypt(key, iv, ct, aad):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).decrypt(iv, ct, aad)
    except ImportError:
        pass
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ct[:-16], ct[-16:])


def _aes_gcm_encrypt(key, iv, pt, aad):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).encrypt(iv, pt, aad)
    except ImportError:
        pass
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(pt)
    return ct + tag


def _extract_body(text):
    """Lb0.Il11: strip whitespace, strip a known URI prefix, take 1st token."""
    text = text.strip()
    if not text:
        return None
    low = text.lower()
    for prefix in ("xveontunnel://", "xveon://", "xvn://"):
        if low.startswith(prefix):
            text = text[len(prefix):]
            break
    if text.startswith(MAGIC + ":"):
        return text.split()[0]
    # bare 5-part string possibly surrounded by other text: first token
    for token in re.split(r"\s+", text):
        if token.startswith(MAGIC + ":"):
            return token
    return text.split()[0] if text.split() else None


def decrypt_text(text, password=""):
    """Decrypt an xveontunnel:// URI or a bare XVN1:... string (or .xveon
    file content). Returns the envelope dict. Raises NeedsPassword /
    XveonError."""
    body = _extract_body(text)
    if body is None:
        raise XveonError("empty input")
    parts = body.split(":")
    if len(parts) != 5 or parts[0] != MAGIC:
        raise XveonError("Invalid .xveon or xveontunnel:// configuration format")
    flag = parts[1]
    if flag not in ("0", "1"):
        raise XveonError("Invalid .xveon or xveontunnel:// configuration format")
    locked = flag == "1"
    if locked and not password:
        raise NeedsPassword("creator-locked configuration: password required")
    try:
        salt = base64.b64decode(parts[2])
        iv = base64.b64decode(parts[3])
        ct = base64.b64decode(parts[4])
    except Exception as exc:
        raise XveonError("Failed to read .xveon file: %s" % exc)
    if len(salt) != 16 or len(iv) != 12:
        raise XveonError("Failed to read .xveon file: bad salt/IV length")
    key = _derive_key(password, salt, locked)
    aad = ("%s:%s" % (MAGIC, flag)).encode("utf-8")
    try:
        gz = _aes_gcm_decrypt(key, iv, ct, aad)
    except Exception as exc:
        raise XveonError("Failed to read .xveon file: %s (bad password or "
                         "tampered data)" % exc)
    try:
        raw = gzip.decompress(gz)
    except Exception as exc:
        raise XveonError("Failed to read .xveon file: gzip error: %s" % exc)
    if len(raw) > 512 * 1024:
        raise XveonError("Decompressed payload exceeds limit")
    try:
        env = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise XveonError("Failed to read .xveon file: bad JSON: %s" % exc)
    if not isinstance(env, dict) or "profiles" not in env:
        raise XveonError("No profiles found in .xveon file")
    if not env["profiles"]:
        raise XveonError("No valid profiles in .xveon file")
    return env


def encrypt_envelope(envelope, password=""):
    """Encrypt an envelope dict -> xveontunnel:// URI (Lb0.v mirror)."""
    locked = bool(password)
    pw = (password or "")[:15] if locked else ""
    raw = json.dumps(envelope, ensure_ascii=False,
                     separators=(",", ":")).encode("utf-8")
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(raw)
    gzipped = buf.getvalue()
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(12)
    key = _derive_key(pw, salt, locked)
    flag = "1" if locked else "0"
    aad = ("%s:%s" % (MAGIC, flag)).encode("utf-8")
    ct = _aes_gcm_encrypt(key, iv, gzipped, aad)
    b64 = lambda b: base64.b64encode(b).decode("ascii")
    body = ":".join([MAGIC, flag, b64(salt), b64(iv), b64(ct)])
    return "xveontunnel://" + body


def decode_file(path, password=""):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return decrypt_text(fh.read(), password=password)


def encode_file(envelope, path, password=""):
    uri = encrypt_envelope(envelope, password=password)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(uri)
    return uri


# ---------------------------------------------------------------- summary

def summarize_profile(p):
    """Normalized view of one profile (raw JSON stays authoritative)."""
    mode = str(p.get("mode", "")).lower()
    out = {"name": p.get("name"), "mode": mode}
    if mode == "ssh" or p.get("sshHost"):
        out["ssh"] = {"host": p.get("sshHost"), "port": p.get("sshPort"),
                      "username": p.get("sshUsername"),
                      "password": p.get("sshPassword") or p.get("sshPasswordEnc"),
                      "engine": p.get("sshTunnelEngine"),
                      "simple_mode": p.get("sshSimpleMode"),
                      "udpgw": ((p.get("udpgwHost"), p.get("udpgwPort"))
                                if p.get("enableUdpgw") else None)}
    if p.get("enablePayload"):
        out["payload"] = p.get("payload")
    if p.get("enableProxy"):
        out["proxy"] = {"host": p.get("proxyHost"), "port": p.get("proxyPort"),
                        "user": p.get("proxyUser"), "pass": p.get("proxyPass")}
    if p.get("enableSni"):
        out["sni"] = p.get("sniHostname")
    if p.get("enableSlowDns"):
        out["slowdns"] = {"server": p.get("slowDnsServer"),
                          "nameserver": p.get("slowDnsNameserver"),
                          "transport": p.get("slowDnsTransport"),
                          "qtype": p.get("slowDnsQtype")}
    if p.get("enableXray"):
        out["xray"] = {"protocol": p.get("xrayProtocol"),
                       "transport": p.get("xrayTransport"),
                       "cipher": p.get("xrayCipher"),
                       "ws_path": p.get("xrayWsPath"),
                       "ws_host": p.get("xrayWsHost"),
                       "flow": p.get("xrayFlow"),
                       "sni": p.get("xraySni")}
    if p.get("enableOvpn"):
        out["ovpn"] = {"file": p.get("ovpnConfigFileName")}
    if p.get("enableUdpCustom"):
        out["udp_custom"] = {"port_range": p.get("udpCustomPortRange")}
    out["dns"] = {"primary": p.get("primaryDns"),
                  "secondary": p.get("secondaryDns")}
    out["tls"] = p.get("forcingTls")
    out["creator"] = p.get("creatorName")
    out["expiry"] = p.get("expiryTimestamp")
    return out


def summarize(envelope):
    return {"format": MAGIC, "version": envelope.get("v"),
            "mode": envelope.get("mode"),
            "creator": envelope.get("creator"),
            "locked": envelope.get("locked"),
            "expiryTimestamp": envelope.get("expiryTimestamp"),
            "creatorNote": envelope.get("creatorNote"),
            "profiles": [summarize_profile(p)
                         for p in envelope.get("profiles", [])]}


def _redact(obj):
    if isinstance(obj, dict):
        return {k: ("****" if k.lower() in ("password", "pass", "proxypass",
                                            "sshpassword", "sshpasswordenc",
                                            "sshprivatekey", "sshprivatekeyenc",
                                            "sshprivatekeypassphrase",
                                            "sshprivatekeypassphraseenc",
                                            "slowdnspublickey",
                                            "slowdnspublickeyenc",
                                            "ovpnconfigcontent",
                                            "ovpnconfigcontentenc")
                     and v else _redact(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact(x) for x in obj]
    return obj


# ---------------------------------------------------------------- self-test

def self_test():
    ok = []
    consts = deobfuscated_constants()
    assert consts["lI"] == "XVN1", consts
    assert consts["ll"] == "AES/GCM/NoPadding", consts
    assert consts["Io"] == "PBKDF2WithHmacSHA256", consts
    assert consts["lo"] == "AES", consts
    assert consts["o"] + consts["O"] + consts["Il"] == \
        "XveonV7_SshVpn_UltraLite_2026_#Key!", consts
    ok.append("Lb1.lI deobfuscation constants OK")
    env = {"v": 2, "mode": "ssh", "creator": "SelfTest", "locked": False,
           "hideSsh": False, "hidePayload": True, "hideProxy": True,
           "hideSni": True, "expiryTimestamp": 0, "creatorNote": "",
           "profiles": [{"name": "TEST SSH", "mode": "ssh",
                         "sshSimpleMode": True, "sshHost": "example.test",
                         "sshPort": 443, "sshUsername": "user1",
                         "sshPassword": "pass1",
                         "sshTunnelEngine": "hev_socks5",
                         "enableUdpgw": True, "udpgwHost": "127.0.0.1",
                         "udpgwPort": 7300, "enablePayload": True,
                         "payload": "GET / HTTP/1.1[crlf]Host: [host][crlf]"
                                    "Upgrade: websocket[crlf][crlf]",
                         "enableProxy": True, "proxyHost": "1.2.3.4",
                         "proxyPort": 8080, "enableSni": True,
                         "sniHostname": "[host]", "forcingTls": "TLS_1_3",
                         "primaryDns": "1.1.1.1", "secondaryDns": "1.0.0.1"},
                        {"name": "TEST XRAY", "mode": "xray",
                         "enableXray": True, "xrayProtocol": "VMESS",
                         "xrayTransport": "ws", "xrayWsPath": "/path",
                         "xrayWsHost": "ws.example.test"}]}
    uri = encrypt_envelope(env)
    assert uri.startswith("xveontunnel://XVN1:0:"), uri[:40]
    back = decrypt_text(uri)
    assert back == env, "round-trip mismatch"
    ok.append("unlocked round-trip OK (2 profiles, ssh + xray)")
    # file round-trip (.xveon content == bare string, no prefix required)
    body = uri[len("xveontunnel://"):]
    back2 = decrypt_text(body)
    assert back2 == env
    ok.append("bare 5-part string (file content) OK")
    # locked round-trip, password truncated to 15 chars like the app
    uri_locked = encrypt_envelope(env, password="0123456789ABCDEF-longer")
    assert uri_locked.split(":")[2] == "1"  # "xveontunnel://XVN1:1:..."
    try:
        decrypt_text(uri_locked)
        raise AssertionError("locked link opened without password")
    except NeedsPassword:
        pass
    back3 = decrypt_text(uri_locked, password="0123456789ABCDEF-longer")
    assert back3 == env
    try:
        decrypt_text(uri_locked, password="wrong-password")
        raise AssertionError("wrong password accepted")
    except XveonError:
        pass
    ok.append("locked round-trip OK (password truncated to 15 chars; "
              "wrong password rejected)")
    # tamper: flipping a ciphertext byte must fail GCM auth
    parts = uri.split(":")
    tampered = parts[:4] + [parts[4][:-4] + ("AAAA" if parts[4][-4:] != "AAAA"
                                            else "BBBB")]
    try:
        decrypt_text(":".join(tampered))
        raise AssertionError("tampered ciphertext accepted")
    except XveonError:
        pass
    ok.append("GCM tamper detection OK")
    s = summarize(env)
    assert s["profiles"][0]["ssh"]["host"] == "example.test"
    assert s["profiles"][0]["proxy"]["host"] == "1.2.3.4"
    assert s["profiles"][1]["xray"]["protocol"] == "VMESS"
    ok.append("profile summary OK")
    print("xveon.py --self-test: %d checks passed" % len(ok))
    for line in ok:
        print("  [OK] " + line)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="XVEON Tunnel Pro .xveon / "
                                            "xveontunnel:// decoder")
    ap.add_argument("--self-test", action="store_true",
                    help="run built-in verification checks")
    sub = ap.add_subparsers(dest="cmd")
    d = sub.add_parser("decode", help="decrypt a URI or .xveon/.xvn file")
    d.add_argument("input", help="xveontunnel:// URI, bare XVN1:... string, "
                                 "or path to a .xveon/.xvn file")
    d.add_argument("--password", default="", help="password for locked (flag 1) configs")
    d.add_argument("--summary", action="store_true",
                   help="print normalized profile summary instead of raw JSON")
    d.add_argument("--redact", action="store_true",
                   help="mask passwords/private keys in the output")
    e = sub.add_parser("encode", help="encrypt an envelope JSON to a URI/file")
    e.add_argument("json_file", help="envelope JSON file")
    e.add_argument("--password", default="", help="creator-lock password (max 15 chars used)")
    e.add_argument("--out", help="write the bare string to this .xveon file")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.cmd == "decode":
        text = args.input
        if os.path.isfile(text):
            with open(text, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        try:
            env = decrypt_text(text, password=args.password)
        except NeedsPassword as exc:
            print("ERROR: %s" % exc, file=sys.stderr)
            return 2
        except XveonError as exc:
            print("ERROR: %s" % exc, file=sys.stderr)
            return 1
        out = summarize(env) if args.summary else env
        if args.redact:
            out = _redact(out)
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "encode":
        with open(args.json_file, "r", encoding="utf-8") as fh:
            env = json.load(fh)
        uri = encrypt_envelope(env, password=args.password)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(uri[len("xveontunnel://"):])
            print("wrote %s" % args.out)
        print(uri)
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
