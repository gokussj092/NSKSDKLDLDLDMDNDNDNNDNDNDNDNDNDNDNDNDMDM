#!/usr/bin/env python3
"""Sentinel Tunnel 4.0.0 (online.zarray.sentineltunnel) — .st file + text-link decoder.

Reversed from Sentinel_Tunnel_4.0.0 (versionCode 64), classes5.dex / W3/e (ConfigCrypto)
and W3/h (Xray link parser). Verified by round-trip: files built by encode_st()
here decode back byte-identically through the app's own algorithm, for all 7
config types, with and without a password.

.st FILE FORMAT (export W3/e.p / import W3/e.e)
-----------------------------------------------
  plain  = b"STCF" + bytes([1]) + <ConfigExport JSON, UTF-8>
  xored  = bytes(plain[i] ^ KEY[i % 32])            KEY = b"SENTINEL_TUNNEL_CONFIG_KEY_V1_20"
  file   = xored with, for each 32-byte block start i (0, 32, 64, ...):
           if i + 16 < len: reverse(file[i : min(i+16, len)])
  import = reverse the same chunks first, then XOR (W3/e.b).

ConfigExport JSON fields (Gson, field names as-is):
  version (default 1), appSignature "SENTINEL_TUNNEL_CONFIG_V1",
  configType: CUSTOM_SSH | CUSTOM_SSL | CUSTOM_SSL_OVPN | CUSTOM_OPENVPN |
              CUSTOM_DNSTT | CUSTOM_HYSTERIA | CUSTOM_XRAY,
  name, isLocked, isPasswordProtected, passwordHash, salt, notes,
  notesFormat (PLAIN...), createdAt (ms), expiresAt (null|ms),
  configData: {iv, data, hmac, keySalt}  (all Base64 NO_WRAP)

PAYLOAD ENCRYPTION (W3/e.f / W3/e.a)
-------------------------------------
  AES-256-GCM, random 12-byte IV, 128-bit tag appended to the ciphertext.
  HMAC-SHA256(key, iv || ciphertext) stored as `hmac`; verified before decrypt.
  Key derivation:
    * no password : key = SHA-256(KEY || base64decode(configData.keySalt))
                    (W3/e.c ; KEY is the same 32-byte STCF key above)
    * with password: key = PBKDF2-HmacSHA256(password, salt, 100000, 256-bit)
                    (W3/e.d ; salt = base64decode(ConfigExport.salt),
                     which equals base64decode(configData.keySalt))
  NOTE (app bug, verified in LT3/D2 export flow): the stored `passwordHash` is
  PBKDF2(password, salt2) with a SECOND random salt that is never stored, so the
  app's own password check W3/e.q() can never succeed for a password-protected
  export. The DATA key above is still correct, so this decoder ignores
  `passwordHash` and decrypts with the password directly (HMAC proves the key).

TEXT LINKS (W3/h.b — Xray custom-config import, pasted as "rawJson")
--------------------------------------------------------------------
  vless://<uuid>@<host>:<port>?params#name
  vmess://<base64-json>
  trojan://<password>@<host>:<port>?params#name
  ss://<base64-method:password>@<host>:<port>#name   (or fully base64-encoded)
  {raw Xray JSON}  (outbounds[0] -> CustomXrayParams, W3/h.d)
  These are standard Xray links; the app has no proprietary URI scheme.

Usage:
  sentinel_tunnel.py file.st [--password PW] [--json]     decode a .st file
  sentinel_tunnel.py --encode export.json [--password PW]  build a .st file
  sentinel_tunnel.py --link "vless://..."                  parse a text link
  sentinel_tunnel.py --selftest                            round-trip all types
"""
import argparse
import base64
import hashlib
import hmac as hmac_mod
import json
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ST_KEY = b"SENTINEL_TUNNEL_CONFIG_KEY_V1_20"  # W3/e.a, 32 bytes
APP_SIGNATURE = "SENTINEL_TUNNEL_CONFIG_V1"
MAGIC = b"STCF"

CONFIG_TYPES = ["CUSTOM_SSH", "CUSTOM_SSL", "CUSTOM_SSL_OVPN", "CUSTOM_OPENVPN",
                "CUSTOM_DNSTT", "CUSTOM_HYSTERIA", "CUSTOM_XRAY"]


def b64d(s):
    return base64.b64decode(s)


def b64e(b):
    return base64.b64encode(b).decode("ascii")


# ---------------------------------------------------------------- .st layer
def _reverse_chunks(buf):
    """Reverse the first 16 bytes of every 32-byte block (if i+16 < len)."""
    lst = bytearray(buf)
    n = len(lst)
    last = ((n - 1) // 32) * 32 if n else -1
    i = 0
    while True:
        if i + 16 < n:
            end = min(i + 16, n)
            lst[i:end] = lst[i:end][::-1]
        if i == last:
            break
        i += 32
    return bytes(lst)


def st_deobfuscate(data):
    """W3/e.b: reverse chunks, then XOR with ST_KEY[i % 32]."""
    rev = _reverse_chunks(data)
    return bytes(b ^ ST_KEY[i % 32] for i, b in enumerate(rev))


def st_obfuscate(plain):
    """W3/e.p: XOR, then reverse chunks (exact inverse of st_deobfuscate)."""
    xored = bytes(b ^ ST_KEY[i % 32] for i, b in enumerate(plain))
    return _reverse_chunks(xored)


def parse_st(data):
    """W3/e.e: return the ConfigExport dict, or None if not a valid .st file."""
    try:
        plain = st_deobfuscate(data)
    except Exception:
        return None
    if len(plain) < 5 or plain[0:4] != MAGIC or plain[4] != 1:
        return None
    try:
        export = json.loads(plain[5:].decode("utf-8"))
    except Exception:
        return None
    if export.get("appSignature") != APP_SIGNATURE:
        return None
    return export


def _pbkdf2(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=100000)
    return kdf.derive(password.encode("utf-8"))


def _no_password_key(key_salt_b64):
    return hashlib.sha256(ST_KEY + b64d(key_salt_b64)).digest()


def decrypt_payload(enc, key):
    """W3/e.a: verify HMAC-SHA256(iv||ct), then AES-256-GCM decrypt."""
    iv = b64d(enc["iv"])
    ct = b64d(enc["data"])
    want_hmac = b64d(enc["hmac"])
    got_hmac = hmac_mod.new(key, iv + ct, hashlib.sha256).digest()
    if not hmac_mod.compare_digest(want_hmac, got_hmac):
        raise ValueError("HMAC verification failed - data may be tampered")
    return AESGCM(key).decrypt(iv, ct, None).decode("utf-8")


def encrypt_payload(plain_json, key, key_salt_b64):
    """W3/e.f: random 12-byte IV, AES-256-GCM, HMAC over iv||ct."""
    import os
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, plain_json.encode("utf-8"), None)
    tag_hmac = hmac_mod.new(key, iv + ct, hashlib.sha256).digest()
    return {"iv": b64e(iv), "data": b64e(ct), "hmac": b64e(tag_hmac),
            "keySalt": key_salt_b64}


def decode_st_file(data, password=None):
    """Full .st decode. Returns dict with export metadata + decrypted payload."""
    export = parse_st(data)
    if export is None:
        raise ValueError("not a valid Sentinel Tunnel .st file "
                         "(bad STCF magic, version or signature)")
    enc = export["configData"]
    keys_tried = []
    candidates = []
    if password is not None:
        for salt_b64 in (export.get("salt"), enc.get("keySalt")):
            if salt_b64:
                candidates.append(("pbkdf2(password, export/keySalt)",
                                   _pbkdf2(password, b64d(salt_b64))))
    else:
        candidates.append(("sha256(ST_KEY||keySalt)",
                           _no_password_key(enc.get("keySalt", ""))))
    last_err = None
    for name, key in candidates:
        keys_tried.append(name)
        try:
            payload = decrypt_payload(enc, key)
            return {"export": export, "payload": json.loads(payload),
                    "payload_raw": payload, "key_method": name,
                    "keys_tried": keys_tried}
        except Exception as ex:  # noqa: BLE001 - try next candidate
            last_err = ex
    raise ValueError("payload decryption failed (%s); tried: %s"
                     % (last_err, "; ".join(keys_tried)))


def encode_st_file(export, payload, password=None):
    """Build a .st file exactly like the app export (W3/e.p + g..m + D2)."""
    import os
    payload_json = json.dumps(payload, ensure_ascii=False,
                              separators=(",", ":"))
    if password is not None:
        salt1 = os.urandom(32)
        key = _pbkdf2(password, salt1)
        key_salt_b64 = b64e(salt1)
        # App bug reproduced faithfully: passwordHash uses a second random
        # salt that is discarded, so q() can never verify it. Kept here so
        # our files are byte-identical in structure to the app's own exports.
        salt2 = os.urandom(32)
        pw_hash = b64e(_pbkdf2(password, salt2))
        export = dict(export)
        export["isPasswordProtected"] = True
        export["passwordHash"] = pw_hash
        export["salt"] = key_salt_b64
    else:
        salt1 = os.urandom(32)
        key = hashlib.sha256(ST_KEY + salt1).digest()
        key_salt_b64 = b64e(salt1)
        export = dict(export)
        export["isPasswordProtected"] = False
        export["passwordHash"] = None
        export["salt"] = None
    export.setdefault("version", 1)
    export.setdefault("appSignature", APP_SIGNATURE)
    export.setdefault("configType", "CUSTOM_SSH")
    export.setdefault("name", "Sentinel Tunnel config")
    export["configData"] = encrypt_payload(payload_json, key, key_salt_b64)
    plain = MAGIC + bytes([1]) + json.dumps(
        export, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return st_obfuscate(plain)


# ------------------------------------------------------------- text links
def _b64_json_or_text(s):
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad).decode("utf-8")
    except Exception:
        try:
            return base64.b64decode(s + pad).decode("utf-8")
        except Exception:
            return None


def _query_params(qs):
    out = {}
    if not qs:
        return out
    from urllib.parse import unquote, parse_qsl
    for k, v in parse_qsl(qs, keep_blank_values=True):
        out[unquote(k)] = unquote(v)
    return out


def _split_host_port(hostport):
    if hostport.startswith("["):
        end = hostport.find("]")
        host = hostport[1:end]
        rest = hostport[end + 1:]
        port = 443
        if rest.startswith(":"):
            try:
                port = int(rest[1:])
            except ValueError:
                pass
        return host, port
    if ":" in hostport:
        host, _, port = hostport.rpartition(":")
        try:
            return host, int(port)
        except ValueError:
            return host, 443
    return hostport, 443


def _base_xray(protocol):
    return {"inputMode": "VISUAL", "rawJson": None, "protocol": protocol,
            "serverHost": "", "serverPort": 443, "uuid": None, "alterId": 0,
            "encryption": None, "flow": None, "ssMethod": None,
            "ssPassword": None, "network": None, "wsHost": None,
            "wsPath": None, "grpcServiceName": None, "grpcMultiMode": False,
            "security": None, "sni": None, "fingerprint": None, "alpn": None,
            "allowInsecure": False, "realityPublicKey": None,
            "realityShortId": None, "realitySpiderX": None,
            "isLocked": False}


def parse_xray_link(text):
    """Mirror of W3/h.b (+ d for raw JSON). Returns CustomXrayParams dict."""
    s = text.strip()
    low = s.lower()
    if low.startswith("vless://"):
        body = s[len("vless://"):]
        main, _, _frag = body.partition("#")
        userinfo, _, hostquery = main.partition("@")
        hostport, _, qs = hostquery.partition("?")
        host, port = _split_host_port(hostport)
        p = _query_params(qs)
        out = _base_xray("VLESS")
        out.update({"serverHost": host, "serverPort": port,
                    "uuid": userinfo,
                    "encryption": p.get("encryption", "none"),
                    "flow": p.get("flow", ""),
                    "network": p.get("type", "tcp"),
                    "wsHost": p.get("host", ""),
                    "wsPath": p.get("path", "/"),
                    "grpcServiceName": p.get("serviceName", ""),
                    "grpcMultiMode": p.get("mode") == "multi",
                    "security": p.get("security", "none"),
                    "sni": p.get("sni", ""),
                    "fingerprint": p.get("fp", "chrome"),
                    "alpn": p.get("alpn", ""),
                    "allowInsecure": p.get("allowInsecure") in ("1", "true"),
                    "realityPublicKey": p.get("pbk", ""),
                    "realityShortId": p.get("sid", ""),
                    "realitySpiderX": p.get("spx", "")})
        return out
    if low.startswith("vmess://"):
        raw = _b64_json_or_text(s[len("vmess://"):])
        if raw is None:
            return None
        j = json.loads(raw)
        out = _base_xray("VMESS")
        net = j.get("net", "tcp")
        out.update({"serverHost": j.get("add", ""),
                    "serverPort": int(j.get("port", 443) or 443),
                    "uuid": j.get("id", ""),
                    "alterId": int(j.get("aid", 0) or 0),
                    "encryption": j.get("scy", "auto"),
                    "network": net,
                    "wsHost": j.get("host", ""),
                    "wsPath": j.get("path", "/"),
                    "grpcServiceName": j.get("path", "") if net == "grpc" else "",
                    "security": "TLS" if j.get("tls") == "tls" else "NONE",
                    "sni": j.get("sni", ""),
                    "fingerprint": j.get("fp", "chrome"),
                    "alpn": j.get("alpn", "")})
        return out
    if low.startswith("trojan://"):
        body = s[len("trojan://"):]
        main, _, _frag = body.partition("#")
        password, _, hostquery = main.partition("@")
        hostport, _, qs = hostquery.partition("?")
        host, port = _split_host_port(hostport)
        p = _query_params(qs)
        out = _base_xray("TROJAN")
        out.update({"serverHost": host, "serverPort": port,
                    "uuid": password,
                    "network": p.get("type", "tcp"),
                    "wsHost": p.get("host", ""),
                    "wsPath": p.get("path", "/"),
                    "grpcServiceName": p.get("serviceName", ""),
                    "security": p.get("security", "tls"),
                    "sni": p.get("sni", ""),
                    "fingerprint": p.get("fp", "chrome"),
                    "alpn": p.get("alpn", ""),
                    "allowInsecure": p.get("allowInsecure") in ("1", "true")})
        return out
    if low.startswith("ss://"):
        body = s[len("ss://"):]
        main, _, _frag = body.partition("#")
        if "@" in main:
            userinfo_b64, _, hostport = main.partition("@")
            decoded = _b64_json_or_text(userinfo_b64) or userinfo_b64
            method, _, pwd = decoded.partition(":")
        else:
            decoded = _b64_json_or_text(main)
            if decoded is None or "@" not in decoded:
                return None
            userinfo, _, hostport = decoded.partition("@")
            method, _, pwd = userinfo.partition(":")
        host, port = _split_host_port(hostport)
        out = _base_xray("SHADOWSOCKS")
        out.update({"serverHost": host, "serverPort": port,
                    "ssMethod": method, "ssPassword": pwd,
                    "security": "NONE"})
        return out
    if s.startswith("{"):
        return parse_xray_json(s)
    return None


def parse_xray_json(text):
    """Mirror of W3/h.d: raw Xray outbound JSON -> CustomXrayParams dict."""
    try:
        j = json.loads(text)
    except Exception:
        return None
    try:
        ob = j["outbounds"][0]
    except Exception:
        return None
    protocol = (ob.get("protocol") or "").lower()
    settings = ob.get("settings", {}) or {}
    stream = ob.get("streamSettings", {}) or {}
    network = stream.get("network", "tcp")
    security = stream.get("security", "none")
    tls = stream.get("tlsSettings", {}) or {}
    ws = stream.get("wsSettings", {}) or {}
    grpc = stream.get("grpcSettings", {}) or {}
    reality = stream.get("realitySettings", {}) or {}
    headers = ws.get("headers", {}) or {}
    out = _base_xray(protocol.upper())
    out.update({"network": network, "security": security,
                "sni": tls.get("serverName", ""),
                "fingerprint": tls.get("fingerprint", "chrome"),
                "alpn": ",".join(tls.get("alpn", []) or []),
                "allowInsecure": bool(tls.get("allowInsecure", False)),
                "wsHost": headers.get("Host", ""),
                "wsPath": ws.get("path", "/"),
                "grpcServiceName": grpc.get("serviceName", ""),
                "grpcMultiMode": bool(grpc.get("multiMode", False)),
                "realityPublicKey": reality.get("publicKey", ""),
                "realityShortId": reality.get("shortId", ""),
                "realitySpiderX": reality.get("spiderX", "")})
    if protocol == "vmess":
        vnext = (settings.get("vnext") or [{}])[0]
        user = (vnext.get("users") or [{}])[0]
        out.update({"serverHost": vnext.get("address", ""),
                    "serverPort": int(vnext.get("port", 443) or 443),
                    "uuid": user.get("id", ""),
                    "alterId": int(user.get("alterId", 0) or 0),
                    "encryption": user.get("security", "auto"),
                    "flow": user.get("flow", "")})
    elif protocol == "vless":
        vnext = (settings.get("vnext") or [{}])[0]
        user = (vnext.get("users") or [{}])[0]
        out.update({"serverHost": vnext.get("address", ""),
                    "serverPort": int(vnext.get("port", 443) or 443),
                    "uuid": user.get("id", ""),
                    "encryption": user.get("encryption", "none"),
                    "flow": user.get("flow", "")})
    elif protocol == "trojan":
        srv = (settings.get("servers") or [{}])[0]
        out.update({"serverHost": srv.get("address", ""),
                    "serverPort": int(srv.get("port", 443) or 443),
                    "uuid": srv.get("password", "")})
    elif protocol == "shadowsocks":
        srv = (settings.get("servers") or [{}])[0]
        out.update({"serverHost": srv.get("address", ""),
                    "serverPort": int(srv.get("port", 443) or 443),
                    "ssMethod": srv.get("method", ""),
                    "ssPassword": srv.get("password", "")})
    return out


# ------------------------------------------------------------------- CLI
SAMPLE_PAYLOADS = {
    "CUSTOM_SSH": {"sshHost": "203.0.113.10", "sshPort": 22,
                   "username": "testuser", "password": "testpass",
                   "proxyHost": "104.18.25.189", "proxyPort": 80,
                   "payload": "GET / HTTP/1.1[crlf]Host: example.com[crlf][crlf]",
                   "useProxy": True, "usePayload": True, "isLocked": False},
    "CUSTOM_SSL": {"sshHost": "203.0.113.11", "sshPort": 443,
                   "username": "ssluser", "password": "sslpass",
                   "payload": "GET / HTTP/1.1[crlf]Host: sni.example.com[crlf][crlf]",
                   "sniHost": "sni.example.com", "usePayload": True,
                   "useSNI": True, "isLocked": False},
    "CUSTOM_SSL_OVPN": {"remoteHost": "203.0.113.12", "remotePort": 1194,
                        "username": "ovpnuser", "password": "ovpnpass",
                        "payload": "", "sniHost": "sni.example.com",
                        "ovpnContent": "client\ndev tun\nproto tcp\nremote 203.0.113.12 1194\n",
                        "ovpnFileName": "test.ovpn", "useAuth": True,
                        "usePayload": False, "useRemoteOverride": False,
                        "useSNI": True, "isLocked": False},
    "CUSTOM_OPENVPN": {"remoteHost": "203.0.113.13", "remotePort": 1194,
                       "username": "u", "password": "p", "payload": "",
                       "proxyHost": "", "proxyPort": 0,
                       "ovpnContent": "client\ndev tun\nproto udp\nremote 203.0.113.13 1194\n",
                       "ovpnFileName": "t.ovpn", "useAuth": False,
                       "usePayload": False, "useProxy": False,
                       "useRemoteOverride": False, "isLocked": False},
    "CUSTOM_DNSTT": {"sshHost": "203.0.113.14", "sshPort": 22,
                     "username": "dnsuser", "password": "dnspass",
                     "dnsttDomain": "dnstt.example.com",
                     "dnsttPubkey": "aabbccddeeff00112233445566778899",
                     "dnsttLocalPort": 5300, "resolverType": "CLOUDFLARE",
                     "customResolver": "", "isLocked": False},
    "CUSTOM_HYSTERIA": {"serverHost": "203.0.113.15", "serverPort": "443",
                        "authPassword": "hy2pass", "sni": "hy.example.com",
                        "obfsPassword": "", "useObfs": False,
                        "useBandwidthLimit": True, "uploadMbps": 10,
                        "downloadMbps": 50, "usePortHopping": False,
                        "portHoppingRange": "", "hopIntervalSec": 30,
                        "useQuicTuning": False, "receiveWindowMb": 32,
                        "allowInsecure": False, "usePinSHA256": False,
                        "pinSHA256": "", "isLocked": False},
    "CUSTOM_XRAY": {"serverHost": "203.0.113.16", "serverPort": 443,
                    "protocol": "VLESS", "uuid": "550e8400-e29b-41d4-a716-446655440000",
                    "alterId": 0, "encryption": "none", "flow": "",
                    "network": "ws", "wsHost": "ws.example.com",
                    "wsPath": "/vless", "grpcServiceName": "",
                    "grpcMultiMode": False, "security": "tls",
                    "sni": "sni.example.com", "fingerprint": "chrome",
                    "alpn": "h2", "allowInsecure": False,
                    "realityPublicKey": "", "realityShortId": "",
                    "realitySpiderX": "", "inputMode": "VISUAL",
                    "ssMethod": "", "ssPassword": "", "isLocked": False},
}


def selftest():
    ok = True
    for ctype in CONFIG_TYPES:
        for password in (None, "test-password-123"):
            export = {"configType": ctype, "name": "selftest-%s" % ctype,
                      "notes": "", "notesFormat": "PLAIN",
                      "createdAt": 1764250000000, "expiresAt": None}
            blob = encode_st_file(export, SAMPLE_PAYLOADS[ctype],
                                  password=password)
            res = decode_st_file(blob, password=password)
            same = res["payload"] == SAMPLE_PAYLOADS[ctype]
            sig = res["export"]["configType"] == ctype
            print("%-16s pw=%-5s round-trip payload match: %s  type match: %s"
                  % (ctype, bool(password), same, sig))
            ok = ok and same and sig
            if password is None:
                # tamper check: flipping one byte must fail HMAC/magic
                bad = bytearray(blob)
                bad[len(bad) // 2] ^= 1
                try:
                    decode_st_file(bytes(bad))
                    print("  TAMPER NOT DETECTED!")
                    ok = False
                except ValueError:
                    pass
    # link parsing checks (mirrors W3/h.b on synthetic links)
    links = {
        "vless://550e8400-e29b-41d4-a716-446655440000@203.0.113.16:443"
        "?encryption=none&security=tls&sni=sni.example.com&type=ws"
        "&host=ws.example.com&path=%2Fvless#Test": ("VLESS", "203.0.113.16", 443),
        "vmess://" + b64e(json.dumps(
            {"v": "2", "ps": "Test", "add": "203.0.113.17", "port": "443",
             "id": "550e8400-e29b-41d4-a716-446655440000", "aid": "0",
             "scy": "auto", "net": "ws", "type": "none", "host": "h.example.com",
             "path": "/vmess", "tls": "tls", "sni": "s.example.com",
             "alpn": "", "fp": "chrome"}).encode()): ("VMESS", "203.0.113.17", 443),
        "trojan://secretpass@203.0.113.18:443?security=tls&sni=s.example.com"
        "#Test": ("TROJAN", "203.0.113.18", 443),
        "ss://" + b64e(b"aes-256-gcm:shadowsocks-pass") +
        "@203.0.113.19:8388#Test": ("SHADOWSOCKS", "203.0.113.19", 8388),
    }
    for link, (proto, host, port) in links.items():
        r = parse_xray_link(link)
        good = r and r["protocol"] == proto and r["serverHost"] == host \
            and r["serverPort"] == port
        print("link %-12s -> %s" % (proto, "OK" if good else "FAIL %r" % (r,)))
        ok = ok and bool(good)
    raw_json = json.dumps({"outbounds": [{"protocol": "vless",
        "settings": {"vnext": [{"address": "203.0.113.20", "port": 443,
                      "users": [{"id": "550e8400-e29b-41d4-a716-446655440000",
                                 "encryption": "none"}]}]},
        "streamSettings": {"network": "ws", "security": "tls",
                           "tlsSettings": {"serverName": "s.example.com"},
                           "wsSettings": {"path": "/x", "headers": {"Host": "h.example.com"}}}}]})
    r = parse_xray_link(raw_json)
    good = r and r["protocol"] == "VLESS" and r["serverHost"] == "203.0.113.20"
    print("link %-12s -> %s" % ("RAW-JSON", "OK" if good else "FAIL %r" % (r,)))
    ok = ok and bool(good)
    print("SELFTEST:", "ALL OK" if ok else "FAILURES")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="Sentinel Tunnel .st decoder")
    ap.add_argument("file", nargs="?", help=".st file to decode")
    ap.add_argument("--password", help="password for protected .st files")
    ap.add_argument("--encode", metavar="EXPORT_JSON",
                    help="build a .st file from an export JSON "
                         "(needs --payload and --out)")
    ap.add_argument("--payload", metavar="PAYLOAD_JSON",
                    help="PlainConfigData JSON for --encode")
    ap.add_argument("--out", help="output .st path for --encode")
    ap.add_argument("--link", help="parse a vless/vmess/trojan/ss link or "
                                   "raw Xray JSON")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.link is not None:
        r = parse_xray_link(args.link)
        if r is None:
            print("could not parse link", file=sys.stderr)
            return 1
        print(json.dumps(r, indent=2, ensure_ascii=False))
        return 0
    if args.encode:
        export = json.load(open(args.encode))
        payload = json.load(open(args.payload)) if args.payload else {}
        blob = encode_st_file(export, payload, password=args.password)
        open(args.out, "wb").write(blob)
        print("wrote %s (%d bytes)" % (args.out, len(blob)))
        return 0
    if not args.file:
        ap.print_help()
        return 1
    res = decode_st_file(open(args.file, "rb").read(),
                         password=args.password)
    print(json.dumps({"export": res["export"], "payload": res["payload"],
                      "key_method": res["key_method"]},
                     indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
