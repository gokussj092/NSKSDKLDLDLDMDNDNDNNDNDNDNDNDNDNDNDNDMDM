#!/usr/bin/env python3
"""STLRAY 1.1.36 (com.stlray.thvpn, versionCode 36) decoder.

Recovered from jadx of base.apk (defpackage.I110l1O, o30, l0OIIlOI1, oa0)
and from the Go core libstlraytcore.so (sing-box libbox fork).

Part A - live catalog (THAIVPN2, 5 layers):
  * Bundled assets/initial-config.json holds the seed catalog plus
    updates.configLocator (THAIVPN2L) -> live URL
    https://stallionray.my.id/sray_v2x6w9c4/config.json
    (modes.json / policy.json live at the same prefix).
  * Envelope: {"format":"THAIVPN2","layers":5,"data":b64,"signature":b64}
  * Signature: ECDSA P-256 / SHA-256 over b"THAIVPN2/config/5" + data,
    public key = assets/catalog-keys.json (SPKI DER, base64).
  * Master key: keys["encryptionKey"] if present, else XOR of the 5x32
    int rows hard-coded in I110l1O.l1l10lOI.
  * 5 layers, i=4..0: layer key = HMAC-SHA256(master,
    "THAIVPN2/<scope>/key/<i>"), AES-256-GCM, nonce = first 12 bytes,
    AAD = "THAIVPN2:<scope>:<i>". Scopes: config / modes / policy /
    locator. Plaintext is gzip (magic 1f 8b) or raw UTF-8 JSON.
  * Live fetch is a plain HTTPS GET (HttpURLConnection defaults, no
    extra headers), up to 4 redirects, max 1 MiB.

Part B - profile links / files (oa0, "TVC" codec):
  * Schemes with keys: sray://, tvc://, uv://, gv://, gpx://,
    insan://, opq://, test://  (hyb:// has no key; bare base64url
    text is treated as sray://). Each scheme has its own 32-byte key
    = XOR of 3 rows of 32 ints (oa0.IlI10lOI1).
  * Link: <scheme> + base64url-no-pad( salt || MASK( GCM-layers(
    randPrefix || rawDeflate(profileJSON) ) ) )
  * .sray file: same raw bytes as the link body (salt || masked
    layers). The decoder also accepts the file as base64url text.
  * KDF: d0 = HMAC(key, salt || kdfLabel); d = HMAC(d, key || salt ||
    [i, i^90]) repeated <rounds> times.
  * Mask: 32-byte blocks HMAC(key, salt || b"TVC-MASK" || BE32(n)),
    XORed over the layered ciphertext.
  * Layers (outermost first on decode): layerKey = HMAC(d, salt ||
    [i, keyByte]); AAD = HMAC(d, salt || [i, aadByte]); AES-256-GCM,
    nonce = first 12 bytes of the layer.
  * Variants tried in order (oa0.l0I10lOI1):
      1. locked:  salt 16, layers 7, rounds 128, "TVC-LOCK-KDF",
         keyByte 85, aadByte 102, prefix 8
      2. normal:  salt 12, layers 1, rounds 64,  "TVC-KDF-INIT",
         keyByte 51, aadByte 68,  prefix 4
      3. legacy:  salt 16, layers 7, rounds 64,  "TVC-KDF-INIT",
         keyByte 17, aadByte 34,  prefix 4
  * After unwrapping, strip the random prefix, raw-inflate
    (zlib wbits=-15) and parse the Profile JSON.

Part C - text links found in the catalog: the free VLESS servers
  carry a standard vless:// sourceUri; parsed by parse_vless().

Usage:
  python3 stlray.py catalog [--out catalogo-completo.json]
      fetch + decrypt the live config catalog (also modes/policy)
  python3 stlray.py decode-link '<scheme>://...'
  python3 stlray.py decode-file file.sray
  python3 stlray.py encode-profile profile.json [--locked]
      build a sray:// link (round-trip test helper)
  python3 stlray.py parse-vless 'vless://...'
"""
import base64
import gzip
import hashlib
import hmac
import json
import os
import re
import struct
import sys
import urllib.parse
import urllib.request
import zlib
from copy import deepcopy

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import load_der_public_key
from Crypto.Cipher import AES

# ---------------------------------------------------------------- catalog
CATALOG_KEYS = {
    "publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDyTM7dSqJdeqmWO4jsSDV9b3Ti4TkrwvO+0bVTqJgq/WyfGcvLN+K9DGAfkC1hDyUSr3sW2l941W/oh0LxFT+Q=="
}
LIVE_BASE = "https://stallionray.my.id/sray_v2x6w9c4"
CONFIG_URL = LIVE_BASE + "/config.json"
MODES_URL = LIVE_BASE + "/modes.json"
POLICY_URL = LIVE_BASE + "/policy.json"

THAIVPN2_ROWS = [
    [53, 64, 58, 145, 247, 205, 19, 137, 234, 206, 146, 7, 231, 151, 71, 80, 116, 211, 44, 68, 48, 247, 148, 170, 13, 22, 197, 61, 148, 220, 70, 177],
    [187, 166, 161, 17, 68, 64, 155, 41, 217, 138, 66, 82, 155, 233, 150, 127, 146, 153, 100, 167, 241, 212, 164, 198, 179, 101, 227, 200, 239, 235, 45, 178],
    [9, 36, 7, 207, 216, 245, 121, 129, 77, 104, 53, 145, 183, 76, 136, 228, 143, 215, 190, 251, 166, 255, 10, 62, 182, 36, 9, 201, 210, 177, 68, 219],
    [39, 103, 241, 99, 25, 83, 231, 109, 228, 156, 11, 23, 130, 81, 109, 20, 200, 79, 45, 29, 113, 63, 46, 56, 56, 163, 21, 250, 232, 150, 155, 228],
    [50, 196, 147, 188, 153, 25, 214, 22, 28, 16, 245, 217, 184, 42, 38, 201, 247, 227, 63, 229, 244, 253, 220, 59, 167, 50, 138, 42, 210, 246, 225, 244],
]


def _hmac(key, *msgs):
    m = hmac.new(key, digestmod=hashlib.sha256)
    for x in msgs:
        m.update(x)
    return m.digest()


def thaivpn2_master_key(keys):
    if keys.get("encryptionKey"):
        return base64.b64decode(keys["encryptionKey"])
    out = bytearray(32)
    for i in range(32):
        x = 0
        for r in THAIVPN2_ROWS:
            x ^= r[i]
        out[i] = x
    return bytes(out)


def thaivpn2_verify(keys, sig_b64, label, data):
    pub = load_der_public_key(base64.b64decode(keys["publicKey"]))
    try:
        pub.verify(base64.b64decode(sig_b64), label.encode() + data, ECDSA(SHA256()))
        return True
    except InvalidSignature:
        return False


def thaivpn2_unwrap(data, keys, scope, max_len):
    mk = thaivpn2_master_key(keys)
    buf = data
    if not (140 <= len(buf) <= 140 + max_len):
        raise ValueError(f"bad wrapped length {len(buf)}")
    for i in range(4, -1, -1):
        lk = _hmac(mk, f"THAIVPN2/{scope}/key/{i}".encode())
        c = AES.new(lk, AES.MODE_GCM, nonce=buf[:12])
        c.update(f"THAIVPN2:{scope}:{i}".encode())
        buf = c.decrypt_and_verify(buf[12:-16], buf[-16:])
    if len(buf) > max_len:
        raise ValueError("plaintext too long")
    return buf


def thaivpn2_decrypt_envelope(env, keys):
    fmt = env.get("format", "")
    mapping = {
        "THAIVPN2": ("config", "THAIVPN2/config/5", 262144),
        "THAIVPN2M": ("modes", "THAIVPN2/modes/5", 262144),
        "THAIVPN2P": ("policy", "THAIVPN2/policy/5", 262144),
        "THAIVPN2L": ("locator", "THAIVPN2/locator/5", 4096),
    }
    if fmt not in mapping:
        raise ValueError(f"unknown THAIVPN2 format: {fmt!r}")
    scope, label, mx = mapping[fmt]
    if env.get("layers") != 5:
        raise ValueError(f"layers != 5: {env.get('layers')}")
    data = base64.b64decode(env["data"])
    sig_ok = None
    if env.get("signature"):
        sig_ok = thaivpn2_verify(keys, env["signature"], label, data)
    pt = thaivpn2_unwrap(data, keys, scope, mx)
    if len(pt) >= 2 and pt[0] == 0x1F and pt[1] == 0x8B:
        pt = gzip.decompress(pt)
    txt = pt.decode("utf-8")
    try:
        return json.loads(txt), sig_ok
    except json.JSONDecodeError:
        return txt, sig_ok


def fetch_live(url):
    """Exact app request: plain HTTPS GET, default headers, <=4 redirects."""
    req = urllib.request.Request(url, headers={"User-Agent": "Dalvik/2.1.0 (Linux; U; Android 14)"})
    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
    with opener.open(req, timeout=30) as r:
        data = r.read()
    if len(data) > 1048576:
        raise ValueError("catalog too large")
    return data


def fetch_catalog():
    out = {}
    for name, url in (("config", CONFIG_URL), ("modes", MODES_URL), ("policy", POLICY_URL)):
        raw = fetch_live(url)
        env = json.loads(raw)
        dec, sig_ok = thaivpn2_decrypt_envelope(env, CATALOG_KEYS)
        out[name] = {"decrypted": dec, "signature_valid": sig_ok, "raw_bytes": len(raw)}
    return out


# ---------------------------------------------------------------- profile codec (oa0)
SCHEME_KEYS = {
    "test://": [[127, 139, 69, 248, 12, 70, 212, 155, 132, 166, 219, 29, 33, 8, 235, 69, 105, 6, 188, 15, 206, 119, 2, 4, 21, 202, 199, 51, 255, 133, 176, 53], [204, 104, 113, 204, 63, 7, 245, 145, 90, 164, 168, 207, 234, 242, 111, 30, 193, 213, 154, 91, 178, 225, 106, 236, 167, 0, 130, 137, 193, 235, 179, 168], [140, 23, 137, 43, 138, 1, 25, 224, 165, 178, 94, 146, 7, 215, 152, 160, 136, 91, 77, 4, 57, 244, 95, 23, 123, 7, 105, 230, 201, 14, 208, 103]],
    "tvc://": [[33, 39, 127, 243, 238, 59, 112, 233, 107, 140, 23, 129, 66, 217, 181, 84, 12, 137, 139, 47, 85, 50, 18, 226, 111, 104, 122, 39, 8, 90, 96, 174], [96, 210, 190, 184, 156, 163, 71, 31, 146, 109, 138, 237, 135, 175, 33, 177, 73, 151, 172, 237, 82, 23, 150, 36, 139, 196, 198, 66, 149, 120, 180, 162], [136, 65, 182, 115, 77, 56, 125, 255, 208, 43, 114, 24, 77, 242, 124, 238, 127, 13, 255, 102, 104, 28, 199, 157, 48, 79, 151, 219, 164, 250, 145, 111]],
    "sray://": [[35, 213, 172, 85, 177, 92, 212, 26, 105, 168, 190, 23, 44, 34, 196, 207, 125, 182, 233, 234, 43, 80, 95, 62, 167, 197, 116, 152, 214, 38, 71, 8], [5, 85, 132, 97, 49, 65, 19, 93, 115, 206, 70, 20, 229, 119, 180, 54, 21, 26, 219, 41, 146, 141, 12, 234, 92, 179, 32, 228, 55, 106, 25, 154], [170, 167, 127, 162, 244, 112, 212, 240, 172, 71, 222, 135, 82, 227, 205, 247, 128, 117, 16, 126, 159, 131, 33, 161, 21, 229, 1, 206, 9, 165, 96, 70]],
    "uv://": [[106, 222, 117, 31, 119, 27, 172, 104, 213, 119, 138, 136, 193, 167, 32, 220, 221, 151, 186, 17, 255, 98, 81, 209, 113, 160, 206, 86, 229, 106, 102, 60], [49, 183, 22, 12, 220, 154, 89, 48, 26, 159, 171, 88, 163, 63, 139, 54, 99, 165, 56, 17, 234, 65, 163, 188, 66, 126, 205, 31, 72, 91, 113, 108], [13, 203, 201, 76, 28, 73, 126, 169, 154, 91, 198, 136, 224, 136, 246, 21, 213, 241, 236, 197, 140, 159, 119, 91, 185, 83, 193, 19, 110, 32, 212, 211]],
    "gv://": [[77, 111, 145, 99, 90, 204, 113, 193, 91, 235, 21, 240, 82, 138, 63, 55, 125, 62, 194, 178, 226, 94, 212, 253, 213, 249, 6, 124, 125, 73, 40, 205], [3, 32, 141, 229, 229, 244, 46, 103, 198, 176, 68, 48, 24, 190, 204, 79, 17, 20, 96, 168, 79, 2, 13, 233, 233, 73, 172, 160, 22, 55, 196, 149], [75, 18, 15, 216, 39, 43, 152, 203, 208, 207, 140, 213, 201, 97, 175, 249, 229, 184, 128, 43, 163, 189, 189, 251, 245, 156, 120, 16, 78, 164, 66, 176]],
    "gpx://": [[243, 195, 181, 39, 175, 26, 8, 91, 85, 182, 212, 165, 16, 25, 153, 111, 27, 131, 10, 212, 172, 154, 119, 21, 238, 246, 168, 237, 241, 147, 166, 206], [135, 163, 91, 169, 228, 185, 247, 249, 38, 93, 43, 249, 71, 232, 79, 159, 16, 227, 93, 45, 19, 82, 112, 6, 213, 0, 159, 187, 16, 225, 69, 38], [166, 50, 43, 120, 81, 63, 212, 218, 73, 230, 46, 44, 117, 25, 251, 49, 20, 164, 40, 138, 249, 114, 18, 5, 175, 67, 153, 1, 136, 7, 238, 181]],
    "insan://": [[63, 60, 160, 221, 25, 133, 77, 78, 161, 198, 44, 160, 48, 245, 251, 20, 170, 19, 17, 16, 183, 107, 7, 113, 133, 25, 118, 34, 171, 251, 179, 183], [20, 5, 5, 196, 255, 60, 212, 3, 36, 164, 47, 42, 36, 73, 73, 150, 43, 238, 190, 131, 135, 47, 223, 121, 42, 186, 45, 119, 42, 77, 255, 33], [225, 240, 254, 20, 107, 28, 183, 228, 103, 162, 152, 59, 231, 14, 20, 26, 47, 237, 68, 68, 103, 201, 227, 239, 75, 122, 57, 133, 252, 45, 99, 74]],
    "opq://": [[51, 62, 91, 177, 229, 166, 3, 138, 60, 45, 77, 184, 206, 205, 88, 76, 100, 246, 115, 50, 91, 209, 121, 193, 104, 28, 163, 223, 226, 38, 171, 136], [191, 228, 141, 195, 14, 29, 124, 117, 191, 9, 152, 4, 131, 239, 190, 191, 7, 58, 114, 253, 186, 245, 61, 121, 97, 73, 173, 76, 20, 249, 225, 168], [226, 199, 112, 119, 65, 229, 19, 24, 134, 139, 225, 221, 148, 70, 216, 172, 154, 96, 51, 84, 96, 170, 168, 145, 119, 56, 45, 246, 32, 99, 248, 182]],
}
# (salt_len, layers, kdf_rounds, kdf_label, key_byte, aad_byte, prefix_len)
PROFILE_VARIANTS = [
    (16, 7, 128, "TVC-LOCK-KDF", 85, 102, 8),
    (12, 1, 64, "TVC-KDF-INIT", 51, 68, 4),
    (16, 7, 64, "TVC-KDF-INIT", 17, 34, 4),
]


def scheme_key(scheme):
    rows = SCHEME_KEYS.get(scheme.lower())
    if rows is None:
        return None
    out = bytearray(32)
    for i in range(32):
        x = 0
        for r in rows:
            x ^= r[i]
        out[i] = x
    return bytes(out)


def _tvc_kdf(key, salt, rounds, label):
    d = _hmac(key, salt, label.encode())
    for i in range(rounds):
        d = _hmac(d, key, salt, bytes([i & 0xFF, (i ^ 90) & 0xFF]))
    return d


def _tvc_mask(data, key, salt):
    out = bytearray(data)
    n = 0
    i = 0
    while i < len(out):
        blk = _hmac(key, salt, b"TVC-MASK", struct.pack(">I", n))
        take = min(len(blk), len(out) - i)
        for j in range(take):
            out[i + j] ^= blk[j]
        i += take
        n += 1
    return bytes(out)


def _tvc_unwrap_layers(buf, derived, salt, layers, key_byte, aad_byte):
    for i in range(layers - 1, -1, -1):
        if len(buf) < 28:
            raise ValueError("layer too short")
        lk = _hmac(derived, salt, bytes([i, key_byte]))
        aad = _hmac(derived, salt, bytes([i, aad_byte]))
        c = AES.new(lk, AES.MODE_GCM, nonce=buf[:12])
        c.update(aad)
        buf = c.decrypt_and_verify(buf[12:-16], buf[-16:])
    return buf


def decode_profile_bytes(raw, scheme="sray://"):
    """Decode raw .sray-style bytes (salt || masked GCM layers)."""
    key = scheme_key(scheme)
    if key is None:
        key = scheme_key("sray://")
    last_err = None
    for salt_len, layers, rounds, label, kb, ab, prefix in PROFILE_VARIANTS:
        try:
            if not (salt_len + layers * 28 + prefix + 1 <= len(raw) <= salt_len + 131072 + layers * 28 + 40):
                continue
            salt, masked = raw[:salt_len], raw[salt_len:]
            derived = _tvc_kdf(key, salt, rounds, label)
            plain = _tvc_unwrap_layers(_tvc_mask(masked, key, salt), derived, salt, layers, kb, ab)
            if len(plain) > 131072:
                continue
            inner = plain[prefix:]
            text = zlib.decompress(inner, -15).decode("utf-8")
            return json.loads(text), {"variant": label, "layers": layers, "prefix": prefix}
        except Exception as e:  # noqa: BLE001 - try next variant
            last_err = e
    raise ValueError(f"no TVC variant decoded the profile: {last_err}")


def _b64url_decode(s):
    s = s.strip().replace("\r", "").replace("\n", "").replace(" ", "")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def decode_link(link):
    """Decode a sray:// (or tvc://, uv://, gv://, gpx://, insan://,
    opq://, test://) link, or a bare base64url body (treated as sray://)."""
    s = link.strip()
    scheme = None
    for cand in SCHEME_KEYS:
        if s.lower().startswith(cand):
            scheme = cand
            s = s[len(cand):]
            break
    if scheme is None:
        if s.lower().startswith("hyb://"):
            scheme = "sray://"  # hyb:// has no own key; app falls back to sray
            s = s[len("hyb://"):]
        else:
            scheme = "sray://"
    return decode_profile_bytes(_b64url_decode(s), scheme)


def decode_file(path):
    """Decode a .sray (or .tvc/.gv/.uv/.gpx/.test/.insan/.opq) file.
    Accepts raw bytes or base64url text (with or without scheme)."""
    raw = open(path, "rb").read()
    try:
        txt = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        txt = ""
    if txt and re.fullmatch(r"[A-Za-z0-9_=\-:/.]+", txt) and (
        txt.lower().startswith(tuple(SCHEME_KEYS)) or re.fullmatch(r"[A-Za-z0-9_\-=]+", txt)
    ):
        try:
            return decode_link(txt)
        except ValueError:
            pass
    scheme = "sray://"
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    if ext and (ext + "://") in SCHEME_KEYS:
        scheme = ext + "://"
    return decode_profile_bytes(raw, scheme)


def encode_profile(profile, locked=False, scheme="sray://"):
    """Build a <scheme>:// link exactly like the app (oa0.OOI10lO).
    Used for round-trip verification."""
    import secrets
    data = json.dumps(profile, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    payload = comp.compress(data) + comp.flush()
    prefix_len = 8 if locked else 4
    prefix = secrets.token_bytes(prefix_len)
    body = prefix + payload
    key = scheme_key(scheme)
    salt_len = 16 if locked else 12
    layers = 7 if locked else 1
    rounds = 128 if locked else 64
    label = "TVC-LOCK-KDF" if locked else "TVC-KDF-INIT"
    kb = 85 if locked else 51
    ab = 102 if locked else 68
    salt = secrets.token_bytes(salt_len)
    derived = _tvc_kdf(key, salt, rounds, label)
    for i in range(layers):
        lk = _hmac(derived, salt, bytes([i, kb]))
        aad = _hmac(derived, salt, bytes([i, ab]))
        nonce = secrets.token_bytes(12)
        c = AES.new(lk, AES.MODE_GCM, nonce=nonce)
        c.update(aad)
        ct, tag = c.encrypt_and_digest(body)
        body = nonce + ct + tag
    masked = _tvc_mask(body, key, salt)
    raw = salt + masked
    return scheme + base64.urlsafe_b64encode(raw).decode().rstrip("="), raw


# ---------------------------------------------------------------- vless
def parse_vless(uri):
    u = urllib.parse.urlparse(uri)
    if u.scheme.lower() != "vless":
        raise ValueError("not a vless:// link")
    q = urllib.parse.parse_qs(u.query)
    return {
        "uuid": urllib.parse.unquote(u.username or ""),
        "server": u.hostname,
        "port": u.port,
        "encryption": q.get("encryption", ["none"])[0],
        "security": q.get("security", ["none"])[0],
        "type": q.get("type", ["tcp"])[0],
        "path": q.get("path", [""])[0],
        "host": q.get("host", [""])[0],
        "sni": q.get("sni", [""])[0],
        "flow": q.get("flow", [""])[0],
        "name": urllib.parse.unquote(u.fragment or ""),
    }


# ---------------------------------------------------------------- redaction
def redact_catalog(cfg):
    c = deepcopy(cfg)
    for s in c.get("servers", []):
        s.pop("host", None)
        s.pop("statusUrl", None)
        for conn in (s.get("connections") or {}).values():
            conn.pop("server", None)
            a = conn.get("auth") or {}
            for k in ("username", "password", "value", "uuid"):
                a.pop(k, None)
        p = s.get("profile") or {}
        p.pop("server", None)
        a = p.get("auth") or {}
        for k in ("username", "password", "value", "uuid"):
            a.pop(k, None)
        p.pop("sourceUri", None)
        if "slowDns" in s:
            (s.get("slowDns") or {}).pop("dns", None)
            (s.get("slowDns") or {}).pop("nameserver", None)
            (s.get("slowDns") or {}).pop("publicKey", None)
        (s.get("udpConfig") or {}).pop("auth_str", None)
    for cert in c.get("certificates", []):
        cert.pop("pem", None)
    # Payload proxy/dns hold bare public IPs (proxy endpoints) - blank them.
    import re as _re
    for p in c.get("payloads", []):
        for k in ("proxy", "dns"):
            v = p.get(k)
            if isinstance(v, str) and _re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", v.strip()):
                p[k] = ""
    return c


# ---------------------------------------------------------------- CLI
def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    cmd = sys.argv[1]
    if cmd == "catalog":
        out = fetch_catalog()
        cfg = out["config"]["decrypted"]
        print(f"config revision={cfg.get('revision')} configVersion={cfg.get('configVersion')} "
              f"servers={len(cfg.get('servers', []))} payloads={len(cfg.get('payloads', []))} "
              f"certificates={len(cfg.get('certificates', []))} sig={out['config']['signature_valid']}")
        print(f"modes revision={out['modes']['decrypted'].get('revision')} "
              f"modes={len(out['modes']['decrypted'].get('modes', []))} sig={out['modes']['signature_valid']}")
        print(f"policy revision={out['policy']['decrypted'].get('revision')} sig={out['policy']['signature_valid']}")
        if len(sys.argv) > 3 and sys.argv[2] == "--out":
            json.dump(cfg, open(sys.argv[3], "w"), indent=2, ensure_ascii=False)
            print("wrote", sys.argv[3])
        return 0
    if cmd == "decode-link":
        prof, info = decode_link(sys.argv[2])
        print(json.dumps(prof, indent=2, ensure_ascii=False))
        print("variant:", info, file=sys.stderr)
        return 0
    if cmd == "decode-file":
        prof, info = decode_file(sys.argv[2])
        print(json.dumps(prof, indent=2, ensure_ascii=False))
        print("variant:", info, file=sys.stderr)
        return 0
    if cmd == "encode-profile":
        prof = json.load(open(sys.argv[2]))
        locked = "--locked" in sys.argv
        link, raw = encode_profile(prof, locked=locked)
        print(link)
        return 0
    if cmd == "parse-vless":
        print(json.dumps(parse_vless(sys.argv[2]), indent=2, ensure_ascii=False))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
