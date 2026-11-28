"""SNI Tunnel 1.3.7 (versionCode 40, com.asnly.snitunnel) -- v2rc:// / .v2rc
sealed-config decoder, v2rcloud:// cloud-link claim, standard link import
(vmess/vless/trojan/ss/hysteria2/tuic/socks/ssh) and HTTPS subscription fetch.

Reverse-engineered from the APK (jadx of classes.dex; Dart/Flutter UI only
holds the screens -- all crypto and all network code is Kotlin in the DEX):

  * uo.j / uo.b  -- seal a profile into a v2rc:// link
  * uo.w / uo.x  -- import/decrypt a v2rc:// link (or .v2rc file content)
  * o5.a / o5.b  -- P-256 ECDH + HKDF-SHA256 + ChaCha20-Poly1305 seal
  * r8.c / r8.d / r8.e / r8.g -- P-256 key derivation from a seed, raw x||y
  * p5.a / p5.b  -- PBKDF2-HMAC-SHA256 + ChaCha20-Poly1305 password envelope
  * c1.a         -- XOR de-obfuscation of the embedded app key (SHA-256 chain)
  * r0.g / r0.j  -- device identity from Settings.Secure.ANDROID_ID
  * v0           -- cloud relay https://snicfg.asnly.net/v1/configs
  * a4           -- v2rcloud:// link format + AES-128-GCM transport
  * SubscriptionHttpClient / DirectSubscriptionTransport -- subscription GET
  * SubscriptionContent -- subscription body parsing (links / Clash / JSON)
  * wo.c         -- standard link export (vmess/vless/trojan/ss/hysteria2)

NO SERVER CATALOG EXISTS in this app (verified 2026-11-28): there is no
catalog URL, endpoint or bundled server list anywhere in the DEX strings
(30,120 lines), the Dart snapshot strings (37,575 lines), the Flutter
assets or the native libraries. The app is a bring-your-own-config V2Ray /
Xray client: the user adds their own subscription URLs, pastes links, or
imports sealed v2rc:// configs. The only server-side endpoints are:

  * POST/GET https://snicfg.asnly.net/v1/configs[/<token>[/claim]] -- the
    cloud relay that stores ONE user-created sealed config per token
    (verified live 2026-11-28: unknown token -> 404 {"error":"not_found"}).
    It has no listing endpoint, so there is no catalog to download.
  * Subscription fetch: plain HTTPS GET of a user-supplied URL with
    User-Agent "SNI-Tunnel/1.3.7 (Android)" (verified in the DEX).

There is therefore no live catalog to reproduce and no server data to
decrypt; catalogo-completo.json / catalogo-redactado.json record this
finding with "catalog": null and servers []. No server was invented.

v2rc:// envelope (uo.j / uo.x):
    link = "v2rc://" + base64url_nopad(JSON)
    JSON = {"version": 1|2, "name": str, "records": [...],
            ["passwordProtected": true], ["cellularOnly": true],
            ["expiresAt": <seconds since 2001-01-01T00:00:00Z>]}
    version 2 <=> passwordProtected. expiresAt (inner and outer) is seconds
    since 2001-01-01 (Apple epoch): unix = value + 978307200.
    record = {"deviceIDHash": hex(SHA256(deviceID)[0:12]),
              "ephemeralPub": base64_std(64B P-256 pub x||y),
              "ciphertext":   base64_std(nonce12 || ChaCha20-Poly1305(ct))}
    Inner plaintext JSON:
      {"deviceID": str, ["expiresAt": <sec since 2001>],
       ["cellularOnly": true],
       "config": "<standard link>" |
       "passwordEnvelope": {"salt": b64, "iterations": int,
                            "ciphertext": b64(nonce12 || ChaCha20-Poly1305)}}

  Device identity (r0.g/r0.j): seed = "sni-tunnel-device-id-v2|" +
    package + "|" + ANDROID_ID (UTF-8); priv = SHA256(seed) mod (n-1) + 1
    on secp256r1; deviceID = base64url_nopad(pub x||y, 64 B).
    deviceIDHash = hex(SHA256(deviceID)[0:12]).
  Seal key (o5.b): HKDF-SHA256(salt=ephemeralPubRaw, IKM=ECDH shared
    secret, info=b"v2rc-seal-v1" + recipientPubRaw, L=32); ChaCha20-Poly1305
    with a random 12-byte nonce. The seal ALWAYS appends an extra "open"
    record for deviceID "v2rc-app-open-v1" whose key is embedded in the APK
    (obfuscated with c1.a, a SHA-256-chain XOR), so a sealed config is
    openable by any install of the app; the per-device records are only a
    preference (the app tries the device record first, then the open one).
  Password envelope (p5): key = PBKDF2-HMAC-SHA256(password, salt, iters,
    32); app seals with 120000 iterations; import requires
    10000 <= iters <= 1000000 and salt >= 16 B; ChaCha20-Poly1305,
    nonce = blob[0:12]. Without the password the inner config cannot be
    decrypted (and the app also refuses expired links).

v2rcloud:// link (a4): "v2rcloud://" + base64url_nopad(29 bytes:
    [0]=1 version, [1:13]=12-byte token id, [13:29]=16-byte AES key).
  Claim: POST https://snicfg.asnly.net/v1/configs/<tokenB64>/claim
    {"deviceHash": hex(SHA256("v2rcloud-device-v1|"+tokenB64+"|"+deviceID))}
    UA "SNI-Tunnel-Android/1", Accept application/json, timeouts 10s/15s.
    -> {"ciphertext": base64_std(nonce12 || AES-128-GCM(v2rc:// link)),
        "remaining": int}. Errors: not_found, expired, exhausted,
    device_mismatch, device_required, revoked, rate_limited, unauthorized,
    payload_too_large, invalid_request.
  Create: POST https://snicfg.asnly.net/v1/configs
    {"ciphertext": <AES-128-GCM of the v2rc:// link, base64_std>,
     "expiresAt": <epoch millis>, "bindDevice": bool,
     "maxClaims": int|null} -> {"token", "expiresAt", "remaining",
     "deviceBound"}. Limits: ciphertext <= 8192 chars, lifetime 5 min ..
    30 days, maxClaims 1..1000.
  Metadata: GET https://snicfg.asnly.net/v1/configs/<token> ->
    {"expiresAt": <epoch millis>, "deviceBound", "expired", "exhausted",
     "remaining"}.

File import: a .v2rc file contains the v2rc:// link text (the sealed
bundle); the app also accepts pasted links, subscription URLs and a
single-outbound V2Ray/Xray JSON document. Subscription bodies are parsed
as base64-or-plain lines of links, Clash YAML (proxies:) or JSON
(SubscriptionContent). Subscription fetch limit: 16 MB (ImportLimits).

Dependencies: Python 3 stdlib + `cryptography` (ECDH P-256,
ChaCha20Poly1305, AESGCM, PBKDF2HMAC). No network access is needed except
for the `subscription` and `cloud` subcommands.
"""

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:  # pragma: no cover
    ec = None

# ---------------------------------------------------------------- constants

APPLE_EPOCH = 978307200  # 2001-01-01T00:00:00Z, unix seconds
PACKAGE = "com.asnly.snitunnel"
APP_OPEN_ID = "v2rc-app-open-v1"
SEAL_INFO_PREFIX = b"v2rc-seal-v1"
DEVICE_ID_SEED_PREFIX = "sni-tunnel-device-id-v2"
PASSWORD_ITERATIONS_SEAL = 120000

# Embedded app key, XOR-obfuscated with c1.a (SHA-256 chain over the
# 16-byte constant below). Verified: priv*G == pub on secp256r1.
_C1_CONSTANT = bytes.fromhex("379c51a2e4186bd02f84c71d935af60e")
_APP_PRIV_B64 = "oalc625RvmMDrCDr3BszQTiP7vlEXs0LUxy9d5iN0Uk="
_APP_PUB_B64 = ("DKYjFOANdaFdOJVC/03xnk4nZsj3Dfwc/VzJ68K+TauOeD0PFeGV90j2y7"
                "DTbmzZyt5HfyZL/Q8PrutvRC15rQ==")

CLOUD_HOST = "snicfg.asnly.net"
CLOUD_UA = "SNI-Tunnel-Android/1"
SUBSCRIPTION_UA = "SNI-Tunnel/1.3.7 (Android)"
SUBSCRIPTION_MAX_BYTES = 16 * 1024 * 1024

B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


class SniError(Exception):
    pass


# ---------------------------------------------------------------- helpers

def b64url_decode(s):
    """base64url without padding, tolerating whitespace (hr.B0 trims)."""
    s = "".join(str(s).split())
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_encode(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64std_decode(s):
    s = "".join(str(s).split())
    return base64.b64decode(s + "=" * (-len(s) % 4))


def b64std_encode(b):
    return base64.b64encode(b).decode()


def device_id_hash(device_id):
    """uo.s: hex(SHA-256(deviceID UTF-8)[0:12])."""
    return hashlib.sha256(device_id.encode("utf-8")).digest()[:12].hex()


def apple_to_unix(value):
    return value + APPLE_EPOCH


def fmt_ts(unix):
    try:
        return datetime.fromtimestamp(unix, timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return "invalid:%r" % (unix,)


# ---------------------------------------------------------------- P-256

def _require_crypto():
    if ec is None:
        raise SniError("the 'cryptography' package is required")


def c1_decode(b64):
    """c1.a: XOR with a SHA-256 chain keystream seeded by _C1_CONSTANT."""
    data = base64.b64decode(b64)
    ks = b""
    prev = b""
    while len(ks) < len(data):
        prev = hashlib.sha256(_C1_CONSTANT + prev).digest()
        ks += prev
    return bytes(x ^ y for x, y in zip(data, ks[:len(data)]))


def app_keypair():
    """Return (priv_scalar_bytes, pub_raw_64_bytes) embedded in the APK."""
    priv = c1_decode(_APP_PRIV_B64)
    pub = c1_decode(_APP_PUB_B64)
    return priv, pub


def priv_from_seed(seed_bytes):
    """r8.c: priv = SHA-256(seed) mod (n-1) + 1 on secp256r1; returns
    (priv_scalar_bytes, pub_raw_64_bytes)."""
    _require_crypto()
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    d = int.from_bytes(hashlib.sha256(seed_bytes).digest(), "big") % (n - 1) + 1
    priv = ec.derive_private_key(d, ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    pub = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    return d.to_bytes(32, "big"), pub


def device_keypair(android_id, package=PACKAGE):
    """r0.j: keypair derived from the device ANDROID_ID. Returns
    (priv_scalar_bytes, device_id_string)."""
    seed = ("%s|%s|%s" % (DEVICE_ID_SEED_PREFIX, package, android_id)).encode("utf-8")
    priv, pub = priv_from_seed(seed)
    return priv, b64url_encode(pub)


def _ec_priv(scalar_bytes):
    _require_crypto()
    return ec.derive_private_key(int.from_bytes(scalar_bytes, "big"), ec.SECP256R1())


def _ec_pub(raw64):
    _require_crypto()
    if len(raw64) != 64:
        raise SniError("Invalid P-256 public key length: %d (want 64)" % len(raw64))
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(raw64[:32], "big"),
        int.from_bytes(raw64[32:], "big"),
        ec.SECP256R1()).public_key()


def _hkdf_seal_key(shared_secret, ephemeral_pub_raw, recipient_pub_raw):
    """o5.b: HKDF-SHA256(salt=ephemeralPub, IKM=shared, info=
    "v2rc-seal-v1" + recipientPub, L=32)."""
    salt = ephemeral_pub_raw if len(ephemeral_pub_raw) else bytes(32)
    prk = hmac.new(salt, shared_secret, hashlib.sha256).digest()
    info = SEAL_INFO_PREFIX + recipient_pub_raw
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def seal_record(recipient_pub_raw, device_id, inner_json_bytes, rng=os.urandom):
    """uo.b: seal one record. Returns the record dict."""
    _require_crypto()
    eph_priv = ec.generate_private_key(ec.SECP256R1())
    eph_pub = eph_priv.public_key().public_numbers()
    eph_raw = eph_pub.x.to_bytes(32, "big") + eph_pub.y.to_bytes(32, "big")
    shared = eph_priv.exchange(ec.ECDH(), _ec_pub(recipient_pub_raw))
    key = _hkdf_seal_key(shared, eph_raw, recipient_pub_raw)
    nonce = rng(12)
    ct = ChaCha20Poly1305(key).encrypt(nonce, inner_json_bytes, None)
    return {
        "deviceIDHash": device_id_hash(device_id),
        "ephemeralPub": b64std_encode(eph_raw),
        "ciphertext": b64std_encode(nonce + ct),
    }


def decrypt_record(priv_scalar, my_pub_raw, record):
    """o5.a: open one record with our private key. Returns inner JSON bytes."""
    _require_crypto()
    eph_raw = b64std_decode(record["ephemeralPub"])
    blob = b64std_decode(record["ciphertext"])
    if len(blob) < 12 + 16:
        raise SniError("ciphertext too short: %d bytes" % len(blob))
    shared = _ec_priv(priv_scalar).exchange(ec.ECDH(), _ec_pub(eph_raw))
    key = _hkdf_seal_key(shared, eph_raw, my_pub_raw)
    try:
        return ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], None)
    except Exception as exc:
        raise SniError("ChaCha20-Poly1305 authentication failed (%s)" % exc)


def decrypt_password_envelope(password, envelope):
    """p5.b: PBKDF2-HMAC-SHA256 + ChaCha20-Poly1305. Returns config bytes."""
    _require_crypto()
    if not password:
        raise SniError("This config requires a password.")
    salt = b64std_decode(envelope["salt"])
    iters = int(envelope["iterations"])
    blob = b64std_decode(envelope["ciphertext"])
    if len(salt) < 16 or not (10000 <= iters < 1000001) or len(blob) < 28:
        raise SniError("Invalid password envelope")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=iters)
    key = kdf.derive(password.encode("utf-8"))
    try:
        return ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], None)
    except Exception:
        raise SniError("The config password is incorrect.")


# ---------------------------------------------------------------- v2rc

def parse_v2rc_envelope(text):
    """uo.x / uo.m: parse a v2rc:// link (or a bare base64url envelope).
    Returns the envelope dict plus decoded metadata."""
    raw = "".join(str(text).split())
    if raw.startswith("v2rc://"):
        raw = raw[len("v2rc://"):]
    try:
        env = json.loads(b64url_decode(raw).decode("utf-8"))
    except Exception as exc:
        raise SniError("The encrypted config is invalid (%s)" % exc)
    version = int(env.get("version", 1))
    pw = bool(env.get("passwordProtected", False))
    if not (1 <= version < 3):
        raise SniError("The encrypted config is invalid (version %r)" % version)
    if pw != (version == 2):
        raise SniError("The encrypted config is invalid "
                       "(passwordProtected/version mismatch)")
    records = env.get("records") or []
    if not records:
        raise SniError("The encrypted config is invalid (no records)")
    expires = None
    if env.get("expiresAt") is not None:
        expires = apple_to_unix(float(env["expiresAt"]))
    return {
        "envelope": env,
        "version": version,
        "name": env.get("name", ""),
        "password_protected": pw,
        "cellular_only": bool(env.get("cellularOnly", False)),
        "expires_at_unix": expires,
        "expired": bool(expires is not None and expires * 1000
                        < time.time() * 1000),
        "records": records,
    }


def open_v2rc(text, password=None, android_id=None, package=PACKAGE):
    """uo.w: open a v2rc:// link. Returns a dict with the inner JSON and,
    when available, the plaintext config string.

    Resolution order (as in the app): the record matching this device
    (needs --android-id), else the app-open record (embedded APK key).
    The password layer needs the password; without it the inner config
    stays encrypted and is reported as such, never guessed."""
    parsed = parse_v2rc_envelope(text)
    env, records = parsed["envelope"], parsed["records"]

    my_priv = my_pub = my_id = None
    if android_id:
        my_priv, my_id = device_keypair(android_id, package)
        my_pub = b64url_decode(my_id)
        my_hash = device_id_hash(my_id)
    else:
        my_hash = None

    app_priv, app_pub = app_keypair()
    open_hash = device_id_hash(APP_OPEN_ID)

    chosen = None
    for rec in records:
        if my_hash and rec.get("deviceIDHash") == my_hash:
            chosen = (rec, my_priv, my_pub, "device")
            break
    if chosen is None:
        for rec in records:
            if rec.get("deviceIDHash") == open_hash:
                chosen = (rec, app_priv, app_pub, "app-open")
                break
    if chosen is None:
        raise SniError("This config does not authorize this device.")

    rec, priv, pub, how = chosen
    inner_raw = decrypt_record(priv, pub, rec)
    try:
        inner = json.loads(inner_raw.decode("utf-8"))
    except Exception as exc:
        raise SniError("Inner JSON is not valid UTF-8/JSON (%s)" % exc)

    result = dict(parsed)
    result.update({
        "record_kind": how,
        "device_id": inner.get("deviceID"),
        "inner_expires_at_unix": (
            apple_to_unix(float(inner["expiresAt"]))
            if inner.get("expiresAt") is not None else None),
        "inner": inner,
        "config": None,
        "password_envelope": inner.get("passwordEnvelope"),
    })
    if inner.get("deviceID") not in (my_id, APP_OPEN_ID):
        raise SniError("The device identity does not match.")
    if bool(inner.get("cellularOnly", False)) != parsed["cellular_only"]:
        raise SniError("The encrypted config is invalid (cellularOnly mismatch)")
    if result["inner_expires_at_unix"] is not None and \
            result["inner_expires_at_unix"] * 1000 < time.time() * 1000:
        result["inner_expired"] = True
    else:
        result["inner_expired"] = False

    if result["password_envelope"] is None:
        if not parsed["password_protected"] and "config" in inner:
            result["config"] = inner["config"]
        else:
            raise SniError("The encrypted config is invalid")
    else:
        if password:
            result["config"] = decrypt_password_envelope(
                password, result["password_envelope"]).decode("utf-8")
        else:
            result["config"] = None  # still sealed behind the password
    return result


def seal_v2rc(config, name, password=None, device_ids=None,
              expires_at_unix=None, cellular_only=False, rng=os.urandom):
    """uo.j: build a v2rc:// link. device_ids are deviceID strings
    (base64url of the 64-byte device pubkey). An app-open record is
    ALWAYS appended (as in the app)."""
    _require_crypto()
    inner = {}
    if expires_at_unix is not None:
        inner["expiresAt"] = expires_at_unix / 1000.0 - APPLE_EPOCH
    if cellular_only:
        inner["cellularOnly"] = True
    pw_env = None
    if password:
        salt = rng(16)
        nonce = rng(12)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                         iterations=PASSWORD_ITERATIONS_SEAL)
        key = kdf.derive(password.encode("utf-8"))
        ct = ChaCha20Poly1305(key).encrypt(nonce, config.encode("utf-8"), None)
        pw_env = {"salt": b64std_encode(salt),
                  "iterations": PASSWORD_ITERATIONS_SEAL,
                  "ciphertext": b64std_encode(nonce + ct)}
        inner["passwordEnvelope"] = pw_env
    else:
        inner["config"] = config

    def inner_for(device_id_str):
        # uo.b builds the inner JSON per record with that record's deviceID
        doc = {"deviceID": device_id_str}
        doc.update(inner)
        return json.dumps(doc).encode("utf-8")

    records = []
    for did in (device_ids or []):
        pub = b64url_decode(did)
        if len(pub) != 64:
            raise SniError("Invalid Device ID: %s..." % did[:12])
        _ec_pub(pub)  # validates the point is on P-256
        records.append(seal_record(pub, did, inner_for(did), rng))
    app_priv, app_pub = app_keypair()
    records.append(seal_record(app_pub, APP_OPEN_ID,
                               inner_for(APP_OPEN_ID), rng))
    env = {"version": 2 if password else 1, "name": name, "records": records}
    if password:
        env["passwordProtected"] = True
    if cellular_only:
        env["cellularOnly"] = True
    if expires_at_unix is not None:
        env["expiresAt"] = expires_at_unix / 1000.0 - APPLE_EPOCH
    return "v2rc://" + b64url_encode(json.dumps(env).encode("utf-8"))


# ---------------------------------------------------------------- v2rcloud

def parse_v2rcloud_link(text):
    """a4.a: v2rcloud:// + 39 base64url chars = 29 bytes:
    [0]=1, [1:13]=token id, [13:29]=AES key (16 B)."""
    raw = "".join(str(text).split())
    if not raw.lower().startswith("v2rcloud://"):
        raise SniError("The cloud config link is invalid.")
    payload = raw[len("v2rcloud://"):]
    if len(payload) != 39:
        raise SniError("The cloud config link is invalid.")
    data = b64url_decode(payload)
    if len(data) != 29 or data[0] != 1:
        raise SniError("This cloud config link needs a newer app version.")
    token_id = data[1:13]
    key = data[13:29]
    return {
        "token_b64": b64url_encode(token_id),
        "token_id": token_id,
        "key": key,
    }


def build_v2rcloud_link(token_b64, key16):
    """a4.d: build a v2rcloud:// link from a token id and a 16-byte key."""
    token = b64url_decode(token_b64)
    if len(token) != 12 or len(key16) != 16:
        raise SniError("The cloud config link is invalid.")
    return "v2rcloud://" + b64url_encode(b"\x01" + token + key16)


def cloud_device_hash(token_b64, device_id):
    """a4.c: hex(SHA-256("v2rcloud-device-v1|"+tokenB64+"|"+deviceID))."""
    msg = ("v2rcloud-device-v1|%s|%s" % (token_b64, device_id)).encode("utf-8")
    return hashlib.sha256(msg).hexdigest()


def _cloud_request(method, path, body=None):
    url = "https://%s/v1/configs%s" % (CLOUD_HOST, path)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", CLOUD_UA)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8") or "{}")
        except Exception:
            payload = {"error": "http_%d" % exc.code}
        return exc.code, payload
    except Exception as exc:
        raise SniError("cloud request failed: %s" % exc)


def cloud_metadata(token_b64):
    """GET /v1/configs/<token> -> metadata (v0.x)."""
    return _cloud_request("GET", "/" + token_b64)


def cloud_claim(link, android_id=None, device_id=None, package=PACKAGE):
    """Claim a v2rcloud:// link (v0.d + a4.f). Returns the v2rc:// string.
    Needs the device identity for the deviceHash proof; without an
    Android ID the proof is omitted (server may answer device_required)."""
    parsed = parse_v2rcloud_link(link)
    proof = None
    if android_id:
        _, did = device_keypair(android_id, package)
        proof = cloud_device_hash(parsed["token_b64"], did)
    elif device_id:
        proof = cloud_device_hash(parsed["token_b64"], device_id)
    body = {"deviceHash": proof} if proof else {}
    status, payload = _cloud_request("POST",
                                     "/%s/claim" % parsed["token_b64"], body)
    if status < 200 or status >= 300:
        raise SniError("cloud claim failed: HTTP %d %s"
                       % (status, payload.get("error", payload)))
    blob = b64std_decode(payload["ciphertext"])
    if len(blob) < 12 + 16:
        raise SniError("cloud payload is invalid")
    try:
        plain = AESGCM(parsed["key"]).decrypt(blob[:12], blob[12:], None)
    except Exception as exc:
        raise SniError("cloud payload AES-GCM failed (%s)" % exc)
    return {"v2rc": plain.decode("utf-8"), "remaining": payload.get("remaining"),
            "status": status}


def cloud_create(v2rc_link, key16=None, expires_at_unix=None,
                 bind_device=False, max_claims=None, rng=os.urandom):
    """Create a cloud link (v0.e + a4.g + a4.d). Returns the v2rcloud://
    link and the server response. expires_at_unix defaults to +24h."""
    _require_crypto()
    key = key16 if key16 is not None else rng(16)
    nonce = rng(12)
    ct = AESGCM(key).encrypt(nonce, v2rc_link.encode("utf-8"), None)
    ciphertext = b64std_encode(nonce + ct)
    if len(ciphertext) > 8192:
        raise SniError("PAYLOAD_TOO_LARGE")
    if expires_at_unix is None:
        expires_at_unix = time.time() + 86400
    expires_ms = int(expires_at_unix * 1000)
    delta = expires_ms - int(time.time() * 1000)
    if not (300000 <= delta <= 2592000000):
        raise SniError("INVALID_POLICY (lifetime must be 5 min .. 30 days)")
    if max_claims is not None and not (1 <= max_claims <= 1000):
        raise SniError("INVALID_POLICY (maxClaims must be 1..1000)")
    body = {"ciphertext": ciphertext, "expiresAt": expires_ms,
            "bindDevice": bool(bind_device),
            "maxClaims": max_claims}
    status, payload = _cloud_request("POST", "", body)
    if status < 200 or status >= 300:
        raise SniError("cloud create failed: HTTP %d %s"
                       % (status, payload.get("error", payload)))
    token_b64 = payload["token"]
    return {"link": build_v2rcloud_link(token_b64, key),
            "token": token_b64, "response": payload}


# ---------------------------------------------------------------- standard links

def _b64_json_or_text(s):
    try:
        return json.loads(b64url_decode(s).decode("utf-8"))
    except Exception:
        return None


def parse_vmess(link):
    body = link[len("vmess://"):]
    data = _b64_json_or_text(body)
    if not isinstance(data, dict):
        raise SniError("invalid vmess:// link")
    return {"type": "vmess", "name": data.get("ps", ""),
            "address": data.get("add", ""), "port": data.get("port", ""),
            "uuid": data.get("id", ""), "alter_id": data.get("aid", ""),
            "network": data.get("net", ""), "tls": data.get("tls", ""),
            "host": data.get("host", ""), "path": data.get("path", ""),
            "sni": data.get("sni", ""), "raw": data}


def parse_url_link(link):
    """vless://, trojan://, ss://, hysteria2://, hy2://, tuic://,
    socks://, ssh:// -- URL form (wo.c export shape)."""
    scheme = link.split("://", 1)[0].lower()
    rest, _, frag = link.partition("#")
    name = urllib.parse.unquote(frag)
    u = urllib.parse.urlparse(rest)
    out = {"type": scheme, "name": name,
           "address": u.hostname or "", "port": u.port or "",
           "query": dict(urllib.parse.parse_qsl(u.query))}
    if scheme in ("vless", "trojan"):
        out["uuid_or_password"] = urllib.parse.unquote(u.username or "")
    elif scheme == "ss":
        # ss://<base64(method:password)@host:port> or ss://<base64(full)>
        userinfo = u.username or ""
        try:
            decoded = b64url_decode(userinfo).decode("utf-8")
            if ":" in decoded and "@" not in decoded:
                method, _, pwd = decoded.partition(":")
                out["method"], out["password"] = method, pwd
            else:
                out["userinfo_b64"] = userinfo
        except Exception:
            # whole body may be base64 of method:password@host:port
            try:
                full = b64url_decode(
                    link[len("ss://"):].split("#")[0].split("@")[0]
                    + "@" + (u.hostname or "")).decode("utf-8", "ignore")
                out["decoded"] = full
            except Exception:
                out["userinfo_b64"] = userinfo
        if u.password:
            out["password"] = urllib.parse.unquote(u.password)
    elif scheme in ("hysteria2", "hy2"):
        out["password"] = urllib.parse.unquote(u.password or u.username or "")
        out["sni"] = out["query"].get("sni", "")
    elif scheme == "tuic":
        out["uuid"] = urllib.parse.unquote(u.username or "")
        out["password"] = urllib.parse.unquote(u.password or "")
    elif scheme in ("socks", "socks5"):
        out["username"] = urllib.parse.unquote(u.username or "")
        out["password"] = urllib.parse.unquote(u.password or "")
    elif scheme == "ssh":
        out["username"] = urllib.parse.unquote(u.username or "")
        out["password"] = urllib.parse.unquote(u.password or "")
    return out


def parse_link(link):
    link = link.strip()
    low = link.lower()
    if low.startswith("vmess://"):
        return parse_vmess(link)
    if low.startswith(("vless://", "trojan://", "ss://", "hysteria2://",
                       "hy2://", "tuic://", "socks://", "socks5://",
                       "ssh://")):
        return parse_url_link(link)
    if low.startswith("v2rc://"):
        return {"type": "v2rc", "link": link}
    if low.startswith("v2rcloud://"):
        return {"type": "v2rcloud", "link": link}
    if link.startswith("{"):
        try:
            doc = json.loads(link)
        except Exception as exc:
            raise SniError("invalid V2Ray JSON (%s)" % exc)
        return {"type": "v2ray-json", "document": doc}
    raise SniError("unsupported link: %.40s..." % link)


# ---------------------------------------------------------------- subscription

def fetch_subscription(url):
    """SubscriptionHttpClient.fetch: HTTPS only, no credentials in the URL,
    UA "SNI-Tunnel/1.3.7 (Android)", up to 5 redirects, 16 MB cap."""
    uri = urllib.parse.urlparse(url)
    if uri.scheme.lower() != "https" or not uri.hostname:
        raise SniError("Subscription URL must use HTTPS.")
    if uri.username or uri.password:
        raise SniError("Subscription URL must not contain credentials.")
    req = urllib.request.Request(url)
    req.add_header("User-Agent", SUBSCRIPTION_UA)
    opener = urllib.request.build_opener(_RedirectLimit(5))
    try:
        with opener.open(req, timeout=30) as resp:
            body = resp.read(SUBSCRIPTION_MAX_BYTES + 1)
            if len(body) > SUBSCRIPTION_MAX_BYTES:
                raise SniError("subscription exceeds 16 MB")
            userinfo = _parse_userinfo(
                resp.headers.get("subscription-userinfo", "")
                or resp.headers.get("x-subscription-userinfo", ""))
            return {"url": resp.geturl(), "status": resp.status,
                    "userinfo": userinfo, "body": body.decode("utf-8", "replace")}
    except urllib.error.HTTPError as exc:
        raise SniError("subscription fetch failed: HTTP %d" % exc.code)
    except SniError:
        raise
    except Exception as exc:
        raise SniError("subscription fetch failed: %s" % exc)


class _RedirectLimit(urllib.request.HTTPRedirectHandler):
    def __init__(self, max_redirects):
        self.max_redirects = max_redirects
        self.count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.count += 1
        if self.count > self.max_redirects:
            raise SniError("too many redirects (>%d)" % self.max_redirects)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _parse_userinfo(header):
    out = {}
    for part in (header or "").split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip()] = v.strip()
    return out


def _strip_comments(text):
    lines = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#") or s.startswith("//"):
            continue
        lines.append(line)
    return "\n".join(lines)


def _decode_if_base64(text):
    """SubscriptionContent.decodeIfBase64: if the whole body is base64,
    decode it once and re-check."""
    compact = re.sub(r"\s+", "", text)
    if len(compact) >= 8 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        try:
            decoded = b64url_decode(compact).decode("utf-8")
            if any(k in decoded for k in
                   ("://", "proxies:", "outbounds", "{")):
                return decoded
        except Exception:
            pass
    return text


def parse_subscription_body(body):
    """SubscriptionContent.parse: lines of links, Clash YAML, or a
    single-outbound V2Ray/Xray JSON document."""
    text = _decode_if_base64(_strip_comments(body))
    text = _strip_comments(text)
    if text.lstrip().startswith("{"):
        try:
            doc = json.loads(text)
            return {"format": "v2ray-json", "document": doc,
                    "profiles": _profiles_from_v2ray_json(doc)}
        except Exception:
            pass
    if re.search(r"(?m)^proxies\s*:", text):
        return {"format": "clash-yaml", "profiles": _profiles_from_clash(text)}
    profiles, failures = [], 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            profiles.append(parse_link(line))
        except SniError:
            failures += 1
    return {"format": "links", "profiles": profiles, "failures": failures}


def _profiles_from_v2ray_json(doc):
    out = []
    for ob in doc.get("outbounds", []) if isinstance(doc, dict) else []:
        out.append({"type": "v2ray-json-outbound",
                    "protocol": ob.get("protocol"),
                    "settings": ob.get("settings", {}),
                    "stream_settings": ob.get("streamSettings", {})})
    return out


def _profiles_from_clash(text):
    """Minimal Clash YAML proxy-list parse (no PyYAML dependency):
    only name/type/server/port are extracted per entry."""
    profiles, cur = [], None
    for line in text.splitlines():
        m = re.match(r"\s*-\s+name\s*:\s*(.+)", line)
        if m:
            cur = {"type": "clash", "name": m.group(1).strip().strip("\"'")}
            profiles.append(cur)
            continue
        if cur is not None:
            m = re.match(r"\s+(type|server|port)\s*:\s*(.+)", line)
            if m:
                cur[m.group(1)] = m.group(2).strip().strip("\"'")
    return profiles


# ---------------------------------------------------------------- CLI

def _dump(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def main(argv):
    ap = argparse.ArgumentParser(
        prog="sni_tunnel",
        description="SNI Tunnel 1.3.7 -- v2rc:// / .v2rc / v2rcloud:// / "
                    "link / subscription decoder (no catalog exists).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("v2rc", help="open a v2rc:// link or .v2rc file")
    p.add_argument("input", help="v2rc:// link, or path to a .v2rc file")
    p.add_argument("--password", default=None)
    p.add_argument("--android-id", default=None,
                   help="ANDROID_ID of the recipient device (device record)")
    p.add_argument("--package", default=PACKAGE)

    p = sub.add_parser("seal", help="build a v2rc:// link (round-trip test)")
    p.add_argument("config", help="standard link to seal")
    p.add_argument("--name", default="test")
    p.add_argument("--password", default=None)
    p.add_argument("--device-id", action="append", default=[])
    p.add_argument("--expires-at", type=float, default=None,
                   help="expiry as unix seconds")
    p.add_argument("--cellular-only", action="store_true")

    p = sub.add_parser("link", help="parse a standard config link")
    p.add_argument("link")

    p = sub.add_parser("subscription", help="fetch + parse a subscription URL")
    p.add_argument("url")

    p = sub.add_parser("cloud", help="claim a v2rcloud:// link")
    p.add_argument("link")
    p.add_argument("--android-id", default=None)
    p.add_argument("--device-id", default=None)
    p.add_argument("--password", default=None,
                   help="if the claimed bundle is password-protected, "
                        "open it as well")

    p = sub.add_parser("cloud-meta", help="GET cloud metadata for a token")
    p.add_argument("token", help="token id (16-char base64url) or full link")

    p = sub.add_parser("device-id", help="derive the device ID from ANDROID_ID")
    p.add_argument("android_id")
    p.add_argument("--package", default=PACKAGE)

    args = ap.parse_args(argv)

    if args.cmd == "v2rc":
        text = args.input
        if os.path.isfile(text):
            with open(text, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        res = open_v2rc(text, password=args.password,
                        android_id=args.android_id, package=args.package)
        out = {
            "name": res["name"], "version": res["version"],
            "password_protected": res["password_protected"],
            "cellular_only": res["cellular_only"],
            "expires_at": (fmt_ts(res["expires_at_unix"])
                           if res["expires_at_unix"] else None),
            "expired": res["expired"],
            "record_kind": res["record_kind"],
            "device_id": res["device_id"],
            "inner_expires_at": (fmt_ts(res["inner_expires_at_unix"])
                                 if res["inner_expires_at_unix"] else None),
            "inner_expired": res.get("inner_expired"),
            "config": res["config"],
        }
        if res["password_envelope"] is not None and res["config"] is None:
            pe = res["password_envelope"]
            out["password_envelope"] = {
                "salt_hex": b64std_decode(pe["salt"]).hex(),
                "iterations": pe["iterations"],
                "ciphertext_bytes": len(b64std_decode(pe["ciphertext"])),
                "plaintext_bytes": len(b64std_decode(pe["ciphertext"])) - 28,
                "status": "STILL ENCRYPTED -- password required",
            }
        if res["config"]:
            try:
                out["parsed_config"] = parse_link(res["config"])
            except SniError:
                out["parsed_config"] = None
        _dump(out)
        return 0

    if args.cmd == "seal":
        print(seal_v2rc(args.config, args.name, password=args.password,
                        device_ids=args.device_id,
                        expires_at_unix=args.expires_at,
                        cellular_only=args.cellular_only))
        return 0

    if args.cmd == "link":
        _dump(parse_link(args.link))
        return 0

    if args.cmd == "subscription":
        fetched = fetch_subscription(args.url)
        parsed = parse_subscription_body(fetched["body"])
        _dump({"url": fetched["url"], "status": fetched["status"],
               "userinfo": fetched["userinfo"], **parsed})
        return 0

    if args.cmd == "cloud":
        claimed = cloud_claim(args.link, android_id=args.android_id,
                              device_id=args.device_id)
        out = {"remaining": claimed["remaining"], "v2rc": claimed["v2rc"]}
        try:
            res = open_v2rc(claimed["v2rc"], password=args.password,
                            android_id=args.android_id)
            out["opened"] = {"name": res["name"],
                             "config": res["config"],
                             "record_kind": res["record_kind"]}
        except SniError as exc:
            out["opened"] = {"error": str(exc)}
        _dump(out)
        return 0

    if args.cmd == "cloud-meta":
        token = args.token
        if token.startswith("v2rcloud://"):
            token = parse_v2rcloud_link(token)["token_b64"]
        status, payload = cloud_metadata(token)
        _dump({"status": status, "metadata": payload})
        return 0

    if args.cmd == "device-id":
        _, did = device_keypair(args.android_id, args.package)
        _dump({"device_id": did, "device_id_hash": device_id_hash(did)})
        return 0

    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except SniError as exc:
        print("error: %s" % exc, file=sys.stderr)
        sys.exit(1)
