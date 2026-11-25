#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Katiba VPN (com.v2ray.adsnetjx) - catalog / config decoder for SP-DECODE.

Method (reversed from the APK, libgojni.so / github.com/2dust/AndroidLibXrayLite):
  * Live catalog: POST https://strongteam.co/api/katibanew/
        Content-Type: application/x-www-form-urlencoded
        User-Agent: Go-http-client/1.1
        body: hash=xsandokUpdatex
    Response body -> decrypt_catalog() -> JSON (Version, Servers, Networks).
  * Bundled catalog (assets/configfile.json) and .katiba files: decrypt_file().
  * Both schemes are Argon2id (time=3, memory=8192 KiB, threads=1, keyLen=32)
    + AES-256-GCM. Layout of the base64 payload:
        raw = salt(16) || nonce(12) || ciphertext+tag(16)
        key = Argon2id(password, salt); AAD = salt.
    The live-catalog scheme additionally inserts ONE random [a-zA-Z] letter
    at index 3 of the base64 text (decrypt drops the char at index 3 first);
    the file/bundled scheme has no inserted char.
  * Per-server fields (ServerIPHost, V2rayUUID, OVPNUser, OVPNPass, UDP_obfs,
    UDP_user, CustomCertificate, SlowDNSHost, SlowDNSKey, H2pass, TrojanPass)
    are each encrypted with the FILE scheme (decrypt_field()).
  * Per-network fields (Payload, SNI, V2rayConfig, V2rayAddress, V2rayHost,
    V2raySNI, CustomProxy, BugDNS) are ALSO each encrypted with the FILE
    scheme when their value is an encrypted blob. A value is treated as a
    blob only if it is pure base64 that decodes to >= 28 bytes; anything
    else (plain hostnames, templates, "8.8.8.8", OVPN text) is left as-is.
    Fields whose blob does NOT decrypt with either app password are kept
    verbatim and reported (see decrypt_catalog_full()): in the 2026-11-25
    live catalog v1.12 those are 21 values in 15 networks, encrypted under
    a key that is NOT in this APK (see "Undecryptable values" below).
  * SlowDNSKey: after decryption it is a 64-hex-char string (32 bytes).
    That IS the real value as the app uses it, not another encryption
    layer: the live catalog (v1.12) and the bundled asset (v1.01) carry
    different ciphertexts that both decrypt to the identical hex string,
    and 64 hex chars = the 32-byte SlowDNS key. It is a credential, so it
    is stripped from the redacted catalog like the other secrets.
  * Text links: v2rayng://install-config?url=<config-uri>
                v2rayng://install-sub?url=<subscription-url>
    Inner config URIs accepted by the app: vmess://, vless://, trojan://,
    wireguard://, ss:// (stock v2rayNG parser).
  * Files: *.katiba (mime application/x-katiba), max 2 MB, EO-encrypted JSON
    with keys Name / TunnelType (+ raw config). Decrypt with decrypt_file().

Undecryptable values (live catalog v1.12, 2026-11-25; same values appear
byte-identical in the bundled asset v1.01, i.e. they were never re-encrypted
with the current key):
  * 21 field values in 15 networks fail the FILE scheme (and also the live
    scheme, 224 password-shaped DEX strings, the sibling strongteam.co apps'
    passwords, Argon2 time/memory/type variants, AES-GCM layout/AAD
    variants, ChaCha20-Poly1305, AES-CBC/CTR/ChaCha20 raw). The APK holds
    exactly two crypto passwords (adjacent constants in libgojni.so, used by
    EO/DO/Encrypt/decrypt); no third key exists in the APK. The 28-byte
    CustomProxy blobs (base64 length 40) cannot even fit the
    salt(16)+nonce(12)+tag(16) layout, and the same 28-byte blob is shared
    verbatim by 4 networks, which rules out randomized per-value encryption.
    Conclusion: these entries were encrypted under a key that is not in
    this APK (rotated-out / server-side-only / another app's key) and cannot
    be decrypted from the APK. The script keeps them verbatim and reports
    them instead of inventing plaintext.

Requires: argon2-cffi, pycryptodome. (pip install argon2-cffi pycryptodome)

Usage:
  katiba.py live [--out FILE] [--decrypt]  fetch + decrypt the live catalog
  katiba.py asset FILE [--out F] [--decrypt]
                                     decrypt bundled assets/configfile.json
  katiba.py file FILE.katiba         decrypt a .katiba config file
  katiba.py encrypt FILE [--out F]   encrypt a JSON/text file (.katiba format)
  katiba.py redact CATALOG.json [--out F]
                                     decrypted catalog with secrets scrubbed
  katiba.py self-test                round-trip + known-vector checks
  katiba.py vless --server N --network M [--catalog FILE]
                                     build a vless:// link from the catalog

VERIFIED_REAL (2026-11-25): live catalog v1.12 (57 servers, 235 networks)
  decrypted from the live endpoint; bundled asset v1.01 (5 servers,
  258 networks) decrypted from the APK. The .katiba FILE container itself
  is VERIFIED_SYNTHETIC: no real exported .katiba sample exists yet; the
  crypto is identical to the bundled asset (proven), only the JSON shape
  (Name/TunnelType) comes from the app bytecode. A real .katiba exported
  from the app would confirm it end to end.
"""

import argparse
import base64
import json
import os
import random
import re
import string
import subprocess
import sys
import urllib.request

API_URL = "https://strongteam.co/api/katibanew/"
API_FORM = "hash=xsandokUpdatex"
API_HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Go-http-client/1.1",
}
# App constants (hardcoded in libgojni.so, needed to run the decoder).
CATALOG_PASSWORD = b"IEdYXDOsmDku64+xQnmcgNzNcqeENRxK"   # live API (Encrypt/decrypt)
FILE_PASSWORD = b"VvyTjWkeii0u47zu1AJTjqck1+YXomBQ"      # .katiba / asset (EO/DO)

ARGON_TIME = 3
ARGON_MEMORY = 8192  # KiB
ARGON_THREADS = 1
ARGON_KEYLEN = 32

LETTERS = string.ascii_letters  # randomLetter() table in the app

# Fields of each server record that are individually encrypted (file scheme).
ENCRYPTED_SERVER_FIELDS = [
    "ServerIPHost", "OVPNUser", "OVPNPass", "UDP_obfs", "UDP_user",
    "CustomCertificate", "SlowDNSHost", "SlowDNSKey", "V2rayUUID",
    "H2pass", "TrojanPass",
]

# Fields of each network record that may be individually encrypted (file
# scheme). Only values that look like encrypted blobs are attempted.
ENCRYPTED_NETWORK_FIELDS = [
    "Payload", "SNI", "V2rayConfig", "V2rayAddress", "V2rayHost",
    "V2raySNI", "CustomProxy", "BugDNS",
]

# Top-level catalog fields that may be individually encrypted (file scheme).
ENCRYPTED_TOP_FIELDS = [
    "DefOVPNUser", "DefOVPNPass", "HysteriaUser", "HysteriaOBFS",
    "DefaultOVPNCert",
]

# Credential fields stripped from the redacted catalog (kept only in the
# analyst's full copy). Hostnames/addresses are NOT credentials.
SECRET_FIELDS = [
    "DefOVPNUser", "DefOVPNPass", "HysteriaUser", "HysteriaOBFS",
    "DefaultOVPNCert", "OVPNUser", "OVPNPass", "UDP_obfs", "UDP_user",
    "CustomCertificate", "SlowDNSKey", "V2rayUUID", "H2pass", "TrojanPass",
]

# Pure-base64 text (standard alphabet, optional padding). Encrypted blobs
# are base64; plaintext values in this catalog (hostnames, templates,
# "8.8.8.8", OVPN text, payloads with [crlf]/spaces) never match.
_BLOB_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}")
_PW_RE = re.compile(r'("password"\s*:\s*")[^"]*(")')
_TROJAN_USER_RE = re.compile(r"(trojan://)[^@\s]+(@)")


def _looks_encrypted(value):
    """True if a string value could be an encrypted blob: pure base64,
    at least 40 chars, decoding to at least 28 bytes (salt+nonce)."""
    if not isinstance(value, str) or len(value) < 40:
        return False
    if not _BLOB_RE.match(value):
        return False
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4))
    except Exception:
        return False
    return len(raw) >= 28


def _argon2_key(password, salt):
    try:
        from argon2.low_level import hash_secret_raw, Type
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "argon2-cffi is required (pip install argon2-cffi)") from exc
    return hash_secret_raw(
        password, salt, time_cost=ARGON_TIME, memory_cost=ARGON_MEMORY,
        parallelism=ARGON_THREADS, hash_len=ARGON_KEYLEN, type=Type.ID)


def _aes_gcm_decrypt(key, nonce, ciphertext, aad):
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "pycryptodome is required (pip install pycryptodome)") from exc
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])


def _aes_gcm_encrypt(key, nonce, plaintext, aad):
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "pycryptodome is required (pip install pycryptodome)") from exc
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return ct + tag


def _b64decode(text):
    text = text.strip()
    text += "=" * (-len(text) % 4)
    return base64.b64decode(text)


def _decrypt_raw(raw, password):
    """raw = salt(16) || nonce(12) || ciphertext+tag -> plaintext bytes."""
    if len(raw) < 28:
        raise ValueError("ciphertext too short: %d bytes" % len(raw))
    salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
    key = _argon2_key(password, salt)
    return _aes_gcm_decrypt(key, nonce, ct, salt)


def _encrypt_raw(plaintext, password, salt=None, nonce=None):
    """-> base64(salt(16) || nonce(12) || ciphertext+tag)."""
    if salt is None:
        salt = os.urandom(16)
    if nonce is None:
        nonce = os.urandom(12)
    key = _argon2_key(password, salt)
    blob = salt + nonce + _aes_gcm_encrypt(key, nonce, plaintext, salt)
    return base64.b64encode(blob).decode("ascii")


def decrypt_catalog(text):
    """Live-API scheme: drop the inserted char at index 3, then decrypt."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    text = text.strip()
    if len(text) > 3:
        text = text[:3] + text[4:]
    return _decrypt_raw(_b64decode(text), CATALOG_PASSWORD)


def decrypt_file(text):
    """Bundled-asset / .katiba scheme: no inserted char."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    return _decrypt_raw(_b64decode(text.strip()), FILE_PASSWORD)


def decrypt_field(value):
    """One individually-encrypted server/network field (file scheme).
    '' stays ''."""
    if not value:
        return ""
    return decrypt_file(value).decode("utf-8", "replace")


def encrypt_file(plaintext, salt=None, nonce=None):
    """Encrypt to the .katiba / bundled-asset format (base64, no insert)."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    return _encrypt_raw(plaintext, FILE_PASSWORD, salt, nonce)


def encrypt_catalog(plaintext, salt=None, nonce=None, letter=None):
    """Encrypt to the live-API format (one random letter inserted at index 3)."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    b64 = _encrypt_raw(plaintext, CATALOG_PASSWORD, salt, nonce)
    if len(b64) <= 3:
        return b64
    if letter is None:
        letter = random.choice(LETTERS)
    return b64[:3] + letter + b64[3:]


def _try_decrypt_field(value, failures, location):
    """Decrypt one field value if it looks encrypted. Returns the
    (possibly unchanged) value; records undecryptable blobs in failures."""
    if not _looks_encrypted(value):
        return value
    try:
        return decrypt_field(value)
    except Exception:
        failures.append((location, value))
        return value


def fetch_live_raw(timeout=30):
    """Fetch the raw live-catalog response body (still encrypted).
    urllib first; curl fallback (the endpoint sometimes truncates chunked
    responses to urllib). Returns the response text."""
    last_exc = None
    for _attempt in range(2):
        try:
            req = urllib.request.Request(
                API_URL, data=API_FORM.encode("ascii"), method="POST",
                headers=API_HEADERS)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", "replace")
        except Exception as exc:  # IncompleteRead and friends
            last_exc = exc
    try:
        proc = subprocess.run(
            ["curl", "-sS", "-X", "POST", API_URL,
             "-H", "Content-Type: application/x-www-form-urlencoded",
             "-H", "User-Agent: Go-http-client/1.1",
             "--data", API_FORM, "--max-time", str(timeout)],
            capture_output=True, text=True, timeout=timeout + 10)
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout
    except Exception as exc:  # pragma: no cover
        last_exc = exc
    raise RuntimeError(
        "live catalog fetch failed (urllib + curl): %s" % last_exc)


def fetch_live(timeout=30):
    """Replicate the app's exact catalog request (CU in libgojni.so)."""
    body = fetch_live_raw(timeout=timeout)
    return json.loads(decrypt_catalog(body).decode("utf-8"))


def decrypt_catalog_full(catalog):
    """Return (decrypted_catalog, failures): a copy of the catalog with
    every individually-encrypted field replaced by its decrypted value
    (servers, networks and top-level fields), plus a list of
    (location, raw_value) for blob values that did not decrypt with the
    app's keys. Undecryptable values are kept verbatim, never dropped."""
    out = json.loads(json.dumps(catalog))
    failures = []
    for field in ENCRYPTED_TOP_FIELDS:
        value = out.get(field)
        if value:
            out[field] = _try_decrypt_field(
                value, failures, "Top." + field)
    for idx, server in enumerate(out.get("Servers", [])):
        for field in ENCRYPTED_SERVER_FIELDS:
            value = server.get(field)
            if value:
                server[field] = _try_decrypt_field(
                    value, failures, "Servers[%d].%s" % (idx, field))
    for idx, network in enumerate(out.get("Networks", [])):
        for field in ENCRYPTED_NETWORK_FIELDS:
            value = network.get(field)
            if value:
                network[field] = _try_decrypt_field(
                    value, failures, "Networks[%d].%s" % (idx, field))
    return out, failures


def decrypt_catalog_dict(catalog):
    """Return a copy of the catalog with every encrypted field replaced
    by its decrypted value (full catalog, WITH credentials). Values that
    do not decrypt are kept verbatim; use decrypt_catalog_full() to list
    them."""
    out, _failures = decrypt_catalog_full(catalog)
    return out


def _scrub_text(value):
    """Scrub credentials embedded in a text/template value: VLESS/Trojan
    UUIDs, trojan:// userinfo, and JSON "password" values."""
    if not isinstance(value, str):
        return value
    value = _UUID_RE.sub("[redacted-uuid]", value)
    value = _TROJAN_USER_RE.sub(r"\1[redacted]\2", value)
    value = _PW_RE.sub(r"\1[redacted]\2", value)
    return value


def redact_catalog(catalog):
    """Return a copy safe to share: decrypted hosts kept, credential
    fields removed, credentials embedded in network templates scrubbed.
    Never put the full catalog in a ZIP or Drive."""
    out, _failures = decrypt_catalog_full(catalog)
    for field in SECRET_FIELDS:
        out.pop(field, None)
    for server in out.get("Servers", []):
        for field in SECRET_FIELDS:
            server.pop(field, None)
    for network in out.get("Networks", []):
        for field, value in list(network.items()):
            network[field] = _scrub_text(value)
    return out


def vless_link(server, network=None):
    """Build a vless:// link from a catalog server (+ optional network),
    following the app's own V2rayConfig template:
    vless://[id]@[address]:[port]?mode=auto&path=[path]&security=tls
    &insecure=1&encryption=none&host=[server]&fp=chrome"""
    uuid = server.get("V2rayUUID") or ""
    host = server.get("ServerIPHost") or ""
    path = server.get("V2rayPath") or ""
    address = host
    port = "443"
    extra = ""
    if network:
        address = network.get("V2rayAddress") or address
        port = str(network.get("V2rayPort") or port)
        template = network.get("V2rayConfig") or ""
        if template:
            link = (template.replace("[id]", uuid)
                    .replace("[path]", path)
                    .replace("[server]", host)
                    .replace("[host]", host))
            return link
    query = ("mode=auto&path=%s&security=tls&insecure=1"
             "&encryption=none&host=%s&fp=chrome" % (path, host))
    return "vless://%s@%s:%s?%s#%s" % (
        uuid, address, port, query, server.get("Name", "").strip())


def _load_catalog(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _save_json(path, data):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=1)


def cmd_live(args):
    catalog = fetch_live()
    print("Version: %s" % catalog.get("Version"))
    print("Servers: %d" % len(catalog.get("Servers", [])))
    print("Networks: %d" % len(catalog.get("Networks", [])))
    if args.decrypt:
        catalog, failures = decrypt_catalog_full(catalog)
        print("Undecryptable field values kept verbatim: %d" % len(failures))
        for location, _value in failures:
            print("  - %s" % location)
    if args.out:
        _save_json(args.out, catalog)
        print("saved: %s" % args.out)


def cmd_asset(args):
    with open(args.file, "r", encoding="utf-8") as fh:
        text = fh.read()
    data = json.loads(decrypt_file(text).decode("utf-8"))
    print("Version: %s" % data.get("Version"))
    print("Servers: %d" % len(data.get("Servers", [])))
    print("Networks: %d" % len(data.get("Networks", [])))
    if args.decrypt:
        data, failures = decrypt_catalog_full(data)
        print("Undecryptable field values kept verbatim: %d" % len(failures))
        for location, _value in failures:
            print("  - %s" % location)
    if args.out:
        _save_json(args.out, data)
        print("saved: %s" % args.out)


def cmd_file(args):
    with open(args.file, "r", encoding="utf-8") as fh:
        text = fh.read()
    data = json.loads(decrypt_file(text).decode("utf-8"))
    print(json.dumps(data, ensure_ascii=False, indent=1))
    if args.out:
        _save_json(args.out, data)
        print("saved: %s" % args.out)


def cmd_encrypt(args):
    with open(args.file, "rb") as fh:
        raw = fh.read()
    out = encrypt_file(raw)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out)
        print("saved: %s" % args.out)
    else:
        print(out)


def cmd_redact(args):
    catalog = _load_catalog(args.catalog)
    redacted = redact_catalog(catalog)
    print("Version: %s" % redacted.get("Version"))
    print("Servers: %d" % len(redacted.get("Servers", [])))
    print("Networks: %d" % len(redacted.get("Networks", [])))
    if args.out:
        _save_json(args.out, redacted)
        print("saved: %s" % args.out)


def cmd_vless(args):
    catalog = _load_catalog(args.catalog) if args.catalog else fetch_live()
    catalog = decrypt_catalog_dict(catalog)
    servers = catalog.get("Servers", [])
    networks = catalog.get("Networks", [])
    server = servers[args.server]
    network = networks[args.network] if args.network is not None else None
    print(vless_link(server, network))


def cmd_self_test(_args):
    sample = {"Name": "SelfTest", "TunnelType": "V2ray",
              "Version": "9.99", "Servers": [], "Networks": []}
    blob = json.dumps(sample, ensure_ascii=False).encode("utf-8")
    # 1. File scheme round-trip with fixed salt/nonce (deterministic vector).
    enc = encrypt_file(blob, salt=b"\x00" * 16, nonce=b"\x00" * 12)
    assert decrypt_file(enc) == blob, "file round-trip failed"
    # 2. Catalog scheme round-trip with a fixed inserted letter.
    enc2 = encrypt_catalog(blob, salt=b"\x01" * 16, nonce=b"\x02" * 12,
                           letter="Q")
    assert decrypt_catalog(enc2) == blob, "catalog round-trip failed"
    assert enc2[3] == "Q" and enc2[:3] + enc2[4:] == _encrypt_raw(
        blob, CATALOG_PASSWORD, b"\x01" * 16, b"\x02" * 12), "insert check"
    # 3. Per-field round-trip.
    enc3 = encrypt_file(b"de.tunnelmart.shop")
    assert decrypt_field(enc3) == "de.tunnelmart.shop", "field round-trip"
    # 4. Network-field round-trip through decrypt_catalog_full().
    net = {"Name": "N1", "Payload": encrypt_file(b"GET / HTTP/1.1[crlf]"),
           "SNI": encrypt_file(b"m.facebook.com"),
           "V2rayConfig": encrypt_file(b"vless://[id]@[host]:443"),
           "CustomProxy": encrypt_file(b""),
           "BugDNS": "8.8.8.8",
           "V2rayAddress": "plain.example.com"}
    cat = {"Version": "9.99", "Servers": [], "Networks": [net]}
    dec, failures = decrypt_catalog_full(cat)
    assert not failures, failures
    dnet = dec["Networks"][0]
    assert dnet["Payload"] == "GET / HTTP/1.1[crlf]", dnet
    assert dnet["SNI"] == "m.facebook.com", dnet
    assert dnet["V2rayConfig"] == "vless://[id]@[host]:443", dnet
    assert dnet["CustomProxy"] == "", dnet
    assert dnet["BugDNS"] == "8.8.8.8", dnet  # plaintext untouched
    assert dnet["V2rayAddress"] == "plain.example.com", dnet
    # 5. An undecryptable blob is kept verbatim and reported.
    bad = {"Version": "9.99", "Servers": [],
           "Networks": [{"Name": "N2",
                         "Payload": base64.b64encode(
                             b"\x00" * 40).decode("ascii")}]}
    dec2, failures2 = decrypt_catalog_full(bad)
    assert len(failures2) == 1 and failures2[0][0] == "Networks[0].Payload"
    assert dec2["Networks"][0]["Payload"] == bad["Networks"][0]["Payload"]
    # 6. Redaction scrubs UUIDs / passwords embedded in network templates.
    red = redact_catalog({
        "Version": "9.99", "DefOVPNUser": "x",
        "Servers": [{"Name": "S1", "ServerIPHost": "h.example.co",
                     "V2rayUUID": "0e59831d-ae88-4679-afa6-d1d16551a06a",
                     "SlowDNSKey": "00" * 32}],
        "Networks": [{"Name": "N1",
                      "V2rayConfig": "vless://0e59831d-ae88-4679-afa6-"
                      "d1d16551a06a@h.example.co:443",
                      "Payload": '{"password": "secret"}'}]})
    assert "DefOVPNUser" not in red, red
    assert "V2rayUUID" not in red["Servers"][0], red
    assert "SlowDNSKey" not in red["Servers"][0], red
    assert "0e59831d" not in json.dumps(red), red
    assert red["Networks"][0]["Payload"] == '{"password": "[redacted]"}', red
    assert red["Servers"][0]["ServerIPHost"] == "h.example.co", red
    # 7. vless link shape.
    link = vless_link({"Name": "Server 1", "V2rayUUID": "u",
                       "ServerIPHost": "de.example.co", "V2rayPath": "/sandok"})
    assert link.startswith("vless://u@de.example.co:443?"), link
    assert "path=/sandok" in link and "host=de.example.co" in link, link
    print("self-test OK: file + catalog round-trips, field decrypt, "
          "network decrypt, undecryptable kept+reported, redaction, "
          "vless link")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Katiba VPN catalog / .katiba decoder (SP-DECODE)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("live", help="fetch + decrypt the live catalog")
    p.add_argument("--out", help="save decrypted catalog JSON")
    p.add_argument("--decrypt", action="store_true",
                   help="also decrypt per-server/per-network fields")
    p.set_defaults(func=cmd_live)

    p = sub.add_parser("asset", help="decrypt bundled assets/configfile.json")
    p.add_argument("file")
    p.add_argument("--out", help="save decrypted catalog JSON")
    p.add_argument("--decrypt", action="store_true",
                   help="also decrypt per-server/per-network fields")
    p.set_defaults(func=cmd_asset)

    p = sub.add_parser("file", help="decrypt a .katiba config file")
    p.add_argument("file")
    p.add_argument("--out", help="save decrypted JSON")
    p.set_defaults(func=cmd_file)

    p = sub.add_parser("encrypt", help="encrypt a file to .katiba format")
    p.add_argument("file")
    p.add_argument("--out", help="save encrypted base64 text")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("redact", help="scrub secrets from a catalog JSON")
    p.add_argument("catalog")
    p.add_argument("--out", help="save redacted catalog JSON")
    p.set_defaults(func=cmd_redact)

    p = sub.add_parser("vless", help="build a vless:// link from the catalog")
    p.add_argument("--server", type=int, default=0)
    p.add_argument("--network", type=int, default=None)
    p.add_argument("--catalog", help="catalog JSON (default: fetch live)")
    p.set_defaults(func=cmd_vless)

    p = sub.add_parser("self-test", help="round-trip + known-vector checks")
    p.set_defaults(func=cmd_self_test)

    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
