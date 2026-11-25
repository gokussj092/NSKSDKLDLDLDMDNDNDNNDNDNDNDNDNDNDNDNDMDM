#!/usr/bin/env python3
"""Mehaf VPN (vpn.jx.udpstrong, v1.0.9.20) - catalog decoder for SP-DECODE.

Recovers the bundled catalog (assets/configfile.json) and decrypts every
encrypted field in it (server hosts, users, passwords, Hysteria obfs/user,
V2Ray UUID, SlowDNS host/key, custom certificates, and the encrypted
network payloads / V2Ray configs).

Method (recovered from libgojni.so, AndroidLibXrayLite.DO, Go 1.24.3):
  input  : base64 StdEncoding string
  bytes  : salt = b[0:16] | nonce = b[16:28] | ciphertext+tag = b[28:]
  key    : Argon2id(password, salt, time=3, memory=8192 KiB, threads=1,
           keyLen=32)
  cipher : AES-256-GCM, additionalData = salt
  A field that is not DO-encrypted is returned unchanged (the app itself
  falls back to the raw string when decryption fails).

Per-field evidence (classes2.dex, Mehaf VPN v1.0.9.20):
  The catalog models (com.v2ray.ang.viewmodel.ServerList / NetworkList)
  are plain Kotlin data classes: every getter is a bare field read, so
  decryption happens at the use sites, through
  Hometab$Companion.a(String) -- decompiled in the APK as
  `try { return Libv2ray.do_(str); } catch (Throwable) { return str; }`
  (DO-decrypt, raw fallback on any failure).
  HomeFragment.G0() (connection setup) applies Companion.a to
  ServerIPHost, SNI, CustomProxy, UDP_obfs, UDP_user, BugDNS,
  SlowDNSKey, SlowDNSHost, Payload, OVPNUser, OVPNPass (Elvis pattern:
  `field = field ?: getString(default); field = Companion.a(field)`).
  HomeFragment.E0() (VLESS link builder) applies Companion.a to
  ServerIPHost, V2rayUUID, Payload and V2rayConfig, and routes
  V2rayAddress / V2rayHost / V2raySNI through HomeFragment.v0(), which
  is Companion.a with a fallback value. HomeFragment.k0() applies
  Companion.a to CustomCertificate. This script mirrors exactly that:
  every field the app passes through Companion.a is DO-decrypted here,
  with the same raw fallback.
  SlowDNSKey is NOT a DO blob: the 64-hex-char value is identical on
  all 9 servers (a DO ciphertext carries a random 16-byte salt, so two
  equal DO outputs are impossible), do_ fails on it (GCM tag check),
  and Companion.a therefore returns it unchanged -- the app uses the
  hex string itself as the SlowDNS key (32 bytes in hex form). It is
  redacted from the public catalog like any other key.
  The V2Ray UUID marker (12345678-1234-1234-1234567B9o) is likewise not
  a DO blob: E0() passes it through Companion.a, which returns it
  unchanged, and the generated vless:// link uses it literally.

Usage:
  python3 mehafvpn.py <configfile.json> [--full out.json] [--redacted out.json]
  python3 mehafvpn.py --self-test

Requires: argon2-cffi, pycryptodome.
"""

import argparse
import base64
import json
import sys

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES

# Decryption key for the catalog/fields (constant embedded in libgojni.so).
PASSWORD = b'0wwSloVh9DWgmXVNMBkwDRnjVJJgkAgo'

# Server fields that are DO-encrypted (when non-empty).
# TrojanPass is empty on all 9 servers in this catalog; it is listed
# because the field is credential-bearing (and redacted below) and the
# app routes it through the same Companion.a path as the other fields.
SERVER_ENC_FIELDS = [
    'ServerIPHost', 'OVPNUser', 'OVPNPass', 'UDP_obfs', 'UDP_user',
    'V2rayUUID', 'H2pass', 'SlowDNSHost', 'SlowDNSKey', 'CustomCertificate',
    'TrojanPass',
]

# Network fields that may be DO-encrypted (when non-empty).
# The shipped v1 script only listed Payload and V2rayConfig and left 33
# DO blobs undecrypted in 8 networks (SNI, V2rayAddress, V2rayHost,
# V2raySNI, BugDNS). The app passes all of these through Companion.a
# in HomeFragment.G0() / E0() (see the module docstring), so they all
# belong here. CustomProxy is decrypted the same way in G0(); its
# values in this catalog are already plaintext hostnames/IPs.
NETWORK_ENC_FIELDS = ['Payload', 'V2rayConfig', 'SNI', 'V2rayAddress',
                      'V2rayHost', 'V2raySNI', 'BugDNS', 'CustomProxy']

# Credential-bearing fields, redacted from the public catalog.
REDACT_FIELDS = {
    'OVPNUser', 'OVPNPass', 'UDP_obfs', 'UDP_user', 'H2pass', 'SlowDNSKey',
    'V2rayUUID', 'CustomCertificate', 'TrojanPass',
}

# Top-level default credentials in the catalog.
REDACT_TOP_FIELDS = {
    'DefOVPNUser', 'DefOVPNPass', 'HysteriaUser', 'HysteriaOBFS',
}


def do_decrypt(text):
    """Decrypt one DO-encrypted base64 string. Raises on failure."""
    dec = base64.b64decode(text)
    if len(dec) < 28:
        raise ValueError('ciphertext too short')
    salt, nonce, ct = dec[:16], dec[16:28], dec[28:]
    key = hash_secret_raw(PASSWORD, salt, time_cost=3, memory_cost=8192,
                          parallelism=1, hash_len=32, type=Type.ID)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(salt)  # additionalData = salt
    return cipher.decrypt_and_verify(ct[:-16], ct[-16:]).decode('utf-8')


def do_maybe(text):
    """Decrypt if DO-encrypted, else return the raw string (app behaviour)."""
    if not text:
        return text
    try:
        return do_decrypt(text)
    except Exception:
        return text


def decrypt_catalog(blob_text):
    """Decrypt the bundled configfile.json blob -> ConfigData dict."""
    return json.loads(do_decrypt(blob_text.strip()))


def decrypt_full_catalog(cat):
    """Return a copy of the catalog with every encrypted field decrypted."""
    out = json.loads(json.dumps(cat))
    for srv in out.get('Servers', []):
        for f in SERVER_ENC_FIELDS:
            if srv.get(f):
                srv[f] = do_maybe(srv[f])
    for net in out.get('Networks', []):
        for f in NETWORK_ENC_FIELDS:
            if net.get(f):
                net[f] = do_maybe(net[f])
    return out


def redact_catalog(cat):
    """Return a copy of the (decrypted) catalog with credentials removed."""
    out = decrypt_full_catalog(cat)
    for f in REDACT_TOP_FIELDS:
        if out.get(f):
            out[f] = '[REDACTED]'
    for srv in out.get('Servers', []):
        for f in REDACT_FIELDS:
            if srv.get(f):
                srv[f] = '[REDACTED]'
    for net in out.get('Networks', []):
        vc = net.get('V2rayConfig') or ''
        if vc and ('vless://' in vc or 'vnext' in vc or 'outbounds' in vc):
            net['V2rayConfig'] = '[REDACTED]'
    return out


def self_test():
    """Verify the decoder against the known bundled catalog values."""
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, 'configfile.json'),
        os.path.expanduser(
            '~/workspace/batch-nov25/mehafvpn/extracted/assets/configfile.json'),
        os.path.join(os.getcwd(), 'extracted/assets/configfile.json'),
        os.path.join(os.getcwd(), 'configfile.json'),
    ]
    asset = next((p for p in candidates if os.path.exists(p)), None)
    if asset is None:
        print('self-test: configfile.json not found in: %s' % candidates)
        return 1
    blob = open(asset, 'rb').read().decode().strip()
    cat = decrypt_catalog(blob)
    assert cat['Version'] == '1.01', cat['Version']
    assert len(cat['Servers']) == 9, len(cat['Servers'])
    assert len(cat['Networks']) == 664, len(cat['Networks'])
    full = decrypt_full_catalog(cat)
    hosts = {s['Name'].strip(): s['ServerIPHost'] for s in full['Servers']}
    assert hosts['Germany'] == 'de.phfiles.com', hosts
    assert hosts['United States V2ray'] == 'us.strongteam.co', hosts
    assert hosts['Germany SSH'] == 'dessh.phfiles.com', hosts
    assert full['Servers'][0]['UDP_obfs'] == 'sandok'
    # The SlowDNS key is identical on all 9 servers (64 hex chars).
    slow_keys = {s['SlowDNSKey'] for s in full['Servers']}
    assert len(slow_keys) == 1, slow_keys
    assert len(next(iter(slow_keys))) == 64
    # Network fields the v1 script missed: 33 DO blobs in 8 networks
    # (SNI / V2rayAddress / V2rayHost / V2raySNI, plus BugDNS on #525).
    # Spot-check the decrypted values, then prove none remain.
    nets = full['Networks']
    assert nets[45]['V2rayAddress'] == 'domain:googleapis.cn', nets[45]
    assert nets[45]['V2raySNI'] == 'ozon.ru', nets[45]
    assert nets[220]['SNI'] == 'www.youtube.com', nets[220]
    assert nets[522]['SNI'] == 'm.youtube.com', nets[522]
    assert nets[522]['V2rayAddress'] == 'www.o2online.de', nets[522]
    assert nets[524]['SNI'] == 'api.udacity.com', nets[524]
    assert nets[524]['V2rayHost'] == 'Zerod.et', nets[524]
    assert nets[525]['BugDNS'] == '197.156.74.223', nets[525]
    assert nets[45]['V2rayHost'] == '[host]', nets[45]
    assert nets[525]['SNI'] == '', nets[525]
    remaining = count_do_blobs(full)
    assert remaining == 0, 'DO blobs remaining: %d' % remaining
    print('self-test OK: version 1.01, 9 servers, 664 networks, '
          'hosts and fields decrypt correctly; 0 DO blobs remaining')
    return 0


def count_do_blobs(cat):
    """Count string values anywhere in the catalog that still DO-decrypt
    (i.e. values that are DO ciphertexts, not plaintext). The SlowDNS
    hex key is not a DO blob (do_decrypt fails on it), so it is not
    counted here."""
    n = 0

    def walk(obj):
        nonlocal n
        if isinstance(obj, dict):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)
        elif isinstance(obj, str) and len(obj) >= 60:
            try:
                pt = do_decrypt(obj)
            except Exception:
                return
            if pt != obj:
                n += 1

    walk(cat)
    return n


def main(argv=None):
    ap = argparse.ArgumentParser(description='Mehaf VPN catalog decoder')
    ap.add_argument('input', nargs='?',
                    help='configfile.json (base64 blob) to decrypt')
    ap.add_argument('--full', help='write full decrypted catalog JSON')
    ap.add_argument('--redacted', help='write redacted catalog JSON')
    ap.add_argument('--self-test', action='store_true')
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.input:
        ap.error('input file required (or --self-test)')
    with open(args.input, 'r', encoding='utf-8') as fh:
        blob = fh.read()
    cat = decrypt_catalog(blob)
    print('Version: %s' % cat.get('Version'))
    print('Servers: %d' % len(cat.get('Servers', [])))
    print('Networks: %d' % len(cat.get('Networks', [])))
    if args.full:
        with open(args.full, 'w', encoding='utf-8') as fh:
            json.dump(decrypt_full_catalog(cat), fh, ensure_ascii=False,
                      indent=2)
        print('full catalog -> %s' % args.full)
    if args.redacted:
        with open(args.redacted, 'w', encoding='utf-8') as fh:
            json.dump(redact_catalog(cat), fh, ensure_ascii=False, indent=2)
        print('redacted catalog -> %s' % args.redacted)
    return 0


if __name__ == '__main__':
    sys.exit(main())
