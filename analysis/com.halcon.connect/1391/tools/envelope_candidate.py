#!/usr/bin/env python3
"""Research-only interpretation of AESCrypt in build1391; real catalog unverified.

Accepts a private password supplied separately. Contains no provider secrets and
does not perform network requests. Does not interpret per-server native fields.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
from pathlib import Path
from Crypto.Cipher import AES

ALPHABET = '▙▚▛▜▝▞▟▃▄▅▆▇█▉▊▐'
MAX_BYTES = 8 * 1024 * 1024

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result

def no_constant(value):
    raise ValueError('Nonfinite JSON value')

def decode(data: bytes, password: str) -> dict:
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_BYTES:
        raise ValueError('Invalid envelope length')
    if not isinstance(password, str) or not password or len(password.encode()) > 4096:
        raise ValueError('Missing private catalog password')
    try:
        text = data.decode('utf-8').strip()
        if not text or len(text) % 2 or any(c not in ALPHABET for c in text):
            raise ValueError('Invalid block-symbol encoding')
        lookup = {c: i for i, c in enumerate(ALPHABET)}
        b64 = bytes((lookup[text[i]] << 4) | lookup[text[i + 1]]
                    for i in range(0, len(text), 2))
        raw = base64.b64decode(b64, validate=True)
        if len(raw) < 28:
            raise ValueError('Truncated GCM envelope')
        key = hashlib.sha256(password.encode('utf-8')).digest()
        plain = AES.new(key, AES.MODE_GCM, nonce=raw[:12]).decrypt_and_verify(raw[12:-16], raw[-16:])
        obj = json.loads(plain.decode('utf-8'), object_pairs_hook=unique, parse_constant=no_constant)
        if not isinstance(obj, dict) or not obj:
            raise ValueError('Expected nonempty JSON object; actual catalog schema remains unverified')
        return obj
    except (UnicodeError, TypeError, RecursionError) as exc:
        raise ValueError('Malformed candidate envelope') from exc

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('input', type=Path)
    p.add_argument('private_recipe', type=Path)
    p.add_argument('private_output', type=Path)
    a = p.parse_args()
    password = json.loads(a.private_recipe.read_text())['catalog_password']
    value = decode(a.input.read_bytes(), password)
    a.private_output.touch(mode=0o600, exist_ok=True)
    a.private_output.chmod(0o600)
    a.private_output.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    print('Candidate envelope authenticated; complete catalog compatibility still unverified.')

if __name__ == '__main__':
    main()
