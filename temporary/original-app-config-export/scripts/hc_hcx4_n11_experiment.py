#!/usr/bin/env python3
"""TEMPORARY HCX4/HCCFG10/n11 rewrap; original-app compatibility is pending."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import sys

# Direct CLI execution must work from any cwd, without PYTHONPATH.
SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS.parents[2]))
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from Crypto.Cipher import ChaCha20_Poly1305
from decoders.Python.apps.HTTP_Custom import codec
from decoders.Python import _hc_hccfg as hc
from lossless_json import differences, equal, parse, replace_values

ALLOWED = {('g', 'a'), ('g', 'v'), ('u',)}
# Captured from build 899's native enum constructor; see access_enum_2026-10-26.json.
ACCESS_MODES = frozenset({'none', 'lock_all', 'lock_payload_unlock_server', 'unlock_user_pass'})


def seal(key: bytes, aad: bytes, plaintext: bytes) -> tuple[str, str]:
    import secrets
    nonce = secrets.token_bytes(24)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(aad)
    return nonce.hex(), (cipher.encrypt(plaintext) + cipher.digest()).hex()


def open_original(raw: bytes) -> tuple[int, bytes]:
    for depth, logical in enumerate(hc._carriers(raw)):
        try:
            clear = hc._xdec(codec.OUTER_KEY, logical[:24], codec.OUTER_AAD, logical[24:])
        except hc.HCError:
            continue
        envelope = parse(clear)
        if isinstance(envelope, dict) and envelope.get('a') == 'HCCFG':
            return depth, clear
        raise ValueError('Authenticated envelope is not HCCFG')
    raise ValueError('HCX4 outer layer did not authenticate')


def carrier_depth(original: bytes) -> int:
    return open_original(original)[0]


def check_changes(original: dict, edited: dict, *, allow_access_type_change=False) -> None:
    if not isinstance(edited, dict) or edited.keys() != original.keys():
        raise ValueError('Edited projection root is incomplete or adds fields')
    for name in original.keys() - {'main', 'protections'}:
        if not equal(original[name], edited[name]):
            raise ValueError('Unexpected changes outside main/protections')
    old, new = original['main'], edited['main']
    if not isinstance(new, dict) or not set(differences(old, new)) <= ALLOWED:
        raise ValueError('Only existing main.g.a, main.g.v and main.u may change')
    for path in differences(old, new):
        before, after = old, new
        for name in path:
            before, after = before[name], after[name]
        if path == ('g', 'a') and isinstance(after, str) and after not in ACCESS_MODES:
            raise ValueError('Access mode is not present in the observed build-899 enum')
        if type(before) is not type(after) and not (
                path == ('g', 'a') and allow_access_type_change
                and isinstance(before, str) and after is False):
            raise ValueError('Field type changed; boolean access mode is diagnostic only')
        if path in {('g', 'v'), ('u',)} and not isinstance(after, str):
            raise ValueError('Note and URL must remain strings')
    if not equal(edited['protections'], hc._norm_prot(new['g'])):
        raise ValueError('Presentation protections do not match main.g')


def private_write(path: Path, data: bytes) -> None:
    """Exclusive create, never follow an existing symlink or overwrite a sample."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


def rewrap(raw: bytes, edited: dict, *, allow_access_type_change=False,
           allow_rejected_layout=False) -> bytes:
    decoded = codec.decrypt(raw)
    check_changes(decoded, edited, allow_access_type_change=allow_access_type_change)
    depth, outer_clear = open_original(raw)
    envelope = parse(outer_clear)
    if not (type(envelope.get('b')) is int and envelope['b'] == 10
            and (envelope.get('c'), envelope.get('d'), envelope.get('e')) == ('s1', 'h1', 'n11')
            and type(envelope.get('n')) is int and envelope['n'] == 899):
        raise ValueError('Only observed HCX4 HCCFG10 n11 build 899 supported')
    if bool(envelope.get('h', False)):
        raise ValueError('Password-protected files are outside this lab workflow')
    key, aad = codec.derive(envelope, None, None)
    if (decoded['main']['g']['a'] != edited['main']['g']['a']
            and edited['main']['g']['a'] == 'none' and not allow_rejected_layout
            and any(hc._dec_section(s, key, aad).startswith(b'HPR1')
                    for s in hc._sec_list(envelope['j']))):
        raise ValueError('Known rejected mode-only conversion: HPR1 needs a reference-backed layout migration')
    section = envelope['i']
    section_aad = aad + b'\0' + section['a'].encode('utf-8')
    clear = hc._dec_section(section, key, aad)
    original_main = parse(clear)
    if not equal(original_main, decoded['main']):
        raise ValueError('Decoder projection transformed main; refusing reconstruction')
    paths = differences(original_main, edited['main'])
    edits = {}
    for path in paths:
        value = edited['main']
        for name in path:
            value = value[name]
        edits[path] = value
    # Baseline plaintext is BYTE-IDENTICAL. Other cases touch only edited tokens.
    new_clear = replace_values(clear, edits) if edits else clear
    nonce, encrypted = seal(key, section_aad, new_clear)
    outer_new = replace_values(outer_clear, {('i', 'b'): nonce, ('i', 'c'): encrypted})
    nonce, encrypted = seal(codec.OUTER_KEY, codec.OUTER_AAD, outer_new)
    result = bytes.fromhex(nonce + encrypted)
    for _ in range(depth):
        result = result.decode('latin-1').encode('utf-8')
    if not equal(codec.decrypt(result), edited):
        raise AssertionError('Decrypted projection differs from edited projection')
    output = codec.open_envelope(result)
    expected = copy.deepcopy(envelope)
    expected['i']['b'], expected['i']['c'] = output['i']['b'], output['i']['c']
    if not equal(output, expected):
        raise AssertionError('Envelope metadata or untouched encrypted sections changed')
    if hc._dec_section(output['i'], key, aad) != new_clear:
        raise AssertionError('Main plaintext bytes differ after authentication')
    if open_original(result)[0] != depth:
        raise AssertionError('Carrier depth changed')
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--edited', required=True, type=Path,
                        help='Complete private decoder projection; never commit it')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--allow-access-type-change', action='store_true',
                        help='Reproduce historical boolean experiment, NOT a schema correction')
    args = parser.parse_args()
    try:
        raw = args.source.read_bytes()
        edited = parse(args.edited.read_bytes())
        output = rewrap(raw, edited, allow_access_type_change=args.allow_access_type_change)
        private_write(args.output, output)
    except (ValueError, OSError, AssertionError):
        parser.exit(2, 'Experiment failed; check input/schema and exclusive output path. No plaintext logged.\n')
    print(json.dumps({'source_sha256': hashlib.sha256(raw).hexdigest(),
                      'output_sha256': hashlib.sha256(output).hexdigest(),
                      'output_bytes': len(output), 'local_crypto_roundtrip': True,
                      'original_app_import': 'PENDING_MANUAL_TEST'}, indent=2))


if __name__ == '__main__':
    main()
