#!/usr/bin/env python3
"""Generate a private Dark Tunnel import matrix and redacted local report."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.decrepit.ciphers.modes import CFB

from dark_tunnel_experiment import (decode, rewrap, unlock_configuration, summary,
                                    private_write, DTConstants, b64decode, LabError)
from dark_synthetic_vectors import wrap_open_vless, reserved_ssh, INJECT_DEFAULTS
from dark_vless_reference import DEFAULTS
from lossless_json import equal

NOTE = ('Exportado con SP-DECODE\nDeveloper: Ghost Developer\n'
        'Organization: Ghost Nexora Studio\nhttps://spdecode.xyz\n'
        'Canal: https://t.me/GhostDeve\nGrupo: https://t.me/CodeBreakersHub').encode('utf-8')


def independent_crypto(document):
    """OpenSSL-backed implementation, independent of PyCryptodome CFB."""
    count = 0

    def check(ciphertext, clear, key):
        nonlocal count
        context = Cipher(algorithms.AES(key), CFB(DTConstants.IV)).decryptor()
        if context.update(ciphertext) + context.finalize() != clear:
            raise LabError('INDEPENDENT_CFB_MISMATCH')
        count += 1

    if document.protected:
        check(b64decode(document.outer['encryptedLockedConfig']), document.raw_export, DTConstants.KEY_256)
        check(document.export['EncryptedLockedConfig'], document.raw_locked, DTConstants.KEY_192)
        from dark_tunnel_experiment import crypt
        for group in document.locked.values():
            if isinstance(group, dict):
                for name, value in group.items():
                    if isinstance(name, str) and name.startswith('Encrypted') and type(value) is bytes:
                        check(value, crypt(value, DTConstants.KEY_192, decrypt=True), DTConstants.KEY_192)
    return count


def effective_vless(document):
    # Compare every active Kotlin field, including defaults omitted by its serializer.
    config = document.outer['vlessTunnelConfig']
    from dark_tunnel_experiment import INJECT_NAMES
    inject_defaults = {v: INJECT_DEFAULTS[k] for k, v in INJECT_NAMES.items()}
    inject_defaults.update(enabled=False, payloadEnhanced=False)
    return {'type': document.outer['type'],
            'v2rayConfig': dict(DEFAULTS, **config.get('v2rayConfig', {})),
            'injectConfig': dict(inject_defaults, **config.get('injectConfig', {}))}


def generate(source, destination):
    d = decode(source)
    destination = Path(destination)
    if destination.exists():
        raise LabError('NEW_OUTPUT_DIRECTORY_REQUIRED')
    # Prepare all dependent outputs before creating any files.
    rewrapped = rewrap(d)
    unlocked = unlock_configuration(d)
    cases = [
        ('A_rewrapped.dark', rewrapped, 'source', 'Rewrap with exact raw JSON/MessagePack bytes'),
        ('B_rewrapped_text.txt', rewrapped, 'source', 'Same native token as A, text transport'),
        ('C_open.dark', unlocked, 'source', 'Open export; supplied reference may already be open'),
        ('D_open_text.txt', unlocked, 'source', 'Same native token as C, text transport'),
    ]
    controls = []
    if d.protected:
        cases.append(('E_note_rewrapped.dark', rewrap(d, note=NOTE), 'source',
                      'Replace protected Message; preserve connection and other metadata'))
    elif d.outer['type'] == 'VLESS':
        locked = decode(wrap_open_vless(d))
        recovered = decode(unlock_configuration(locked))
        if not equal(effective_vless(d), effective_vless(recovered)):
            raise LabError('EFFECTIVE_VLESS_CONNECTION_CHANGED')
        if not equal({k: v for k, v in d.outer.items() if k not in ('vlessTunnelConfig', 'encryptedLockedConfig')},
                     {k: v for k, v in recovered.outer.items() if k not in ('vlessTunnelConfig', 'encryptedLockedConfig')}):
            raise LabError('UNRELATED_OUTER_FIELDS_CHANGED')
        cases.append(('E_reference_restored.dark', rewrap(recovered), 'synthetic_wrapper_on_source',
                      'Source values restored from artificial locked wrapper, not a captured locked export'))
        controls.extend([
            ('controls/VLESS_artificial_locked.dark', rewrap(locked), 'synthetic_wrapper_on_source',
             'Artificial control containing source private values; not vendor-exported'),
            ('controls/VLESS_artificial_note.dark', rewrap(locked, note=NOTE), 'synthetic_wrapper_on_source',
             'Same control with protected Message replaced; HTML rendering not asserted'),
        ])
    ssh = decode(reserved_ssh())
    cases.append(('F_synthetic_ssh_open.dark', unlock_configuration(ssh), 'reserved_synthetic',
                  'Synthetic editable SSH model; example.invalid is not a live service'))
    controls.append(('controls/SSH_artificial_locked.dark', rewrap(ssh), 'reserved_synthetic',
                     'Synthetic locked schema control; not vendor-exported'))
    report = {'source': summary(d), 'source_has_locked_container': d.protected,
              'vendor_locked_export_confirmed': False,
              'source_already_open': not d.protected, 'android_import': 'pending',
              'cases': [], 'controls': [],
              'file_text_tokens_identical': True,
              'effective_vless_reference_preserved': True if not d.protected and d.outer['type'] == 'VLESS' else None}
    records = []
    for collection, values in [('cases', cases), ('controls', controls)]:
        for name, content, origin, purpose in values:
            opened = decode(content)
            record = {'file': name, 'origin': origin, 'purpose': purpose,
                      'bytes': len(content) + 1, 'sha256': hashlib.sha256(content + b'\n').hexdigest(),
                      'layout': summary(opened)['layout'], 'local_decode': 'passed',
                      'independent_cfb_checks': independent_crypto(opened),
                      'android_import': 'pending', 'connection_test': 'not_performed'}
            report[collection].append(record)
            records.append((name, content + b'\n'))
    destination.mkdir(mode=0o700, parents=True)
    (destination / 'controls').mkdir(mode=0o700)
    for name, content in records:
        private_write(destination / name, content)
    private_write(destination / 'REPORT.json', (json.dumps(report, indent=2) + '\n').encode())
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = generate(args.source.read_bytes(), args.output_dir)
        print(json.dumps({'cases': len(result['cases']), 'controls': len(result['controls']),
                          'source_already_open': result['source_already_open'], 'android_import': 'pending'}))
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        print(json.dumps({'error': str(error) if isinstance(error, LabError) else 'INPUT_OR_OUTPUT_ERROR'}),
              file=sys.stderr)
        sys.exit(1)
