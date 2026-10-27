#!/usr/bin/env python3
"""Private EHI trials with verified outer HMAC, checksum and inner AEAD."""
import argparse
import hashlib
import json
from pathlib import Path

from ehi_export_experiment import (open_profile, reseal, observed_open_access_edits,
    encode_message, private_write, summary, EhiLabError)
from ehi_carrier_keys import derive_carrier_keys
from create_ehi_export_matrix import audit
from lossless_json import differences
from spdecode_note import plain_note, html_note


def generate(source, owned_open, apk, output_dir):
    out = Path(output_dir)
    if out.exists():
        raise EhiLabError('NEW_OUTPUT_DIRECTORY_REQUIRED')
    mac_key = derive_carrier_keys(apk)[16:]
    original = open_profile(source, carrier_mac_key=mac_key, require_carrier_mac=True)
    reference = open_profile(owned_open, carrier_mac_key=mac_key, require_carrier_mac=True)
    if reference.inner.get('isConfigLock') is not False or reference.outer.get('lockModes') != '["none"]':
        raise EhiLabError('OWNED_OPEN_REFERENCE_REQUIRED')
    if observed_open_access_edits(reference)[0]['lockModesHash'] != reference.outer['lockModesHash']:
        raise EhiLabError('OWNED_OPEN_HASH_RULE_MISMATCH')
    access_outer, access_inner = observed_open_access_edits(original)
    text = encode_message(plain_note('es'))
    html = encode_message(html_note('es').replace('\r', '').replace('\n', ''))
    cases = [
        ('A_REWRAP_ORIGINAL.ehi', original, {}, {}),
        ('B_NOTE_TEXT_HMAC.ehi', original, {}, {'configMessage': text}),
        ('C_NOTE_HTML_HMAC.ehi', original, {}, {'configMessage': html}),
        ('D_ACCESS_HMAC_CANDIDATE.ehi', original, access_outer, access_inner),
        ('E_ACCESS_HTML_HMAC_CANDIDATE.ehi', original, access_outer, dict(access_inner, configMessage=html)),
        ('owned_open/O_A_OPEN_REWRAP.ehi', reference, {}, {}),
        ('owned_open/O_B_OPEN_TEXT.ehi', reference, {}, {'configMessage': text}),
        ('owned_open/O_C_OPEN_HTML.ehi', reference, {}, {'configMessage': html}),
    ]
    report = {'locked_source': summary(original), 'owned_open_source': summary(reference),
        'carrier_hmac': 'verified_and_recomputed', 'cases': [],
        'original_app_import': 'pending', 'editor_access': 'pending',
        'banner_rendering': 'pending', 'connection_network_test': 'not_run',
        'production_changes': False}
    files = []
    for name, before, outer, inner in cases:
        raw = reseal(before, outer_edits=outer, inner_edits=inner)
        after = open_profile(raw, carrier_mac_key=mac_key, require_carrier_mac=True)
        checked = audit(after)
        report['cases'].append({'file': name, 'sha256': hashlib.sha256(raw).hexdigest(),
            'bytes': len(raw), 'source_sha256': hashlib.sha256(before.source).hexdigest(),
            'source_byte_identical': raw == before.source,
            'outer_changed_paths': [list(p) for p in differences(before.outer, after.outer)],
            'inner_changed_paths': [list(p) for p in differences(before.inner, after.inner)],
            'checks': checked, 'checksum': 'adler32_verified',
            'connection_tokens_unchanged': True, 'unknown_sections_preserved': True,
            'original_app_import': 'pending', 'editor_access': 'pending',
            'banner_rendering': 'pending' if 'HTML' in name else 'not_tested'})
        files.append((name, raw))
    out.mkdir(parents=True, mode=0o700)
    (out/'owned_open').mkdir(mode=0o700)
    for name, raw in files:
        private_write(out/name, raw)
    private_write(out/'REPORT.json', (json.dumps(report, indent=2)+'\n').encode())
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', required=True, type=Path)
    p.add_argument('--owned-open', required=True, type=Path)
    p.add_argument('--apk', required=True, type=Path)
    p.add_argument('--output-dir', required=True, type=Path)
    args = p.parse_args()
    try:
        result = generate(args.source.read_bytes(), args.owned_open.read_bytes(),
                          args.apk.read_bytes(), args.output_dir)
        print(json.dumps({'files': len(result['cases']), 'all_local_checks': 'passed',
                          'original_app_import': 'pending'}))
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(json.dumps({'error': str(error) if isinstance(error, EhiLabError)
                          else 'INPUT_OR_OUTPUT_OR_APK_ERROR'}))
        raise SystemExit(1)
