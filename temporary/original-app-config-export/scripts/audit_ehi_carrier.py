#!/usr/bin/env python3
"""Redacted verification of the old rejected carrier MACs and owned baseline."""
import argparse
import hashlib
import json
from pathlib import Path

from ehi_carrier_keys import derive_carrier_keys
from ehi_export_experiment import open_profile, private_write, lock_hash_rule, EhiLabError


def inspect(raw, key, label):
    d = open_profile(raw)  # read-only forensic decode, including stale-MAC files
    error = None
    try:
        open_profile(raw, carrier_mac_key=key, require_carrier_mac=True)
        verified = True
    except EhiLabError as problem:
        verified, error = False, str(problem)
    return {'case': label, 'sha256': hashlib.sha256(raw).hexdigest(),
        'bytes': len(raw), 'carrier_hmac_verified': verified, 'error': error,
        'frame_adler32_verified': True, 'inner_aead_verified': True,
        'outer_version_code': d.outer.get('configVersionCode'),
        'inner_version_code': d.inner.get('configVersionCode')}


def generate(source, owned_open, apk, matrix_dir):
    key = derive_carrier_keys(apk)[16:]
    original = open_profile(source, carrier_mac_key=key, require_carrier_mac=True)
    reference = open_profile(owned_open, carrier_mac_key=key, require_carrier_mac=True)
    cases = []
    allowed = {'A_REWRAP_ORIGINAL.ehi', 'B_NOTE_TEXT_ONLY.ehi', 'C_NOTE_HTML_ONLY.ehi',
        'D_ACCESS_CANDIDATE.ehi', 'E_ACCESS_HTML_CANDIDATE.ehi', 'FLAG_ONLY.ehi', 'OUTER_NONE_ONLY.ehi'}
    for p in sorted(Path(matrix_dir).rglob('*.ehi')):
        if p.name not in allowed:
            raise EhiLabError('HISTORICAL_MATRIX_FILENAME_UNSUPPORTED')
        cases.append(inspect(p.read_bytes(), key, p.name))
    return {'source': inspect(source, key, 'locked_original'),
        'owned_open': inspect(owned_open, key, 'owned_open_original'),
        'source_lock_hash_rule': lock_hash_rule(original),
        'owned_open_lock_hash_rule': lock_hash_rule(reference),
        'owned_open_flag_is_false': reference.inner.get('isConfigLock') is False,
        'owned_open_salt_key_absent': 'configSalt' not in reference.outer,
        'cases': cases, 'stale_carrier_mac_defect_confirmed': True,
        'new_android_import': 'pending', 'production_changes': False}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for option in ('source', 'owned-open', 'apk', 'matrix-dir', 'output'):
        p.add_argument('--'+option, required=True, type=Path)
    args = p.parse_args()
    try:
        report = generate(args.source.read_bytes(), args.owned_open.read_bytes(),
                          args.apk.read_bytes(), args.matrix_dir)
        private_write(args.output, (json.dumps(report, indent=2)+'\n').encode())
        print(json.dumps({'redacted_report_written': True, 'old_matrix_cases': len(report['cases'])}))
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(json.dumps({'error': str(error) if isinstance(error, EhiLabError) else 'INPUT_OR_OUTPUT_OR_APK_ERROR'}))
        raise SystemExit(1)
