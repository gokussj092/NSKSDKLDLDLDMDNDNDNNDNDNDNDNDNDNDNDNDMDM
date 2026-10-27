#!/usr/bin/env python3
"""Audit private HC files without logging their plaintext or connection fields."""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path

from hc_hcx4_n11_experiment import codec, hc, open_original, private_write
from lossless_json import differences, equal, parse, replace_values


def authenticate_pure(raw):
    depth, _ = open_original(raw)
    logical = list(hc._carriers(raw))[depth]
    outer = hc._xdec_pure(codec.OUTER_KEY, logical[:24], codec.OUTER_AAD, logical[24:])
    env = parse(outer)
    key, aad = codec.derive(env, None, None)
    checks = 1
    main = None
    for section in [env['i'], *hc._sec_list(env['j'])]:
        tag = aad + b'\0' + section['a'].encode()
        clear = hc._xdec_pure(key, bytes.fromhex(section['b']), tag,
                             bytes.fromhex(section['c']))
        checks += 1
        if section is env['i']:
            main = clear
        if clear.startswith(b'HPR1'):
            hc._xdec_pure(key, clear[4:28], tag + b':r', clear[28:])
            checks += 1
        if section.get('d') is not None:
            sidecar = section['d']
            hc._xdec_pure(key, bytes.fromhex(sidecar['a']), tag + b':x',
                         bytes.fromhex(sidecar['b']))
            checks += 1
    return env, main, checks


def run(source, historical, matrix):
    env, clear, count = authenticate_pure(source)
    main = parse(clear)
    decoded = codec.decrypt(source)
    report = {
        'scope': 'HCX4 HCCFG10 n11 build899, local evidence only',
        'source_sha256': hashlib.sha256(source).hexdigest(),
        'source_bytes': len(source),
        'source_main_plaintext_bytes': len(clear),
        'previous_global_reserialization_bytes': len(json.dumps(main, ensure_ascii=False,
                                                               separators=(',', ':')).encode()),
        'source_main_projection_type_exact': equal(main, decoded['main']),
        'source_outer_fields': list(env),
        'source_main_fields': list(main),
        'original_access_mode_type': type(main['g']['a']).__name__,
        'source_pure_python_aead_tags_verified': count,
        'cases': [],
        'vendor_import_status': 'PENDING_MANUAL_TEST',
        'vendor_invalid_json_root_cause': 'UNCONFIRMED',
    }
    for row in matrix['cases']:
        path = matrix['_directory'] / (row['case'] + '.hc')
        raw = path.read_bytes()
        output_env, new_clear, verified = authenticate_pure(raw)
        new_main = parse(new_clear)
        paths = differences(main, new_main)
        edits = {}
        for p in paths:
            value = new_main
            for name in p:
                value = value[name]
            edits[p] = value
        metadata = copy.deepcopy(output_env)
        metadata['i']['b'], metadata['i']['c'] = env['i']['b'], env['i']['c']
        checks = {
            'hash_matches_generated_manifest': hashlib.sha256(raw).hexdigest() == row['sha256'],
            'unchanged_raw_json_bytes_preserved': replace_values(clear, edits) == new_clear,
            'all_non_ciphertext_envelope_fields_preserved': equal(metadata, env),
            'profile_ciphertext_byte_identical': equal(output_env['j'], env['j']),
            'source_main_shape_preserved': parse(new_clear).keys() == main.keys(),
        }
        if not all(checks.values()):
            raise AssertionError('Matrix audit failed')
        report['cases'].append(dict(case=row['case'], pure_python_aead_tags_verified=verified,
                                    checks=checks))
    if historical:
        previous_env, previous_clear, previous_tags = authenticate_pure(historical)
        previous = parse(previous_clear)
        before, after = copy.deepcopy(env), copy.deepcopy(previous_env)
        for obj in (before, after):
            del obj['i']['b'], obj['i']['c']
        report['historical_rejected'] = {
            'sha256': hashlib.sha256(historical).hexdigest(), 'bytes': len(historical),
            'main_json_syntax_valid': True,
            'pure_python_aead_tags_verified': previous_tags,
            'untouched_envelope_fields_preserved': equal(before, after),
            'changed_paths': ['main.' + '.'.join(p) for p in differences(main, previous)],
            'access_mode_type': type(previous['g']['a']).__name__,
            'vendor_import': 'INVALID_JSON_OWNER_REPORTED',
        }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--historical', type=Path)
    parser.add_argument('--matrix-dir', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    matrix = parse((args.matrix_dir / 'import_matrix.json').read_bytes())
    matrix['_directory'] = args.matrix_dir
    report = run(args.source.read_bytes(), args.historical.read_bytes() if args.historical else None, matrix)
    private_write(args.output, (json.dumps(report, indent=2) + '\n').encode())
    print('Audited all supplied cases with pure-Python AEAD; unedited bytes and metadata match. Android import: PENDING.')


if __name__ == '__main__':
    main()
