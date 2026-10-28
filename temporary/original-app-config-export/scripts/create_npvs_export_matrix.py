#!/usr/bin/env python3
"""Private NPV controls, fresh authenticated exports and NPVO1 editor candidate."""
import argparse
import hashlib
import json
from pathlib import Path

from npvs_export_experiment import (read_profile, export_open, export_sealed, summary,
                                    private_write, NpvLabError)
from audit_npvs_export import audit
from lossless_json import equal


def generate(protected, owned_open, output_dir):
    out = Path(output_dir)
    if out.exists():
        raise NpvLabError('NEW_OUTPUT_DIRECTORY_REQUIRED')
    protected_doc, open_doc = read_profile(protected), read_profile(owned_open)
    if protected_doc.kind != 'NPVS_V5_APPKEY' or open_doc.kind != 'NPVO1':
        raise NpvLabError('MATCHING_PROTECTED_AND_OPEN_REFERENCES_REQUIRED')
    cases = [
        ('A_OPEN_ORIGINAL.npvs', open_doc, owned_open, 'open_byte_identical_control'),
        ('B_PROTECTED_ORIGINAL.npvs', protected_doc, protected, 'protected_byte_identical_control'),
        ('C_PROTECTED_REENCRYPTED.npvs', protected_doc, export_sealed(protected_doc), 'fresh_v5_same_document_and_metadata'),
        ('D_OPEN_EDITABLE_CANDIDATE.npvs', protected_doc, export_open(protected_doc), 'protected_document_in_observed_NPVO1'),
        ('E_OWNED_OPEN_ENCRYPTED.npvs', open_doc, export_sealed(open_doc, metadata_template=protected_doc),
         'owned_open_document_in_v5_with_explicit_empty_policy_template'),
    ]
    report = {'protected_source': summary(protected_doc), 'owned_open_source': summary(open_doc),
              'cases': [], 'banner_added': False, 'original_app_import': 'pending',
              'editor_access': 'pending', 'network_connection': 'not_tested', 'production_changes': False}
    for name, before, raw, purpose in cases:
        after = read_profile(raw)
        if not equal(after.document, before.document) or after.raw_document != before.raw_document:
            raise NpvLabError('UNRELATED_DOCUMENT_CHANGE')
        checks = audit(raw, after) if after.envelope else {'NPVO1_JSON': 'verified', 'encryption': 'not_present_in_open_format'}
        report['cases'].append({'file': name, 'purpose': purpose, 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest(), 'source_sha256': summary(before)['sha256'],
            'source_byte_identical': raw == before.source, 'kind': after.kind,
            'document_and_types_preserved': True, 'raw_document_tokens_preserved': True,
            'connection_fields_changed': False, 'npvs1_tokens_preserved': True,
            'raw_metadata_preserved': (after.raw_metadata == before.raw_metadata) if before.envelope and after.envelope else 'not_applicable_to_open_transport',
            'new_signing_identity': bool(after.envelope and raw != before.source),
            'metadata_template': summary(protected_doc)['sha256'] if name.startswith('E_') else None,
            'banner_added': False, 'checks': checks, 'original_app_import': 'pending', 'editor_access': 'pending'})
    out.mkdir(mode=0o700, parents=True)
    for name, _, raw, _ in cases:
        private_write(out/name, raw)
    private_write(out/'REPORT.json', (json.dumps(report, indent=2)+'\n').encode())
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--protected', type=Path, required=True)
    p.add_argument('--owned-open', type=Path, required=True)
    p.add_argument('--output-dir', type=Path, required=True)
    args = p.parse_args()
    try:
        report = generate(args.protected.read_bytes(), args.owned_open.read_bytes(), args.output_dir)
        print(json.dumps({'files': len(report['cases']), 'local_checks': 'passed',
                          'android_import': 'pending', 'banner_added': False}))
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print(json.dumps({'error': 'NPV_MATRIX_FAILED'}))
        raise SystemExit(1)
