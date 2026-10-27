#!/usr/bin/env python3
"""Redacted EHI field provenance and rejected-matrix audit, without exports.

Do not use the presentation JSON as reconstruction input. This script reports
types and codec evidence; it never prints credentials or unknown scalar values.
No production decoder is changed. TLS default-salt recovery is a bounded lab
candidate, not an independently verified observation of Android TLS settings.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys

from ehi_export_experiment import (open_profile, decode_field, encode_field,
    encode_message, private_write, summary, EhiLabError, D)
from lossless_json import differences

TLS_NAMES = frozenset(('TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'))
KNOWN_NAMES = frozenset(('user', 'password', 'host', 'port', 'remoteProxy',
    'remoteProxyAuth', 'payload', 'sniHostname', 'tlsVersion', 'tunnelType',
    'configMessage', 'configTimestamp', 'configExpiryTimestamp', 'configVersionCode',
    'lockModes', 'lockModesHash', 'configSalt', 'configLockMobileOperatorId',
    'localPort', 'customDns1', 'customDns2', 'dnsType', 'isDefaultRoute',
    'excludedRoutes', 'customRoutes', 'dnsttResolverMode', 'dnsttResolverProfile',
    'isPublicKey', 'isConfigLock'))


def canonical_text(token, salt):
    """Exact inverse, including observed '?' replacing Base64 padding.

    The configData exporter deliberately supports only its separate observed
    carrier. Here '=' may be spelled '?', but only a complete exact re-encoding
    can accept it. Do not delete arbitrary '?' characters or any NUL bytes.
    """
    try:
        normalized = token.replace('?', '=')
        raw, upper = decode_field(normalized, salt)
        encoded = encode_field(raw, salt, upper)
        if encoded != normalized or token not in (encoded, encoded.replace('=', '?')):
            return None
        return raw.decode('utf-8')
    except (ValueError, TypeError, UnicodeError):
        return None


def presentation_type(value):
    """Model just the primitive/container coercion in parseInlineJson.

    Not an Android execution or a complete Gson clone. Numeric strings and
    serialized arrays are sufficient to reproduce the observed type loss.
    """
    if type(value) is not str:
        return type(value).__name__
    try:
        parsed = json.loads(value)
    except (ValueError, TypeError):
        return 'str'
    return type(parsed).__name__ if type(parsed) is not str else 'str'


def audit_decode(document):
    legacy = D._decode_inner_fields(document.inner, document.outer['configSalt'])
    fields = []
    for index, (name, value) in enumerate(document.inner.items()):
        current = legacy[name]
        record = {'index': index, 'known_name': name if name in KNOWN_NAMES else None,
            'raw_type': type(value).__name__, 'legacy_decoded_type': type(current).__name__,
            'legacy_transformed': type(current) is not type(value) or current != value}
        if type(value) is not str or not value:
            record['status'] = 'original_typed_or_empty_value'
        elif name == 'configMessage':
            try:
                roundtrip = encode_message(current) == value
            except (ValueError, TypeError, UnicodeError):
                roundtrip = False
            record.update(status='message_codec_roundtrip' if roundtrip else 'unresolved_message',
                          exact_codec_roundtrip=roundtrip)
        else:
            candidate = canonical_text(value, document.outer['configSalt'])
            if candidate is None:
                record['status'] = 'original_string_preserved_codec_unresolved'
            elif any(ord(ch) < 32 and ch not in '\t\r\n' or ord(ch) == 127
                     for ch in candidate):
                record['status'] = 'canonical_xor_contains_control_characters'
            else:
                record['status'] = 'canonical_xor_utf8_not_semantically_authenticated'
            # No general default-key retry: only an existing, exact TLS enum.
            if name == 'tlsVersion' and candidate not in TLS_NAMES:
                default = canonical_text(value, 'EVZJNI')
                if default in TLS_NAMES:
                    record['default_salt_tls_candidate'] = default
                    record['default_salt_codec_roundtrip'] = True
                    record['android_tls_setting_verified'] = False
        record['presentation_reparse_type'] = presentation_type(current)
        record['presentation_type_changes'] = record['presentation_reparse_type'] != type(current).__name__
        fields.append(record)
    return {'source': summary(document), 'field_count': len(fields),
        'inner_aead_authenticated': True, 'outer_carrier_integrity_verified': False,
        'all_fields_fully_interpreted': False,
        'raw_inner_version_code': document.inner.get('configVersionCode')
            if type(document.inner.get('configVersionCode')) is int else None,
        'fields': fields,
        'interpretation': {
            'unknown_names_are_not_split_or_renamed': True,
            'unknown_strings_are_not_confirmed_decoys': True,
            'default_salt_not_applied_to_other_fields': True,
            'presentation_json_is_not_lossless_export_input': True,
            'production_changes': False}}


def audit_matrix(document, directory):
    records = []
    for path in sorted(Path(directory).rglob('*.ehi')):
        after = open_profile(path.read_bytes())
        # Names only for local expected artifacts, never source-provided names.
        allowed = ('A_REWRAP_ORIGINAL.ehi', 'B_NOTE_TEXT_ONLY.ehi', 'C_NOTE_HTML_ONLY.ehi',
            'D_ACCESS_CANDIDATE.ehi', 'E_ACCESS_HTML_CANDIDATE.ehi', 'FLAG_ONLY.ehi',
            'OUTER_NONE_ONLY.ehi')
        payload = after.source[after.payload_offset:after.payload_offset+after.payload_size]
        original_payload = document.source[document.payload_offset:document.payload_offset+document.payload_size]
        def safe_paths(left, right):
            return [[part if part in KNOWN_NAMES or part == 'configData' else '<unknown>'
                     for part in key] for key in differences(left, right)]
        records.append({'case': path.name if path.name in allowed else '<unnamed_case>',
            'sha256': hashlib.sha256(after.source).hexdigest(),
            'source_byte_identical': after.source == document.source,
            'prefix_before_payload_length_unchanged':
                after.source[:after.length_offset] == document.source[:document.length_offset],
            'outer_version_unchanged': after.outer.get('configVersionCode') == document.outer.get('configVersionCode'),
            'inner_version_unchanged': after.inner.get('configVersionCode') == document.inner.get('configVersionCode'),
            'aead_parameters_unchanged': after.aead[:10] == document.aead[:10],
            'carrier_middle_unchanged': after.middle == document.middle,
            'ciphertext_changed': payload != original_payload,
            'inner_aead_authenticated': True, 'frame_adler32_verified': True,
            'outer_changed_paths': safe_paths(document.outer, after.outer),
            'inner_changed_paths': safe_paths(document.inner, after.inner),
            'carrier_integrity_verified': False})
    try:
        middle_size = len(base64.b64decode(document.middle, validate=True))
    except ValueError:
        middle_size = None
    return {'source_sha256': hashlib.sha256(document.source).hexdigest(),
            'carrier_middle_decoded_bytes': middle_size,
            'carrier_middle_role': 'unresolved_mac_hypothesis',
            'hmac_algorithm_or_key_recovered': False,
            'version_error_root_cause_confirmed': False,
            'cases': records}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source', type=Path)
    p.add_argument('--matrix-dir', type=Path)
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    try:
        d = open_profile(args.source.read_bytes())
        result = audit_decode(d)
        if args.matrix_dir:
            result['matrix'] = audit_matrix(d, args.matrix_dir)
        raw = (json.dumps(result, indent=2) + '\n').encode()
        if args.output:
            private_write(args.output, raw)
            print(json.dumps({'redacted_audit_written': True,
                              'modified_export_status': 'blocked_pending_carrier_integrity'}))
        else:
            print(raw.decode(), end='')
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        print(json.dumps({'error': str(error) if isinstance(error, EhiLabError)
                          else 'INPUT_OR_OUTPUT_ERROR'}), file=sys.stderr)
        sys.exit(1)
