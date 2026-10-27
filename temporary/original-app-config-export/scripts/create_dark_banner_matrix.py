#!/usr/bin/env python3
"""Private HTML banner trials on an existing Dark Tunnel note wrapper.

Change only LockedAppConfig.Message. Preserve the accepted wrapper's connection,
flags, unknown fields and every inner ciphertext byte. Never invent an open
JSON note field or silently create a new protection wrapper.
"""
import argparse
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys

from dark_tunnel_experiment import (decode, rewrap, private_write, replace_packed,
                                    LabError)
from create_dark_export_matrix import independent_crypto
from lossless_json import equal, replace_values
from spdecode_note import LINKS

ASSETS = Path(__file__).resolve().parents[1] / 'notes'
BANNERS = {'compatible': 'dark-banner-compatible.es.html',
           'amoled': 'spdecode-note.es.html'}


class BannerParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag not in {'div', 'table', 'tr', 'td', 'p', 'h2', 'a', 'b', 'br', 'font'}:
            raise LabError('UNSUPPORTED_BANNER_TAG')
        for name, value in attrs:
            if name.lower().startswith('on') or name.lower() in ('src', 'srcset'):
                raise LabError('UNSUPPORTED_BANNER_ATTRIBUTE')
            if name == 'href':
                if value not in LINKS.values():
                    raise LabError('UNEXPECTED_BANNER_LINK')
                self.links.append(value)

    handle_startendtag = handle_starttag


def banner(kind):
    if kind not in BANNERS:
        raise LabError('UNKNOWN_BANNER')
    html = (ASSETS / BANNERS[kind]).read_text('utf-8').strip()
    # The original UI replaces every LF with <br /> before Html.fromHtml.
    # Remove formatting-only line breaks from our static templates first.
    html = re.sub(r'>\s+<', '><', html).replace('\r', '').replace('\n', '')
    parser = BannerParser()
    parser.feed(html); parser.close()
    if set(parser.links) != set(LINKS.values()):
        raise LabError('BANNER_LINK_MISSING')
    return html.encode('utf-8')


def verify_change(before, raw, note):
    after = decode(raw)
    expected = dict(before.export['LockedAppConfig'])
    if note is not None:
        expected['Message'] = note
    if not equal(after.export['LockedAppConfig'], expected):
        raise LabError('BANNER_METADATA_CHANGED')
    if after.raw_locked != before.raw_locked:
        raise LabError('BANNER_CONNECTION_CHANGED')
    if after.export['EncryptedLockedConfig'] != before.export['EncryptedLockedConfig']:
        raise LabError('BANNER_INNER_CIPHERTEXT_CHANGED')
    expected_packed = (replace_packed(before.raw_export, ('LockedAppConfig', 'Message'), note)
                       if note is not None else before.raw_export)
    if after.raw_export != expected_packed:
        raise LabError('BANNER_UNRELATED_MSGPACK_BYTES_CHANGED')
    expected_json = replace_values(before.raw_json,
        {('encryptedLockedConfig',): after.outer['encryptedLockedConfig']})
    # The unchanged control retains even the original ciphertext token spelling.
    if note is None:
        expected_json = before.raw_json
    if after.raw_json != expected_json:
        raise LabError('BANNER_UNRELATED_JSON_BYTES_CHANGED')
    return after


def generate(source, output_dir):
    output_dir = Path(output_dir)
    if output_dir.exists():
        raise LabError('NEW_OUTPUT_DIRECTORY_REQUIRED')
    original = decode(source)
    if not original.protected:
        raise LabError('EXISTING_NOTE_WRAPPER_REQUIRED')
    if type(original.export['LockedAppConfig'].get('Message')) is not bytes:
        raise LabError('BINARY_MESSAGE_REQUIRED')
    planned = [
        ('01_CONTROL_NOTA_TEXTO.dark', None, 'control'),
        ('02_BANNER_COMPATIBLE.dark', banner('compatible'), 'compatible'),
        ('03_BANNER_AMOLED.dark', banner('amoled'), 'amoled'),
    ]
    report = {'source_sha256': hashlib.sha256(source).hexdigest(),
              'changed_field': 'LockedAppConfig.Message',
              'source_protection_flags_preserved': True,
              'inner_ciphertext_identical': True,
              'new_open_json_fields': False,
              'android_import': 'pending', 'banner_rendering': 'pending',
              'banner_links': 'pending', 'editor_access': 'pending',
              'cases': []}
    files = []
    for name, note, kind in planned:
        content = rewrap(original, note=note) + b'\n'
        after = verify_change(original, content, note)
        record = {'file': name, 'kind': kind, 'bytes': len(content),
                  'sha256': hashlib.sha256(content).hexdigest(),
                  'independent_cfb_checks': independent_crypto(after),
                  'local_verification': 'passed', 'android_import': 'pending',
                  'banner_rendering': 'not_applicable' if note is None else 'pending'}
        if note is not None:
            record['html_sha256'] = hashlib.sha256(note).hexdigest()
            record['text_file'] = name.replace('.dark', '.txt')
            files.append((record['text_file'], content))
        report['cases'].append(record)
        files.append((name, content))
    output_dir.mkdir(mode=0o700, parents=True)
    for name, content in files:
        private_write(output_dir/name, content)
    private_write(output_dir/'REPORT.json', (json.dumps(report, indent=2)+'\n').encode())
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = generate(args.source.read_bytes(), args.output_dir)
        print(json.dumps({'cases': len(result['cases']), 'connection_preserved': True,
                          'banner_rendering': 'pending'}))
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        print(json.dumps({'error': str(error) if isinstance(error, LabError) else 'INPUT_OR_OUTPUT_ERROR'}),
              file=sys.stderr)
        sys.exit(1)
