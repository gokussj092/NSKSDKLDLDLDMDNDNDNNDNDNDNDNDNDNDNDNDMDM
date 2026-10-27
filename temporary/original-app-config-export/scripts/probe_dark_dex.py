#!/usr/bin/env python3
"""Verify exact VLESS transport enum names from the pinned original DEX.

Optional analysis dependency: androguard==4.1.4. Does not run APK code.
R8 reordered the enum constructor to (ordinal, name, displayLabel), so JADX's
human labels alone are insufficient to recover case-sensitive JSON names.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

from loguru import logger
logger.remove()
from androguard.core.dex import DEX

from dark_vless_reference import DEFAULTS, render, recover

BASE_SHA256 = 'fa5fbc7473636456d525ee8c8a9f6e9ae168008d64c415867084b623f47e8b2e'
ENUM = 'Lיˉ/י;'
CONSTRUCTOR = ENUM + '-><init>(I Ljava/lang/String; Ljava/lang/String;)V'


def probe(path):
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != BASE_SHA256:
        raise ValueError('Unsupported APK checksum')
    with zipfile.ZipFile(path) as archive:
        dex = DEX(archive.read('classes.dex'))
    classes = [c for c in dex.get_classes() if c.get_name() == ENUM]
    methods = [m for c in classes for m in c.get_methods() if m.get_name() == '<clinit>']
    if len(methods) != 1:
        raise ValueError('Missing or ambiguous native enum initializer')
    registers, members = {}, []
    for instruction in methods[0].get_instructions():
        operands = instruction.get_operands()
        name = instruction.get_name()
        if name.startswith('const-string'):
            registers[operands[0][1]] = operands[1][2]
        elif name.startswith('const') and len(operands) == 2:
            registers[operands[0][1]] = operands[1][1]
        elif name.startswith('move') and not name.startswith('move-result') and len(operands) == 2:
            registers[operands[0][1]] = registers.get(operands[1][1])
        elif name == 'invoke-direct' and operands[-1][-1] == CONSTRUCTOR:
            members.append({'ordinal': registers[operands[1][1]],
                            'name': registers[operands[2][1]],
                            'display': registers[operands[3][1]]})
    if [x['ordinal'] for x in members] != [0, 1, 2]:
        raise ValueError('Unsupported enum initializer flow')
    for member in members:
        candidate = dict(DEFAULTS, transportNetwork=member['name'])
        if recover(render(candidate))['transportNetwork'] != member['name']:
            raise ValueError('Laboratory enum differs from original DEX')
    if DEFAULTS['transportNetwork'] != members[1]['name']:
        raise ValueError('Default transport differs from audited Kotlin constructor')
    return {'base_apk_sha256': BASE_SHA256, 'enum_descriptor': ENUM,
            'source': 'original DEX const-string operands passed to enum constructor',
            'constructor_descriptor': CONSTRUCTOR, 'members': members,
            'laboratory_transports_match_original': True, 'android_import': 'pending'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base_apk', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.base_apk), indent=2, ensure_ascii=False))
