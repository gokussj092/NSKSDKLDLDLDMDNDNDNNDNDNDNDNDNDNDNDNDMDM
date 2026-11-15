#!/usr/bin/env python3
"""Recover two protected ELF libraries from the provided 6.5.0 split ZIP.

Research only; version-scoped offsets, no Android execution, no EHI key recovery.
Inputs and recovered binaries remain private and must never be committed.
Dependencies: pycryptodome. Accepts ZIP containing APKS, APKS, or split APK.
"""
import argparse
from io import BytesIO
from pathlib import Path
import struct
import zipfile

from Crypto.Cipher import ARC4

OFFSETS = {'libdexjniehi.so': 0x4000, 'libDexHelper.so': 0xc000}


def libraries(data):
    with zipfile.ZipFile(BytesIO(data)) as z:
        for name in z.namelist():
            if name.endswith('.apks') or name.endswith('split_config.arm64_v8a.apk'):
                yield from libraries(z.read(name))
            elif name.rsplit('/', 1)[-1] in OFFSETS:
                yield name.rsplit('/', 1)[-1], z.read(name)


def unpack(name, data):
    params = OFFSETS[name]
    if len(data) < params + 0x3c:
        raise ValueError('biblioteca truncada')
    payload = struct.unpack_from('<I', data, params + 0x20)[0]
    key_at = struct.unpack_from('<I', data, params + 0x38)[0]
    if not (payload + 64 <= key_at and key_at + 20 <= len(data)):
        raise ValueError('parámetros no compatibles con esta versión')
    header = ARC4.new(data[key_at:key_at + 16]).decrypt(data[payload:payload + 64])
    if header[:6] != b'\x7fELF\x02\x01':
        raise ValueError('cabecera ELF no válida; revisar offsets para esta APK')
    if struct.unpack_from('<H', header, 18)[0] != 183:
        raise ValueError('el ELF recuperado no es ARM64')
    mask = data[key_at + 16]
    clear = header + bytes(v ^ mask for v in data[payload + 64:key_at])
    sections, width, count = struct.unpack_from('<Q', header, 40)[0], *struct.unpack_from('<HH', header, 58)
    if sections + width * count > len(clear):
        raise ValueError('ELF interior truncado')
    return clear


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('apk_zip', type=Path)
    p.add_argument('--output-dir', type=Path, required=True)
    args = p.parse_args()
    found = dict(libraries(args.apk_zip.read_bytes()))
    if set(found) != set(OFFSETS):
        p.error('no se encontraron las dos bibliotecas ARM64 esperadas')
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, data in found.items():
        out = args.output_dir / (name + '.unpacked')
        out.write_bytes(unpack(name, data))
        print(out)


if __name__ == '__main__':
    main()
