#!/usr/bin/env python3
"""Capture synthetic LIAPP LCG/CRC vectors from the original AM-63 ARM64 core."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct
import sys
import zlib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/apk_analysis'))
from arm64_function import Arm64Function
from liapp_wrapper import CORE_SHA256


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('core', type=Path)
    args = parser.parse_args()
    if args.core.stat().st_size > 2 * 1024 * 1024 or hashlib.sha256(args.core.read_bytes()).hexdigest() != CORE_SHA256:
        raise ValueError('Unsupported native core')
    native = Arm64Function(args.core)

    def xor(seed, plain):
        ptr = native.alloc(plain)
        native.call(0x11798, seed, ptr, len(plain), limit=100_000)
        return native.read(ptr, len(plain))

    vectors = []
    for seed, plain in [(0, bytes(range(32))), (0xffffffff, b'LIAPP synthetic vector\0\xff'),
                        (0x12345678, bytes(range(255, 191, -1))), (0x80000001, b'')]:
        vectors.append({'seed': seed, 'plainHex': plain.hex(), 'encodedHex': xor(seed, plain).hex()})
    crc = []
    for data in [b'', b'123456789', bytes(range(64))]:
        ptr = native.alloc(data)
        value = native.call(0x10994, ptr, len(data), limit=100_000)
        if value != zlib.crc32(data):
            raise ValueError('Native CRC/zlib mismatch')
        crc.append({'plainHex': data.hex(), 'crc32': value})
    seeds = (0x10203040, 0x50607080, 0x90a0b0c0)
    words = (seeds[0] ^ seeds[1] ^ seeds[2], 7, 8, 9, 10, 11)
    block = struct.pack('<6I', *words) + b'test.Application,2,test.Activity'
    envelope = bytes(0x220) + xor(seeds[0], struct.pack('<I', len(block))) + xor(seeds[1], block)
    result = {
        'source': 'Original AM-63 core; LCG 0x11798 and CRC32 0x10994, no modeled crypto',
        'coreSha256': CORE_SHA256, 'lcg': vectors, 'crc': crc,
        'metadata': {'seeds': seeds, 'plainHex': block.hex(), 'assetBase64': base64.b64encode(envelope).decode()},
    }
    (ROOT / 'tests/golden/am_liapp_vectors.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'lcgVectors': len(vectors), 'crcVectors': len(crc), 'syntheticMetadata': 1}))


if __name__ == '__main__':
    main()
