#!/usr/bin/env python3
"""Recover LIAPP metadata from the exact AM-63 APK, offline; not a DEX reader."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import zipfile
import zlib

APK_SHA256 = '636f96d211266bb592d47ff0f63cb886e332cb312c99ef0fb48572c180065aed'
ASSET_SHA256 = '6352540c129e4085de9b95b4f9060d64abf947e1d15705e84da486c3fdeafd9c'
METADATA_SHA256 = '626ddbf5be13f9fb8e4d86062c5fcf5e8f3ecf147d509a657536ba80fa1b7a01'
PACKAGE = 'app.vpn.amtunnellite'
VERSION_CODE = 63
MAX_APK_BYTES = 64 * 1024 * 1024
MAX_BLOCK_BYTES = 1024 * 1024
PROTECTED_ASSET = 'assets/.efuyxx.dex'
EXCLUDED_ASSETS = {PROTECTED_ASSET, 'assets/dexopt/baseline.prof', 'assets/dexopt/baseline.profm'}


def stream_xor(seed: int, data: bytes) -> bytes:
    """Native 0x11798: unsigned 32-bit LCG; the low byte uses bits 16..23."""
    if not 0 <= seed <= 0xffffffff or len(data) > MAX_BLOCK_BYTES:
        raise ValueError('Invalid LCG seed or block size')
    state = seed ^ 0x94202191
    out = bytearray(data)
    for i in range(len(out)):
        state = (state * 214013 + 2531011) & 0xffffffff
        out[i] ^= (state >> 16) & 255
    return bytes(out)


def open_metadata(asset: bytes, seeds: tuple[int, int, int]) -> bytes:
    """Native 0x802b0..0x803a4, including its three-word relation check."""
    first, second, third = seeds
    if len(asset) < 0x224 or len(asset) > MAX_BLOCK_BYTES:
        raise ValueError('Invalid protected asset size')
    length, = struct.unpack('<I', stream_xor(first, asset[0x220:0x224]))
    if not 24 <= length <= 8192 or 0x224 + length > len(asset):
        raise ValueError('Invalid protected metadata length')
    block = stream_xor(second, asset[0x224:0x224 + length])
    words = struct.unpack('<6I', block[:24])
    if words[0] != first ^ second ^ third:
        raise ValueError('LIAPP metadata relation check failed')
    return block


def recover(apk: Path) -> tuple[dict, bytes]:
    """Hash-pinned layout, with APK ZIP CRC/size folds; no library execution."""
    with apk.open('rb') as source:
        raw = source.read(MAX_APK_BYTES + 1)
    if len(raw) > MAX_APK_BYTES or hashlib.sha256(raw).hexdigest() != APK_SHA256:
        raise ValueError('Unsupported APK; expected the original AM build 63 base.apk')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(infos) > 10000 or len(names) != len(set(names)):
            raise ValueError('Unexpected or duplicate ZIP entries')
        info = archive.getinfo(PROTECTED_ASSET)
        if info.file_size > MAX_BLOCK_BYTES:
            raise ValueError('Oversized protected asset')
        asset = archive.read(info)
        if hashlib.sha256(asset).hexdigest() != ASSET_SHA256:
            raise ValueError('Unexpected protected asset')
        # 0x8c18c..0x8c1cc initializes d60/d64/d6c/d70. 0x7faf8 folds
        # admitted asset CRC/size pairs; the three exclusions are build-specific.
        third = 0xa6038691 ^ 0xb3167321
        folded_assets = 0
        for info in infos:
            if info.filename.startswith('assets/') and not info.is_dir() and info.filename not in EXCLUDED_ASSETS:
                third ^= info.CRC ^ info.file_size
                folded_assets += 1
    second = zlib.crc32(PACKAGE.encode('ascii')) ^ 0xd6162568 ^ VERSION_CODE
    first = third ^ 0xd6162568 ^ 0x11308681
    seeds = (first, second, third)
    block = open_metadata(asset, seeds)
    if hashlib.sha256(block).hexdigest() != METADATA_SHA256:
        raise ValueError('Unexpected recovered metadata; do not continue with this layout')
    words = struct.unpack('<6I', block[:24])
    flags = [words[1] ^ first, words[2] ^ second, words[3] ^ first,
             words[4] ^ second, words[5] ^ third]
    fields = block[24:].decode('utf-8').split(',')
    result = {
        'package': PACKAGE, 'versionCode': VERSION_CODE,
        'foldedAssets': folded_assets, 'seeds': [f'{s:08x}' for s in seeds],
        'metadataBytes': len(block), 'metadataSha256': METADATA_SHA256,
        'relationCheckPassed': True, 'flags': flags,
        'originalApplication': fields[0], 'originalActivity': fields[2],
        'dexRecovered': False, 'catalogDecoded': False,
    }
    return result, block


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base_apk', type=Path)
    parser.add_argument('--output', type=Path, help='Optional private metadata output; never overwrite')
    args = parser.parse_args()
    if args.output and args.output.exists():
        parser.error('Output already exists')
    report, block = recover(args.base_apk)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with args.output.open('xb') as stream:
            stream.write(block)
        args.output.chmod(0o600)
    print(json.dumps(report, ensure_ascii=True))


if __name__ == '__main__':
    main()
