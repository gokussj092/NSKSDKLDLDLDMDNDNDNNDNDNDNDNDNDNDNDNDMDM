#!/usr/bin/env python3
"""Recover relevant strings from the exact user-supplied HA 1.7.1 MOD, offline.

Emulates only its SGB2 parser/lookup and memory helpers, never JNI or the OS.
The recovered inventory is private output; do not commit it.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import tempfile
import zipfile
from arm64_function import Arm64Function
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0, UC_ARM64_REG_X30

APK_SHA256 = "49784eadfcfb5d0ec9cbb5e24b96a0f02d5ed53314b0b068ff261c8a0ad6c4e0"


def string_block(raw):
    def word(pos):
        return struct.unpack_from("<I", raw, pos)[0]
    pos = word(32) + 116
    for mask in [0x56A3958A] * 2 + [0x01C0DB76] * 7:
        size = word(pos) ^ mask
        pos += 4 + size
        if pos > len(raw):
            raise ValueError("Invalid trailer bounds")
    pos += word(pos) * 2 + 8
    for step in range(3):
        if step == 1:
            pos += 256
        size = word(pos) ^ 0x01C0DB76
        pos += 4
        if pos + size > len(raw):
            raise ValueError("Invalid string block bounds")
        if step < 2:
            pos += size
    block = raw[pos:pos + size]
    if block[:4] != b"SGB2" or struct.unpack_from("<I", block, 4)[0] != 10005:
        raise ValueError("Unexpected string block")
    return block


def recover(library, block, ids):
    emulator = Arm64Function(library)
    emulator.uc.hook_del(emulator.step_hook)

    def finish(value=0):
        emulator.uc.reg_write(UC_ARM64_REG_X0, value)
        emulator.uc.reg_write(UC_ARM64_REG_PC, emulator.uc.reg_read(UC_ARM64_REG_X30))

    for address, name in emulator.image.plt.copy().items():
        if name in ("malloc", "calloc", "free", "qsort"):
            def memory_helper(_, name=name):
                if name in ("malloc", "calloc"):
                    finish(emulator.alloc(emulator.reg(0) * (emulator.reg(1) if name == "calloc" else 1)))
                elif name == "qsort":
                    pointer, count, size = emulator.reg(0), emulator.reg(1), emulator.reg(2)
                    if size != 16 or count > 10005:
                        raise ValueError("Unexpected native sort")
                    rows = [emulator.read(pointer + i * size, size) for i in range(count)]
                    rows.sort(key=lambda row: struct.unpack_from("<I", row)[0])
                    emulator.uc.mem_write(pointer, b"".join(rows))
                    finish()
                else:
                    finish()
            del emulator.image.plt[address]
            emulator.observers[address] = memory_helper
        emulator.uc.hook_add(UC_HOOK_CODE, emulator._step, begin=address, end=address)
    context, source = emulator.alloc(0x958), emulator.alloc(block)
    if emulator.call(0x2E89C, context, source, len(block), 0x2DDC, 10005,
                     0x6757A190, 36, 0x61734425, limit=30_000_000) != 0:
        raise ValueError("Native parser failed")
    result = {}
    for ident in ids:
        pointer, length = emulator.alloc(8), emulator.alloc(8)
        if emulator.call(0x2ECB4, context, ident, pointer, length, limit=10_000_000) != 0:
            raise ValueError("Native lookup failed")
        pointer = struct.unpack("<Q", emulator.read(pointer, 8))[0]
        length = struct.unpack("<Q", emulator.read(length, 8))[0]
        if length > 8 * 1024 * 1024:
            raise ValueError("Oversized native string")
        value = emulator.read(pointer, length).replace(b"\xc0\x80", b"\0").decode("utf-8", errors="surrogatepass")
        result[str(ident if ident < 2**31 else ident - 2**32)] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--sources", type=Path, required=True, help="JADX sources/app/fast/ssh directory")
    parser.add_argument("--output", type=Path, required=True, help="New private JSON file, never overwrite")
    args = parser.parse_args()
    if args.apk.stat().st_size != 28602472 or hashlib.sha256(args.apk.read_bytes()).hexdigest() != APK_SHA256:
        raise ValueError("Unexpected APK; offsets apply only to the documented MOD")
    ids = sorted({int(value) & 0xFFFFFFFF for path in args.sources.rglob("*.java")
                  for value in re.findall(r"y\.m\d+\((-?\d+)\)", path.read_text())})
    if not ids or len(ids) > 2000:
        raise ValueError("Unexpected JADX input")
    with zipfile.ZipFile(args.apk) as archive, tempfile.TemporaryDirectory(prefix="ha-strings-") as temporary:
        libraries = [name for name in archive.namelist() if name.endswith("/arm64-v8a/libewutwwzwb.so")]
        if len(libraries) != 1:
            raise ValueError("Expected one ARM64 string library")
        library = Path(temporary) / "strings.so"
        library.write_bytes(archive.read(libraries[0])); library.chmod(0o600)
        result = recover(library, string_block(archive.read("assets/.ewutwwzwb.dex")), ids)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=True, indent=2)
    print(f"Recovered {len(result)} relevant strings; private inventory saved.")


if __name__ == "__main__":
    main()
