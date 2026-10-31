#!/usr/bin/env python3
"""Validate 16 KiB ELF PT_LOAD alignment in APK and AAB native libraries."""
from __future__ import annotations

import argparse
import struct
import zipfile
from pathlib import Path

PAGE_SIZE = 16 * 1024
SUPPORTED_64 = ("/arm64-v8a/", "/x86_64/")


def load_segments(binary: bytes) -> list[tuple[int, int, int]]:
    if len(binary) < 64 or binary[:4] != b"\x7fELF":
        raise ValueError("not an ELF shared library")
    if binary[4] != 2 or binary[5] not in (1, 2):
        raise ValueError("expected supported ELF64 encoding")
    endian = "<" if binary[5] == 1 else ">"
    phoff = struct.unpack_from(endian + "Q", binary, 32)[0]
    entry_size = struct.unpack_from(endian + "H", binary, 54)[0]
    count = struct.unpack_from(endian + "H", binary, 56)[0]
    if entry_size < 56 or count == 0 or count > 256:
        raise ValueError("missing or invalid ELF program headers")
    segments: list[tuple[int, int, int]] = []
    for index in range(count):
        offset = phoff + index * entry_size
        if offset + 56 > len(binary):
            raise ValueError("truncated ELF program header")
        kind, _flags, file_off, vaddr, _paddr, _filesz, _memsz, align = (
            struct.unpack_from(endian + "IIQQQQQQ", binary, offset)
        )
        if kind == 1:
            segments.append((file_off, vaddr, align))
    if not segments:
        raise ValueError("ELF has no loadable segments")
    return segments


def verify_elf(binary: bytes) -> list[int]:
    segments = load_segments(binary)
    for offset, vaddr, align in segments:
        if align < PAGE_SIZE or (vaddr - offset) % PAGE_SIZE:
            raise ValueError(
                f"ELF LOAD alignment fails 16 KiB: align={align}, "
                f"offset={offset}, vaddr={vaddr}"
            )
    return [align for _, _, align in segments]


def audit_archive(path: Path) -> list[str]:
    verified: list[str] = []
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if not any(name.endswith("/libv7q3.so") for name in names):
            raise ValueError(f"{path.name}: libv7q3.so missing")
        for name in sorted(names):
            if not name.endswith(".so") or not any(abi in "/" + name for abi in SUPPORTED_64):
                continue
            try:
                alignment = verify_elf(archive.read(name))
            except ValueError as exc:
                raise ValueError(f"{path.name}:{name}: {exc}") from exc
            verified.append(f"{name}: PT_LOAD aligned ({min(alignment)} bytes)")
    if not verified:
        raise ValueError(f"{path.name}: no inspected 64-bit ELF libraries")
    return verified


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", type=Path, nargs="+")
    args = parser.parse_args()
    for path in args.archives:
        for line in audit_archive(path):
            print(f"{path.name}: {line}")


if __name__ == "__main__":
    main()
