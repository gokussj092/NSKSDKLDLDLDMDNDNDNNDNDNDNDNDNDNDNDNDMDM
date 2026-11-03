#!/usr/bin/env python3
"""Check that a compiled Cloud release APK and AAB contain all four correct native ABIs.

This audits *actual archives*, not Gradle configuration. It never signs,
publishes or creates any QA application.
"""
import argparse
from pathlib import Path
import struct
from zipfile import ZipFile, BadZipFile

# Android ABI -> ELF class (1=32-bit, 2=64-bit), e_machine.
ABIS = {
    "armeabi-v7a": (1, 40),  # EM_ARM
    "arm64-v8a": (2, 183),  # EM_AARCH64
    "x86": (1, 3),          # EM_386
    "x86_64": (2, 62),      # EM_X86_64
}
LIBRARY = "libv7q3.so"


def verify(archive: Path, prefix: str) -> None:
    if not archive.is_file() or archive.stat().st_size == 0:
        raise ValueError(f"Artifact missing or empty: {archive}")
    with ZipFile(archive) as z:
        names = set(z.namelist())
        if z.testzip() is not None:
            raise ValueError(f"Invalid ZIP entry in {archive}")
        seen = set()
        for abi, (elf_class, machine) in ABIS.items():
            path = f"{prefix}lib/{abi}/{LIBRARY}"
            if path not in names:
                raise ValueError(f"{archive.name}: missing {path}")
            entry = z.getinfo(path)
            if entry.file_size < 4096:
                raise ValueError(f"{archive.name}: implausible ELF size for {path}")
            with z.open(path) as src:
                h = src.read(20)
            if len(h) != 20 or h[:4] != b"\x7fELF" or h[5] != 1:
                raise ValueError(f"{archive.name}: invalid little-endian ELF: {path}")
            if h[4] != elf_class or struct.unpack("<H", h[18:20])[0] != machine:
                raise ValueError(f"{archive.name}: mismatched ABI/ELF machine: {path}")
            seen.add(abi)
        print(f"{archive.name}: PASS, {len(seen)} native ABIs: {', '.join(sorted(seen))}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--aab", required=True, type=Path)
    args = parser.parse_args()
    verify(args.apk, "")
    verify(args.aab, "base/")


if __name__ == "__main__":
    main()
