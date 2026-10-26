#!/usr/bin/env python3
"""Read Go f1/64-bit pclntab and annotate AArch64 disassembly, offline only.

Resolve missing textStart through relocated runtime.moduledata, rather than
guessing .text or adding an arbitrary offset. Unknown layouts fail explicitly.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import struct
from elf_inspect import ElfImage


def find_pclntab(elf):
    """Modern external linking can merge gopclntab into .data.rel.ro."""
    signature = b"\xf1\xff\xff\xff\0\0\x04\x08"
    section = elf.get_section_by_name(".gopclntab")
    if section is not None:
        data = section.data()
        if data[:8] != signature:
            raise ValueError("Unsupported Go pclntab layout")
        return data, section["sh_addr"]
    section = elf.get_section_by_name(".data.rel.ro")
    if section is None:
        raise ValueError("Unsupported Go pclntab layout")
    data = section.data()
    offset = data.find(signature)
    if offset < 0 or data.find(signature, offset + 1) >= 0:
        raise ValueError("Missing or ambiguous embedded Go pclntab")
    return data[offset:], section["sh_addr"] + offset


class GoImage(ElfImage):
    def __init__(self, path):
        super().__init__(path)
        data, table_address = find_pclntab(self.elf)
        if len(data) < 72:
            raise ValueError("Truncated Go pclntab")
        count, _, start, names, _, _, _, pcln = struct.unpack_from("<8Q", data, 8)
        if not 0 < count < 1_000_000 or pcln + (count + 1) * 8 > len(data):
            raise ValueError("Invalid function table bounds")
        if not start:
            relative = {r["r_offset"]: r["r_addend"] for r in self.relocations if r["r_info_type"] == 1027}
            candidates = {relative[p + 176] for p, value in relative.items()
                          if value == table_address and p + 176 in relative}
            if len(candidates) != 1:
                raise ValueError("Cannot resolve relocated Go textStart")
            start = candidates.pop()
        self.functions = {}
        for i in range(count):
            entry, record = struct.unpack_from("<2I", data, pcln + i * 8)
            following = struct.unpack_from("<I", data, pcln + (i + 1) * 8)[0]
            if following < entry or pcln + record + 8 > len(data):
                raise ValueError("Invalid function record")
            name_offset = struct.unpack_from("<i", data, pcln + record + 4)[0]
            pos = names + name_offset
            if not 0 <= pos < len(data):
                raise ValueError("Invalid function name offset")
            end = data.find(b"\0", pos, min(pos + 4096, len(data)))
            if end < 0:
                raise ValueError("Unterminated Go function name")
            name = data[pos:end].decode("utf-8")
            address = start + entry
            self.read(address, min(4, following - entry))
            self.functions[name] = (address, following - entry)
            self.symbols[address] = name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--filter", default="npv-tunnel-core/MobileLibrary/libnpvtunnel")
    parser.add_argument("--disassemble", help="exact Go symbol name")
    args = parser.parse_args()
    image = GoImage(args.file)
    if args.disassemble:
        address, size = image.functions[args.disassemble]
        if size > 65536:
            parser.error("Function exceeds the disassembly limit")
        print("\n".join(image.disassemble(address, size)))
    else:
        pattern = re.compile(args.filter)
        print(json.dumps({k: {"address": hex(v[0]), "size": v[1]}
                          for k, v in image.functions.items() if pattern.search(k)}, indent=2))


if __name__ == "__main__":
    main()
