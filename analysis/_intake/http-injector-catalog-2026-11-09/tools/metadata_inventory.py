#!/usr/bin/env python3
"""Inventory selected server UI type names from known, partial DEX metadata.

This is not a DEX reconstruction or an executable-code extractor. Original
headers/tables are partially overwritten. No method operands, constants, keys
or string pools are exported. Inputs and intermediate data stay outside Git.
"""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

LIBRARY_SHA256 = "2563039f827ff936035abfbe7aeb0cb9d4bac8bf42f414bb6c68cf7241081a4d"
FRAME_SHA256 = "c27c702a5b4ed762b3389777a14547650e056615999bfcb9cf8b29b5ff22e654"
TYPE = re.compile(
    r"Lcom/evozi/injector/(?:views/ServersActivity(?:\$[^;/]*)?"
    r"|model/(?:LogicalServers|ConfigEhiServer|EncryptedApi)"
    r"|fragment/HomeFragment\$fetchAndUpdateServerConfig[^;]*);"
)


def uleb128(data, offset):
    result = 0
    for shift in range(0, 35, 7):
        value = data[offset]
        offset += 1
        if shift == 28 and value > 15:
            raise ValueError("INVALID_ULEB128")
        result |= (value & 127) << shift
        if value < 128:
            return result, offset
    raise ValueError("INVALID_ULEB128")


def inventory_types(data, base, map_offset):
    count = struct.unpack_from("<I", data, map_offset)[0]
    if not 10 <= count <= 40:
        raise ValueError("INVALID_MAP")
    sections = {}
    for index in range(count):
        kind, unused, size, offset = struct.unpack_from(
            "<HHII", data, map_offset + 4 + index * 12
        )
        if unused or size > 100000 or base + offset >= len(data):
            raise ValueError("INVALID_MAP_ENTRY")
        sections[kind] = (size, base + offset)
    string_count, cursor = sections[0x2002]
    strings = []
    for _ in range(string_count):
        _, cursor = uleb128(data, cursor)
        end = data.index(b"\0", cursor)
        # MUTF-8 NUL/surrogate data need not be decoded for these type names.
        # Only exact descriptor matches below leave this function.
        strings.append(data[cursor:end].decode("utf-8", errors="replace"))
        cursor = end + 1
    type_count, offset = sections[2]
    identifiers = set()
    valid_references = 0
    for index in range(type_count):
        string_index = struct.unpack_from("<I", data, offset + index * 4)[0]
        if string_index >= len(strings):
            continue
        valid_references += 1
        value = strings[string_index]
        if TYPE.fullmatch(value):
            identifiers.add(value)
    return {
        "baseOffset": hex(base),
        "mapOffset": hex(map_offset),
        "stringDataItemsVisited": len(strings),
        "typeItemsVisited": type_count,
        "inRangeTypeStringReferences": valid_references,
        "selectedTypeIdentifiers": sorted(identifiers),
        "completeDexReconstructed": False,
    }


def inspect(private):
    library = (private / "inputs/libdatajar.so").read_bytes()
    frame = (private / "code-frame.bin").read_bytes()
    if hashlib.sha256(library).hexdigest() != LIBRARY_SHA256:
        raise ValueError("BUILD_HASH_MISMATCH")
    if hashlib.sha256(frame).hexdigest() != FRAME_SHA256:
        raise ValueError("FRAME_HASH_MISMATCH")
    result = {
        "metadata": [
            inventory_types(library, 0x4018, 0x163600),
            inventory_types(frame, 0x581000, 0x6EE49C),
            inventory_types(frame, 0x16CC000, 0x172C228),
        ],
        "apkCodeExecuted": False,
        "authenticationMaterialCollected": False,
        "catalogVerified": False,
        "limitation": (
            "Selected class names establish server UI/model presence only. "
            "Overwritten headers/tables and unsupported class-data do not "
            "establish a valid request, endpoint, credentials or authentication requirement."
        ),
    }
    target = private / "metadata-inventory.json"
    target.write_text(json.dumps(result, ensure_ascii=True, indent=2) + "\n")
    target.chmod(0o600)
    print(json.dumps(result, ensure_ascii=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("private", type=Path)
    inspect(parser.parse_args().private)
