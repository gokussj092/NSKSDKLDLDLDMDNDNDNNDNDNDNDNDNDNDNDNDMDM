#!/usr/bin/env python3
"""Pin build59's native CU request and existing format constants; no JNI runs."""
from pathlib import Path
import argparse
import hashlib
import json
import sys

from go_inspect import GoImage

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoders.Python.ultra import VPNS_SD

SHA256 = "32840bca9b80405d90563c4e910433a4d36c8c83a93d4b0132eee35ae7537c87"


def check(path):
    if hashlib.sha256(path.read_bytes()).hexdigest() != SHA256:
        raise ValueError("Unsupported Ultra native build")
    image = GoImage(path)
    name = "github.com/2dust/AndroidLibXrayLite."
    expected = {"CU": (0x1019500, 1056), "decrypt": (0x1015fe0, 576), "DO": (0x1016970, 944)}
    if any(image.functions.get(name+k) != value for k, value in expected.items()):
        raise ValueError("Native function layout differs")
    code = list(image.disassemble(*expected["CU"]))
    for instruction in ("0x101954c mov x3, #3", "0x1019558 mov x5, #0x31",
                        "0x1019564 bl #0x8014d0 net/http.NewRequestWithContext",
                        "0x1019584 mov x1, #0xa", "0x10195a4 mov x2, #0xc",
                        "0x10196c0 bl #0x1015fe0 github.com/2dust/AndroidLibXrayLite.decrypt"):
        if instruction not in code:
            raise ValueError("CU request instructions differ")
    profile = VPNS_SD["ultratunnel"]
    if image.read(0x366351, 32) != profile["password"] or image.read(0x34bf00, 16) != profile["password2"]:
        raise ValueError("Original format constants differ")
    recipe = {"method": image.read(0x33e103, 3).decode(), "url": image.read(0x37f11b, 49).decode(),
              "header": image.read(0x3451b1, 10).decode(), "agent": image.read(0x347569, 12).decode()}
    if recipe != {"method": "GET", "url": profile["url"], "header": "User-Agent", "agent": profile["ua"]}:
        raise ValueError("Original request differs from the existing Ultra metadata")
    return {"nativeSha256": SHA256, "functions": {k: {"address": hex(v[0]), "bytes": v[1]} for k, v in expected.items()},
            "recipe": recipe, "existingFormatConstantsMatch": True, "nativeExecution": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.library)), flush=True)
