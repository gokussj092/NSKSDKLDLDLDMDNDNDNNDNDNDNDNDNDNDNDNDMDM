#!/usr/bin/env python3
"""Run the original B46 ARM64 grant-binding block on synthetic JDK data.

Only metadata parsing and the binding block execute. No JNI, RSA, AES, Android,
attestation, network, or complete app execution is emulated here.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X25
from arm64_function import Arm64Function

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoders.Python import flexnet_b42 as codec

SO_SHA256 = "a1779083ed5418eedd1ff70ea10e729745dfc2baac27ec2441fc517ff80098bb"


def verify(path: Path) -> dict:
    if hashlib.sha256(path.read_bytes()).hexdigest() != SO_SHA256:
        raise ValueError("Expected the exact FlexNet B46 arm64 library")
    vectors = json.loads((ROOT / "tests/golden/flexnet_b46_vectors.json").read_text())
    capture = (ROOT / "tests/golden/flexnet_b46_grant_capture.json").read_bytes()
    obj = json.loads(capture)
    profile = base64.b64decode(vectors["online"])
    grant = base64.b64decode(obj["grantBase64"])
    challenge = base64.b64decode(obj["challengeBase64"])
    runner = Arm64Function(path)
    profile_ptr = runner.alloc(profile)
    metadata_ptr = runner.alloc(32)
    if runner.call(0x335d8c, profile_ptr, len(profile), 46, metadata_ptr) != 1:
        raise AssertionError("Original native parser rejected the JDK online header")
    metadata = profile[13:41] + profile[9:13]
    if runner.read(metadata_ptr, 32) != metadata:
        raise AssertionError("Original native metadata differs")

    grant_ptr = runner.alloc(grant)
    challenge_ptr = runner.alloc(challenge)
    sp = runner.STACK + 0xF0000
    for offset, pointer in ((0x90, grant_ptr), (0x60, metadata_ptr), (0x78, challenge_ptr)):
        runner.uc.mem_write(sp + offset, struct.pack("<Q", pointer))
    runner.uc.mem_write(sp + 0xC0, hashlib.sha256(profile).digest())
    accepted = []

    def stop(value):
        def observe(machine):
            accepted.append(value)
            machine.uc.reg_write(UC_ARM64_REG_PC, machine.STOP)
        return observe

    # Boundaries obtained from the exact original transport, not patched checks.
    runner.observers[0x336a8c] = stop(True)
    runner.observers[0x33616c] = stop(False)
    runner.observers[0x336174] = stop(False)

    def native_check(candidate):
        runner.uc.mem_write(grant_ptr, candidate)
        runner.uc.reg_write(UC_ARM64_REG_X25, 0)  # Java encrypt=false => grant mode 2
        accepted.clear()
        runner.call(0x336a10, limit=10000)
        if len(accepted) != 1:
            raise AssertionError("Binding block did not reach a known boundary")
        return accepted[0]

    if not native_check(grant):
        raise AssertionError("Original binding block rejected the JDK grant")
    if codec.file_key_from_grant(profile, grant, challenge).hex() != vectors["fileKey"]:
        raise AssertionError("Python grant key differs from the JDK key")
    for offset in range(32, 117):
        altered = bytearray(grant)
        altered[offset] ^= 1
        if native_check(bytes(altered)):
            raise AssertionError("Original binding block accepted an altered binding")
        try:
            codec.file_key_from_grant(profile, bytes(altered), challenge)
        except codec.DecodeError as error:
            if error.code != "GRANT_BINDING":
                raise
        else:
            raise AssertionError("Python accepted an altered binding")
    # The first 32 bytes are the AES key: binding checks alone cannot validate it.
    altered = bytes([grant[0] ^ 1]) + grant[1:]
    if not native_check(altered):
        raise AssertionError("Unexpected key comparison in native binding block")
    key = codec.file_key_from_grant(profile, altered, challenge)
    try:
        codec.decode(profile, file_key=key)
    except codec.DecodeError as error:
        if error.code != "AUTH_FAILED":
            raise
    else:
        raise AssertionError("Wrong content key passed GCM verification")
    if codec.decrypt_profile_xml(profile, grant_capture=capture) != vectors["xml"]:
        raise AssertionError("JDK and Python full XML differ")
    return {"nativeBindingCases": 87, "alteredBindingRejections": 85,
            "fullXmlMatchesJdk": True, "nativeScope": "metadata-and-binding-only"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.library), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
