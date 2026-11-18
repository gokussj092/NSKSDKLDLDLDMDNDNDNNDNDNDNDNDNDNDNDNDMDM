#!/usr/bin/env python3
"""Check running web HPKE key IDs against the native Android *public* pin.

Never prints private keyring JSON, environment variables, public-key bytes,
or any config file. This is a non-mutating operator diagnostic.
"""
import argparse
import hashlib
import pathlib
import re
import subprocess
import sys

NATIVE = pathlib.Path(__file__).resolve().parents[3] / "android/app/src/main/cpp/spdecode_transport.cpp"
SHARE = re.compile(r"kHpkePinPart([AB])\[kHpkePinLength\]=\{([^}]+)\};")
KID = re.compile(r"^[a-f0-9]{16}$")
JS = (
    'const {hpkeKeyIds}=await import("/app/lib/v2-hpke.mjs");'
    'if(process.env.CLOUD_V2_HPKE_ENABLED!=="true")process.exit(3);'
    'const ids=hpkeKeyIds();'
    'if(!ids.length||ids.some(id=>!/^[0-9a-f]{16}$/.test(id)))process.exit(4);'
    'process.stdout.write(ids.join(","));'
)


def expected_key_id(path=NATIVE):
    data = pathlib.Path(path).read_text("utf-8")
    matches = SHARE.findall(data)
    shares = {}
    for label, values in matches:
        values = re.findall(r"0x[0-9a-fA-F]{2}", values)
        if len(values) != 40 or label in shares:
            raise ValueError("Native public pin shares are invalid")
        shares[label] = bytes(int(value, 16) for value in values)
    if set(shares) != {"A", "B"}:
        raise ValueError("Native public pin shares are missing")
    pin = bytes(a ^ b for a, b in zip(shares["A"], shares["B"]))
    kid = hashlib.sha256(pin[8:]).digest()[:8]
    if kid != pin[:8]:
        raise ValueError("Native public pin hash does not match public key")
    return kid.hex()


def running_key_ids():
    result = subprocess.run(
        ["docker", "ps", "-q",
         "--filter", "label=com.docker.compose.project=spdecode",
         "--filter", "label=com.docker.compose.service=web"],
        capture_output=True, text=True, timeout=10, check=True,
    )
    containers = result.stdout.split()
    if len(containers) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", containers[0]):
        raise RuntimeError("Expected exactly one running SP-DECODE web container")
    reply = subprocess.run(
        ["docker", "exec", containers[0], "node", "--input-type=module", "-e", JS],
        capture_output=True, text=True, timeout=15, check=True,
    )
    ids = reply.stdout.strip().split(",")
    if not ids or any(not KID.fullmatch(item) for item in ids):
        raise RuntimeError("Web returned an invalid or empty HPKE key ID set")
    return ids


def main():
    parser = argparse.ArgumentParser(description="Read-only SP-DECODE HPKE public pin compatibility")
    parser.add_argument("--expected-only", action="store_true",
                        help="Print only Android public key ID (no Docker calls)")
    args = parser.parse_args()
    try:
        expected = expected_key_id()
        if args.expected_only:
            print("Android pinned HPKE public ID:", expected)
            return 0
        compatible = expected in running_key_ids()
        print("Android / running web HPKE pin:", "MATCH" if compatible else "MISMATCH")
        print("Result:", "compatible" if compatible else "incompatible")
        return 0 if compatible else 2
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        # Error classes only; subprocess stderr/env is intentionally discarded.
        print("HPKE audit could not complete:", type(error).__name__, file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
