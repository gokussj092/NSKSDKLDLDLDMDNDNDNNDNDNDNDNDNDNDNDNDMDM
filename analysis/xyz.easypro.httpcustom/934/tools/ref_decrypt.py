"""Reference oracle for the harness comparison: decrypt one .hc with the
server codec (decoders/Python/apps/HTTP_Custom/codec.py) and print the
normalized result as JSON. Password comes only from argv (runtime input,
never stored). Usage: <venv python> ref_decrypt.py <file.hc> [password]
On failure prints "ERROR <message>" on stderr and exits 1.
"""
import json
import sys
from pathlib import Path

PATCH = Path("/home/hatch/workspace/spdecode-patch")
sys.path.insert(0, str(PATCH / "decoders/Python/apps/HTTP_Custom"))
sys.path.insert(0, str(PATCH / "decoders/Python"))
import importlib.util

spec = importlib.util.spec_from_file_location(
    "hc_codec", PATCH / "decoders/Python/apps/HTTP_Custom/codec.py")
codec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(codec)


def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("usage: ref_decrypt.py <file.hc> [password]", file=sys.stderr)
        return 3
    password = sys.argv[2] if len(sys.argv) == 3 else None
    try:
        result = codec.decrypt(Path(sys.argv[1]).read_bytes(), password=password)
    except Exception as error:  # HCError and friends
        print(f"ERROR {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
