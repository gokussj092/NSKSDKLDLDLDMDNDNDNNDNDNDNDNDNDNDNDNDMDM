"""Cross-check the SSC oracle against the real server decoder.

For every positive fixture: the mapped JSON produced by this oracle
must equal the mapped JSON recovered from the SERVER decoder
(decoders/Python/SSCCUSTOM.py run() banner output) and must equal the
expected JSON written by make_fixtures.py. For every negative fixture
both decoders must return None / no result.

The server decoder returns banner text, so its CONFIGS line (a JSON
array) and NOTE line are extracted back for comparison.

Usage (from the repo root):
    python3 analysis/dev.epro.ssc/96/tools/verify.py [--server DIR]
Default --server is the repo root that contains decoders/Python/.
Exit 0 only when every case matches.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOSSIER = HERE.parent
FIX = DOSSIER / "tests" / "fixtures"
EXP = DOSSIER / "tests" / "expected"

sys.path.insert(0, str(HERE))
from ssc_oracle import decode_mapped  # noqa: E402

POSITIVE = ["single_layer", "two_layer", "inner_encrypted", "ssc_link"]
NEGATIVE = ["truncated", "bad_hex", "garbage", "empty", "odd_hex",
            "valid_l1_no_json"]
SUFFIX = {"single_layer": ".ssc", "two_layer": ".ssc",
          "inner_encrypted": ".ssc", "ssc_link": ".txt"}


def _server_decode(server_root: Path, data: bytes):
    """Run the real server decoder; return its mapped dict or None."""
    sys.path.insert(0, str(server_root / "decoders" / "Python"))
    import SSCCUSTOM  # noqa: E402
    out = SSCCUSTOM.run(data)
    if not out:
        return None
    mapped: dict = {}
    for line in out.splitlines():
        m = re.match(r"│\[۞\] ([^:]+): (.*)$", line)
        if not m:
            continue
        key, value = m.group(1).strip(), m.group(2)
        if key in {"𝗚𝗥𝗢𝗨𝗣", "𝗖𝗛𝗔𝗡𝗡𝗘𝗟"}:
            continue  # banner footer, not mapped profile data
        try:
            mapped[key] = json.loads(value)
        except (json.JSONDecodeError, ValueError):
            mapped[key] = value
    return mapped or None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default=None,
                    help="repo root containing decoders/Python")
    args = ap.parse_args()
    server_root = Path(args.server) if args.server else Path("/tmp/ssc-server")
    # Default: the spdecode-patch checkout next to this worktree, else cwd.
    if not (server_root / "decoders" / "Python" / "SSCCUSTOM.py").exists():
        for cand in (Path.home() / "workspace" / "spdecode-patch",
                     Path.cwd()):
            if (cand / "decoders" / "Python" / "SSCCUSTOM.py").exists():
                server_root = cand
                break
    print(f"server decoder: {server_root}/decoders/Python/SSCCUSTOM.py")
    passes = failures = 0

    def check(name: str, ok: bool, detail: str = ""):
        nonlocal passes, failures
        if ok:
            passes += 1
            print(f"PASS {name}")
        else:
            failures += 1
            print(f"FAIL {name}: {detail}")

    for name in POSITIVE:
        data = (FIX / f"{name}{SUFFIX[name]}").read_bytes()
        expected = json.loads((EXP / f"{name}.json").read_text())
        got_oracle = decode_mapped(data)
        check(f"{name}/oracle==expected", got_oracle == expected,
              f"oracle={got_oracle!r} expected={expected!r}")
        got_server = _server_decode(server_root, data)
        check(f"{name}/server==expected", got_server == expected,
              f"server={got_server!r} expected={expected!r}")
        check(f"{name}/oracle==server", got_oracle == got_server)

    for name in NEGATIVE:
        data = (FIX / f"{name}.ssc").read_bytes()
        check(f"{name}/oracle-rejects", decode_mapped(data) is None,
              f"oracle returned {decode_mapped(data)!r}")
        check(f"{name}/server-rejects",
              _server_decode(server_root, data) is None)

    print(f"\nverify.py: {passes} passed, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
