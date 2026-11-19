"""Compare the offline C++ host harness against the Python reference codec
over the synthetic fixtures in tests/fixtures/.

Positive fixtures (open in both, JSON must be identical after parsing):
  tls-profile1..5.tls  - one per modern key profile (profile 2 has an
                         odd-length plaintext, exercising the unequal
                         C1/C2 split)
  tls-profile6-legacy.tls - historic key, legacy DNS field names
  tls-link.txt         - tls:// text link, no ":::::" suffix
  tls-short.tls        - 5-field plaintext, defaults for the rest
  tls-profile3-bad-inner-b64.tls - invalid inner Base64 preserved as-is

Negative fixtures (both sides must reject; the C++ error code is checked):
  tls-tampered.tls   -> TLS_AUTH_FAILED
  tls-truncated.tls  -> TLS_CONTAINER_TOO_SHORT
  tls-garbage.tls    -> TLS_INVALID_BASE64
  tls-empty.tls      -> TLS_EMPTY_INPUT

No real credential is used or stored by this script; every fixture value
is invented (see tools/make_fixtures.py).

Usage:
  <venv python> tools/run_harness.py [--harness PATH] [--report PATH]
Default harness: /tmp/tls-harness-build/tls_harness
Default report: analysis/.../516/RESULTS_harness.json (next to RESULTS.md)
"""
import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

DOSSIER = Path(__file__).resolve().parents[1]
REPO_ROOT = DOSSIER.parents[2]
FIXTURES = DOSSIER / "tests" / "fixtures"

TLS_PY = REPO_ROOT / "decoders" / "Python" / "TLS.py"
spec = importlib.util.spec_from_file_location("tls_oracle", TLS_PY)
tls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tls)

POSITIVE = [
    "tls-profile1.tls",
    "tls-profile2.tls",
    "tls-profile3.tls",
    "tls-profile4.tls",
    "tls-profile5.tls",
    "tls-profile6-legacy.tls",
    "tls-link.txt",
    "tls-short.tls",
    "tls-profile3-bad-inner-b64.tls",
]

NEGATIVE = {
    "tls-tampered.tls": "TLS_AUTH_FAILED",
    "tls-truncated.tls": "TLS_CONTAINER_TOO_SHORT",
    "tls-garbage.tls": "TLS_INVALID_BASE64",
    "tls-empty.tls": "TLS_EMPTY_INPUT",
}


def oracle(path: Path):
    try:
        return tls._render_config(
            tls.decrypt_tls_payload(path.read_bytes().decode("utf-8-sig")))
    except Exception as exc:
        return ("ORACLE_ERROR", str(exc))


def run_harness(harness: str, path: Path):
    proc = subprocess.run([harness, str(path)], capture_output=True,
                          text=True, timeout=60)
    if proc.returncode == 0:
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError:
            return ("HARNESS_BAD_JSON", proc.stdout[:200])
    err = proc.stderr.strip()
    code = err.replace("ERROR ", "", 1) if err.startswith("ERROR ") else err
    return ("HARNESS_ERROR", code)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harness", default="/tmp/tls-harness-build/tls_harness")
    parser.add_argument("--report", default=str(DOSSIER / "RESULTS_harness.json"))
    args = parser.parse_args()

    results = {"positive": {}, "negative": {}}
    failures = 0

    for name in POSITIVE:
        path = FIXTURES / name
        expected = oracle(path)
        got = run_harness(args.harness, path)
        match = isinstance(expected, dict) and got == expected
        results["positive"][name] = {
            "match": match,
            "profile": expected.get("_tls", {}).get("key_profile", 6)
            if isinstance(expected, dict) else None,
        }
        if not match:
            failures += 1
            results["positive"][name]["expected"] = expected
            results["positive"][name]["got"] = got
        print(f"{'MATCH' if match else 'MISMATCH'} {name}")

    for name, code in NEGATIVE.items():
        path = FIXTURES / name
        expected = oracle(path)
        got = run_harness(args.harness, path)
        oracle_rejects = isinstance(expected, tuple)
        harness_rejects = (isinstance(got, tuple) and got[0] == "HARNESS_ERROR"
                           and got[1] == code)
        ok = oracle_rejects and harness_rejects
        results["negative"][name] = {
            "match": ok, "expected_code": code,
            "oracle": expected, "got": got,
        }
        if not ok:
            failures += 1
        print(f"{'MATCH' if ok else 'MISMATCH'} {name} (expect {code})")

    total = len(POSITIVE) + len(NEGATIVE)
    passed = total - failures
    results["summary"] = {"passed": passed, "total": total, "failures": failures}
    Path(args.report).write_text(
        json.dumps(results, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8")
    print(f"{passed}/{total} MATCH")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
