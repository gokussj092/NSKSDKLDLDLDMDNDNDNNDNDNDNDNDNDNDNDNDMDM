"""Compare the offline C++ host harness against the Python reference codec
over the 12 real 934 samples plus the synthetic n15 fixtures.

Real-sample expectations (from the verified Python reference, 2026-11-16):
  5 n15 files open without a password (2 profiles each);
  3 n15 protected files require a password (PASSWORD_REQUIRED without one,
  AUTH_FAILED with a wrong one — the positive open with Pedro's test
  password cannot be run here because that password was supplied in chat
  and was never persisted to any file this session can read; see RESULTS.md);
  4 files fail cleanly as UNSUPPORTED (n16, n17, n18, b=9).

Synthetic fixtures (tests/fixtures/, synthetic password only):
  open fixture opens (1 profile + sidecar); protected fixture opens with the
  synthetic password (2 profiles, one HPR1-wrapped) and fails without it
  (PASSWORD_REQUIRED) / with a wrong one (AUTH_FAILED); tampered and
  truncated fixtures are rejected.

No real credential is used or stored by this script. The only passwords it
passes are the synthetic fixture password and the fixed wrong-password probe
"wrong-password-for-test".

Usage:
  <venv python> tools/run_harness.py [--harness PATH] [--report PATH]
Default harness: /tmp/hc-n15-harness-build/hc_harness
Default report: analysis/.../934/RESULTS_harness.json (written next to RESULTS.md)
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

DOSSIER = Path(__file__).resolve().parents[1]
DRIVE = Path("/home/hatch/workspace/http-custom-update/drive")
VENV_PY = "/home/hatch/workspace/http-custom-update/venv/bin/python"
REF = Path(__file__).resolve().parent / "ref_decrypt.py"
FIXTURES = DOSSIER / "tests" / "fixtures"

NO_PASSWORD = [
    "Test Oppen.hc",
    "Test bloquear usuário y contraseña.hc",
    "Test bloqueo de root2.hc",
    "Test bloqueo inicio de sesión con hwid.hc",
    "Test desbloqueo payload.hc",
]
PROTECTED = [
    "Test bloqueo de operador.hc",
    "Test bloqueo de root.hc",
    "Test password2.hc",
]
UNSUPPORTED = [
    "Test bloqueo password y hwid.hc",   # b=12/n16
    "Test password.hc",                  # b=13/n17
    "Test hwid.hc",                      # b=13/n18
    "Test bloqueo ID de acceso.hc",      # b=9 RSA wrapper
]
SYNTHETIC_PASSWORD = "synthetic-n15-test-password"
WRONG_PASSWORD = "wrong-password-for-test"

PROFILE_FIELDS = ["label", "name", "protocol", "host", "port", "username",
                  "password", "payload", "mode", "flags", "updated_at_ms"]


def run(cmd):
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return proc.returncode, proc.stdout, proc.stderr.strip()


def norm_profiles(result):
    out = []
    for p in result.get("config", []):
        entry = {k: p.get(k) for k in PROFILE_FIELDS}
        entry["options"] = p.get("options", {})
        if "custom_payload_sidecar" in p:
            entry["custom_payload_sidecar"] = p["custom_payload_sidecar"]
        if "custom_payload_sidecar_hex" in p:
            entry["custom_payload_sidecar_hex"] = p["custom_payload_sidecar_hex"]
        out.append(entry)
    return out


def check_open(harness, path, password=None):
    """Run harness (+ reference when no password is needed) and compare."""
    args = [str(harness), str(path)]
    if password is not None:
        args.append(password)
    rc, out, err = run(args)
    row = {"file": Path(path).name, "harness_rc": rc}
    if rc != 0:
        row.update(status="FAIL", harness_error=err)
        return row
    try:
        cpp = json.loads(out)
    except json.JSONDecodeError:
        row.update(status="FAIL", harness_error="INVALID_JSON_OUTPUT")
        return row
    row["profiles"] = len(cpp.get("config", []))
    row["app_version"] = cpp.get("app_version")
    row["other_sections"] = [s.get("label") for s in cpp.get("other_sections", [])]
    if password is None:
        rrc, rout, rerr = run([VENV_PY, str(REF), str(path)])
        if rrc != 0:
            row.update(status="MISMATCH",
                       reference_error=rerr, note="reference failed, harness opened")
            return row
        ref = json.loads(rout)
        cpp_profiles = norm_profiles(cpp)
        ref_profiles = norm_profiles(ref)
        if cpp_profiles == ref_profiles and cpp.get("app_version") == ref.get("app_version"):
            row["status"] = "MATCH"
        else:
            row.update(status="MISMATCH", cpp_profiles=cpp_profiles,
                       ref_profiles=ref_profiles,
                       cpp_version=cpp.get("app_version"),
                       ref_version=ref.get("app_version"))
    else:
        row["status"] = "OPEN"
    return row


def check_fail(harness, path, password, expect):
    args = [str(harness), str(path)]
    if password is not None:
        args.append(password)
    rc, _out, err = run(args)
    got = err.replace("ERROR ", "") if err.startswith("ERROR ") else err
    return {"file": Path(path).name, "harness_rc": rc,
            "expected": expect, "got": got,
            "status": "MATCH" if rc != 0 and got == expect else "MISMATCH"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--harness", default="/tmp/hc-n15-harness-build/hc_harness")
    ap.add_argument("--report", default=str(DOSSIER / "RESULTS_harness.json"))
    args = ap.parse_args()
    harness = args.harness
    rows = []

    for name in NO_PASSWORD:
        rows.append(check_open(harness, DRIVE / name))
    for name in PROTECTED:
        rows.append(check_fail(harness, DRIVE / name, None, "PASSWORD_REQUIRED"))
        rows.append(check_fail(harness, DRIVE / name, WRONG_PASSWORD, "AUTH_FAILED"))
    for name in UNSUPPORTED:
        rows.append(check_fail(harness, DRIVE / name, None, "HC_UNSUPPORTED_SCHEMA"))
    # Synthetic fixtures: positive password-branch verification.
    rows.append(check_open(harness, FIXTURES / "synthetic_n15_open.hc"))
    rows.append(check_open(harness, FIXTURES / "synthetic_n15_protected.hc",
                           password=SYNTHETIC_PASSWORD))
    rows.append(check_fail(harness, FIXTURES / "synthetic_n15_protected.hc",
                           None, "PASSWORD_REQUIRED"))
    rows.append(check_fail(harness, FIXTURES / "synthetic_n15_protected.hc",
                           WRONG_PASSWORD, "AUTH_FAILED"))
    tampered = check_fail(harness, FIXTURES / "synthetic_n15_tampered.hc",
                          None, "AUTH_FAILED")
    # A tampered outer tag may surface as unrecognized instead; either is a
    # clean rejection, but record the exact code.
    if tampered["status"] == "MISMATCH" and tampered["got"] in (
            "HC_UNRECOGNIZED_FORMAT", "HC_INVALID_ENVELOPE"):
        tampered["status"] = "MATCH_REJECTED"
        tampered["expected"] = "AUTH_FAILED|HC_UNRECOGNIZED_FORMAT"
    rows.append(tampered)
    rows.append(check_fail(harness, FIXTURES / "synthetic_n15_truncated.hc",
                           None, "HC_UNRECOGNIZED_FORMAT"))

    summary = {
        "harness": harness,
        "total": len(rows),
        "match": sum(1 for r in rows if r["status"] in ("MATCH", "OPEN", "MATCH_REJECTED")),
        "mismatch": [r for r in rows if r["status"] not in
                     ("MATCH", "OPEN", "MATCH_REJECTED")],
        "rows": rows,
    }
    Path(args.report).write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    for r in rows:
        print(f"{r['status']:15} {r['file']} {r.get('profiles', '')}"
              f"{' ' + r.get('got', '') if 'got' in r else ''}")
    print(f"\n{summary['match']}/{summary['total']} checks matched; "
          f"report: {args.report}")
    return 0 if not summary["mismatch"] else 1


if __name__ == "__main__":
    sys.exit(main())
