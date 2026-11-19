"""Oracle for the offline native TLS Tunnel decoder.

Thin wrapper over the server decoder decoders/Python/TLS.py: exposes the
exact JSON the C++ port must reproduce (decrypt_tls_payload + _render_config)
so tools/run_harness.py can compare profile-for-profile.

Usage:
  python3 tools/ref_tls.py <file.tls|file.txt> [--json]
Prints the rendered config as JSON (or the TLS.py text form without --json).
Exit 1 with the Python error on stderr when the input does not open.
"""
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
TLS_PY = REPO_ROOT / "decoders" / "Python" / "TLS.py"

spec = importlib.util.spec_from_file_location("tls_oracle", TLS_PY)
tls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tls)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: ref_tls.py <file.tls|file.txt> [--json]", file=sys.stderr)
        return 2
    data = Path(sys.argv[1]).read_bytes()
    try:
        config = tls._render_config(
            tls.decrypt_tls_payload(data.decode("utf-8-sig")))
    except Exception as exc:  # oracle failure = input does not open
        print(f"TLS oracle error: {exc}", file=sys.stderr)
        return 1
    if "--json" in sys.argv[1:]:
        print(json.dumps(config, indent=2, ensure_ascii=False))
    else:
        print("TLS Tunnel\n" + "=" * 30 + "\n\n" +
              json.dumps(config, indent=4, ensure_ascii=False) +
              "\n\n" + "=" * 30)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
