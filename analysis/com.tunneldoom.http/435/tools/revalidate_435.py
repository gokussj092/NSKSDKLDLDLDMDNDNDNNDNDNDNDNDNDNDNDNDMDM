#!/usr/bin/env python3
"""Revalidate the TunnelDOOM 4.3.5 re-analysis: live fetch from the new host,
old-host liveness check, and a proof JSON with counts/hashes only.

No decrypted catalog, credential, or server address is written anywhere.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
from pathlib import Path
from urllib.request import Request, build_opener

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "decoders/Python/apps/TunnelDOOM_VPN"))
import codec  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    proof: dict = {"app": "TunnelDOOM VPN", "version_code": 435}
    # Old host: expect failure (connection closes).
    try:
        with build_opener().open(
                Request("https://web.tunneldoom.space/config.json",
                        headers={"Accept-Encoding": "identity",
                                 "User-Agent": "Dalvik/2.1.0"}),
                timeout=10) as resp:
            proof["old_host"] = {"alive": True, "status": resp.status}
    except Exception as exc:  # noqa: BLE001 - liveness probe only
        proof["old_host"] = {"alive": False, "error": type(exc).__name__}
    # New host: live fetch + full decode, counts only. Same headers as
    # the decoder (the host rejects bare urllib requests with 403).
    with build_opener().open(
            Request("https://free.tunneldoom.space/config.json",
                    headers={"Accept-Encoding": "identity",
                             "User-Agent": "Dalvik/2.1.0"}),
            timeout=30) as resp:
        raw = resp.read(codec.MAX_BYTES + 1)
    proof["new_host"] = {
        "alive": True, "status": resp.status,
        "envelope_bytes": len(raw),
        "envelope_sha256": hashlib.sha256(raw).hexdigest(),
    }
    doc = codec.decode_catalog(raw)
    proof["catalog"] = {
        "version": doc.get("Version"),
        "servers": len(doc.get("Servers", [])),
        "servers_with_payload": sum(
            1 for s in doc.get("Servers", []) if s.get("Payload")),
        "decrypted_bytes": len(codec.render(doc).encode("utf-8")),
    }
    args.report.write_text(json.dumps(proof, indent=2), encoding="utf-8")
    print(json.dumps(proof, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
