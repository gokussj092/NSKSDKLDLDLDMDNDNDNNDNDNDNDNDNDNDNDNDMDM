#!/usr/bin/env python3
"""Revalidate the TunelGuard 17.7 re-analysis: live fetch from the new URL,
bundled-seed decode, and a proof JSON with counts/hashes only.

No decrypted catalog, credential, or server address is written anywhere.
The bundled-seed envelope string is read from the batch-15 analyst script
(it is a fixed build constant, not a credential).
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.request import Request, build_opener

ROOT = Path(__file__).resolve().parents[4]
OVERLAY = Path(__file__).resolve().parents[5] / "overlay"
BATCH = Path.home() / "workspace/batch15-work/tunelguard-vpn/tunelguard.py"


def load_codec():
    """Load the staged codec from a temp repo-layout tree (see the
    dossier test for why: the staged codec needs its unchanged repo
    siblings HTTP_FenixVPN/codec.py and field_names.json). Siblings are
    taken from the repo tree when present, else from the read-only
    overlay (stage-tree runs)."""
    import importlib.util
    import tempfile
    overlay_apps = OVERLAY / "decoders/Python/apps"
    repo_apps = ROOT / "decoders/Python/apps"

    def sibling(app, name):
        for base in (repo_apps, overlay_apps):
            path = base / app / name
            if path.is_file():
                return path
        raise FileNotFoundError(str(base / app / name))

    tmp = Path(tempfile.mkdtemp(prefix="tg177-reval-"))
    tg = tmp / "apps" / "TunelGuard_VPN"
    hx = tmp / "apps" / "HTTP_FenixVPN"
    tg.mkdir(parents=True)
    hx.mkdir(parents=True)
    for src, dst in (
            (ROOT / "decoders/Python/apps/TunelGuard_VPN/codec.py",
             tg / "codec.py"),
            (sibling("TunelGuard_VPN", "field_names.json"),
             tg / "field_names.json"),
            (sibling("HTTP_FenixVPN", "codec.py"), hx / "codec.py"),
            (sibling("HTTP_FenixVPN", "field_names.json"),
             hx / "field_names.json")):
        dst.write_bytes(src.read_bytes())
    for pkg in (tmp / "apps", tg, hx):
        (pkg / "__init__.py").write_text("", encoding="utf-8")
    sys.path.insert(0, str(tmp / "apps"))
    spec = importlib.util.spec_from_file_location("tg177_codec", tg / "codec.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


codec = load_codec()


def bundled_envelope() -> str:
    text = BATCH.read_text(encoding="utf-8")
    match = re.search(r"BUNDLED_ENVELOPE = \(\s*((?:'[^']*'\s*)+)\)", text)
    parts = re.findall(r"'([^']*)'", match.group(1))
    return "".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    proof: dict = {"app": "TunelGuard VPN", "version_code": 177}
    with build_opener().open(
            Request("https://raw.githubusercontent.com/guruzgh-ed/edd/refs/heads/main/tg.js"),
            timeout=30) as resp:
        raw = resp.read(codec.MAX_BYTES + 1)
    proof["live"] = {
        "status": resp.status, "envelope_bytes": len(raw),
        "envelope_sha256": hashlib.sha256(raw).hexdigest(),
    }
    doc = codec.decode_catalog(raw)
    proof["catalog"] = {
        "version": doc.get("version"),
        "config_revision": doc.get("config_revision"),
        "servers": len(doc.get("Servers", [])),
        "tweaks": len(doc.get("Tweaks", [])),
        "tgcr1_left": str(doc).count("TGCR1."),
    }
    seed = codec.decode_catalog(bundled_envelope().encode("utf-8"))
    proof["bundled_seed"] = {
        "version": seed.get("version"),
        "servers": len(seed.get("Servers", [])),
    }
    args.report.write_text(json.dumps(proof, indent=2), encoding="utf-8")
    print(json.dumps(proof, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
