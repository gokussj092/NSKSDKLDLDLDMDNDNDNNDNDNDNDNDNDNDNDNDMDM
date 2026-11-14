#!/usr/bin/env python3
"""VC VPN .tgv file bridge.

VC_VPN_archivos.py takes --file/--stdin, not a positional path, so the
worker cannot invoke it directly. It also imports its sibling VC_VPN
module, so it must be loaded the way the engine runs scripts: from its
own file, with its folder on sys.path. This bridge reads the file given
on argv, decodes it through the script's own decode() API, and prints
the resulting JSON. Used by engine.py only when the input starts with
STGCM2.VC./STGCM3.VC. (see _is_vc_tgv); anything else keeps the
TunelGuard route. The decoder itself is not modified.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def fail(code: str) -> int:
    sys.stdout.write(json.dumps({"workerError": code}))
    return 3


def _load_decoder():
    folder = ROOT / "decoders" / "Python" / "apps" / "VC_VPN"
    sys.path.insert(0, str(folder))
    spec = importlib.util.spec_from_file_location(
        "VC_VPN_archivos", folder / "VC_VPN_archivos.py"
    )
    if spec is None or spec.loader is None:
        raise ImportError("VC_VPN_archivos")
    module = importlib.util.module_from_spec(spec)
    sys.modules["VC_VPN_archivos"] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    try:
        raw = Path(sys.argv[1]).read_bytes()
    except OSError:
        return fail("DECODE_FAILED")
    try:
        decoder = _load_decoder()
    except Exception:
        return fail("ENGINE_UNAVAILABLE")
    try:
        result = decoder.decode(raw)
    except Exception:
        return fail("DECODE_FAILED")
    if not isinstance(result, dict):
        return fail("DECODE_FAILED")
    sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
