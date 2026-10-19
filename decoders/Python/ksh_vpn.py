#!/usr/bin/env python3
"""Compatibility-only launcher for the unchanged independent ksh_vpn codec."""
from __future__ import annotations

from importlib import import_module
from pathlib import Path
import sys

# Direct invocation (python decoders/Python/ksh_vpn.py) has no repository-root
# sys.path entry. Import the original apps module without altering its decoder.
_root = str(Path(__file__).resolve().parents[2])
if _root not in sys.path:
    sys.path.insert(0, _root)
_module = import_module("decoders.Python.apps.KSH_VPN.ksh_vpn")
if __name__ == "__main__":
    raise SystemExit(_module.main())
sys.modules[__name__] = _module
