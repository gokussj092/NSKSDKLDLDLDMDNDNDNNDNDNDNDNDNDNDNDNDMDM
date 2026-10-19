#!/usr/bin/env python3
"""Compatibility alias to the canonical independent codec in apps/VPN_PLUS_PERU."""
from importlib import import_module
import sys

_module = import_module("decoders.Python.apps.VPN_PLUS_PERU.vpn_plus_peru")
if __name__ == "__main__":
    raise SystemExit(_module.main())
sys.modules[__name__] = _module
