#!/usr/bin/env python3
"""Compatibility alias to the canonical independent codec in apps/Neutro_VPN."""
from importlib import import_module
import sys

_module = import_module("decoders.Python.apps.Neutro_VPN.neutro_vpn")
if __name__ == "__main__":
    raise SystemExit(_module.main())
sys.modules[__name__] = _module
