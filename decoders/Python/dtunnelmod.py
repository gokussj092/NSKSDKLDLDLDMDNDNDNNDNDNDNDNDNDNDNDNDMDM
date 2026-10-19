#!/usr/bin/env python3
"""Compatibility alias to the canonical independent codec in apps/DTunnel_Mod."""
from importlib import import_module
import sys

_module = import_module("decoders.Python.apps.DTunnel_Mod.dtunnelmod")
if __name__ == "__main__":
    raise SystemExit(_module.main())
sys.modules[__name__] = _module
