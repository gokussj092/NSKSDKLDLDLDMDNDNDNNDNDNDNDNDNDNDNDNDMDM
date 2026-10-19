#!/usr/bin/env python3
"""Compatibility alias to the canonical independent codec in apps/FlexNet_B42."""
from importlib import import_module
import sys

_module = import_module("decoders.Python.apps.FlexNet_B42.flexnet_b42")
if __name__ == "__main__":
    raise SystemExit(_module.main())
sys.modules[__name__] = _module
