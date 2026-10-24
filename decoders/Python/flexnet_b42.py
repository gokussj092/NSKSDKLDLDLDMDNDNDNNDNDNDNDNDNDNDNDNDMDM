#!/usr/bin/env python3
"""Compatibility launcher for the FlexNet B42/B46 codec."""
from __future__ import annotations

from importlib import import_module
from pathlib import Path
import sys

# Direct invocation (python decoders/Python/flexnet_b42.py) has no repository-root
# sys.path entry. Import the canonical apps module while preserving the historical import path.
_root = str(Path(__file__).resolve().parents[2])
if _root not in sys.path:
    sys.path.insert(0, _root)
_module = import_module("decoders.Python.apps.FlexNet_B42.flexnet_b42")
if __name__ == "__main__":
    raise SystemExit(_module.main())
sys.modules[__name__] = _module
