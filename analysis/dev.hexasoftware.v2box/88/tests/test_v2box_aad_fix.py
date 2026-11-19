"""Dossier runner: executes the canonical AAD regression tests.

The canonical tests live at tests/test_v2box_aad.py (single source);
this file only re-runs them from the dossier so the evidence folder
stays self-describing. Synthetic fixtures only; no real file, no
network, no secrets.
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))

from tests.test_v2box_aad import V2BoxAadTest  # noqa: E402

if __name__ == "__main__":
    unittest.main()
