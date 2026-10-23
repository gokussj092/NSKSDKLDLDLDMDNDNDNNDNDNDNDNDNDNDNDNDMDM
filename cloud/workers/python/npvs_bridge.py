#!/usr/bin/env python3
"""Fixed NPVS entry point; credentials use stdin only, never argv or env."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from decoders.Python.npvs import main

if __name__ == "__main__":
    sys.argv.append("--credentials-stdin")
    raise SystemExit(main())
