#!/usr/bin/env python3
"""Fixed worker entry point: credentials arrive exclusively on stdin."""
import sys
from file_decoder import main

if __name__ == "__main__":
    sys.argv.append("--password-stdin")
    raise SystemExit(main())
