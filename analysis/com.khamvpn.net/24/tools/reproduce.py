#!/usr/bin/env python3
"""Build recipe delegates to preserved common scripts; no vendor execution."""
import subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('Expected private app directory')
    script='probe_kham.py'
    subprocess.run([sys.executable,str(ROOT/'analysis/_intake/thailand-kham-arpro-2026-11-09/tools'/script),sys.argv[1]],check=True)
