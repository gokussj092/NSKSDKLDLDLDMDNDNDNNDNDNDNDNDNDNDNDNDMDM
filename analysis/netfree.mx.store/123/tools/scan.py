#!/usr/bin/env python3
"""Static metadata scan only; delegates to the preserved common tool."""
import subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('Expected private sample directory')
    subprocess.run([sys.executable,str(ROOT/'analysis/_intake/hmac-auth-audit-2026-11-09'/'tools/audit_hmac_usage.py'),'scan',sys.argv[1]],check=True)
