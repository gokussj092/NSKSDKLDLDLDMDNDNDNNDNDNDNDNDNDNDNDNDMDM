#!/usr/bin/env python3
"""Per-build recipe for base Litron25; the retained helper cannot fetch Pro."""
import argparse,importlib.util
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args()
    path=ROOT/'analysis/_intake/catnet-play-litron-2026-11-09/tools/acquire_litron.py'
    s=importlib.util.spec_from_file_location('base_litron_acquisition',path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.acquire(a.private,25)
