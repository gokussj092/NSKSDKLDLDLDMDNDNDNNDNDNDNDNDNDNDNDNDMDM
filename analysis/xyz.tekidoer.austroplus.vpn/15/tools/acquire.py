#!/usr/bin/env python3
"""Fixed build acquisition through the retained shared research helper."""
import argparse,importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args()
path=ROOT/'analysis/_intake/austro-cat-2026-11-09/tools/acquire.py'
s=importlib.util.spec_from_file_location('acquire_current',path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
print(json.dumps(m.acquire('austro',a.private,15)))
