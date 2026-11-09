#!/usr/bin/env python3
"""Fixed build159 wrapper for the retained initial acquisition recipe."""
import argparse,importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();path=ROOT/'analysis/_intake/speigo-2026-11-09/tools/acquire.py'
    s=importlib.util.spec_from_file_location('speigo_intake',path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.acquire(a.private,159)
    if json.loads((a.private/'identity.json').read_text())['apkSha256']!='37b2524bb63404e74abbfc52b73308180d141a2a0f32d182e9dfd63ced872826':raise ValueError('UNEXPECTED_BUILD159')
