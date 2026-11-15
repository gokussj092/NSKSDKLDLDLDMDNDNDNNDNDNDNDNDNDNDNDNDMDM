#!/usr/bin/env python3
"""Per-build wrapper for the retained owner-APKS static intake recipe."""
import argparse,importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('apks',type=Path);p.add_argument('private',type=Path);a=p.parse_args()
    path=ROOT/'analysis/_intake/litron-pro-2026-11-09/tools/prepare.py'
    s=importlib.util.spec_from_file_location('pro_intake',path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.prepare(a.apks,a.private)
    d=json.loads((a.private/'identity.json').read_text())
    if d['versionCode']!=11 or d['apkSha256']!='83425c38c72a04e0875374cc50706e3eb5ff518104e7edaa1e5f753e675484e1':raise ValueError('UNEXPECTED_PRO_BUILD')
