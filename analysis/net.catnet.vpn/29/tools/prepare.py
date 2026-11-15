#!/usr/bin/env python3
"""Per-build recipe for the retained bounded Play APKS identity helper."""
import argparse,importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
def main():
    p=argparse.ArgumentParser();p.add_argument('apks',type=Path);p.add_argument('private',type=Path);a=p.parse_args()
    path=ROOT/'analysis/_intake/catnet-play-litron-2026-11-09/tools/prepare_catnet.py'
    s=importlib.util.spec_from_file_location('play_identity',path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.prepare(a.apks,a.private)
    d=json.loads((a.private/'identity.json').read_text())
    if d['versionCode']!=29 or d['apkSha256']!='870a4e41f11a1cc3987c2f6b098ffa6adb1f69877820065ab7d938b394b39676':raise ValueError('UNEXPECTED_PLAY_BUILD')
if __name__=='__main__':main()
