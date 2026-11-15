#!/usr/bin/env python3
"""Retain the exact raw-resource extraction originally performed inline."""
import argparse,hashlib,zipfile
from pathlib import Path
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args();d=a.private
    apk=d/'unpacked/apks/noob.arpro.vpn.apk'
    assert hashlib.sha256(apk.read_bytes()).hexdigest()=='b159049c522923ac83e788bdc3b94df9dec034a7da44c90f14ff86b8db9ad1ad'
    with zipfile.ZipFile(apk) as z:
        for name in ['res/raw/noobdev.js','res/raw/q.json']:
            f=d/Path(name).name;f.touch(mode=0o600,exist_ok=True);f.chmod(0o600);f.write_bytes(z.read(name))
if __name__=='__main__':main()
