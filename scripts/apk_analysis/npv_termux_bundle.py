#!/usr/bin/env python3
"""Build a deterministic standalone NPV bundle from canonical tracked sources."""
import argparse
from pathlib import Path
import zipfile

ROOT=Path(__file__).resolve().parents[2]
FILES={"npv_termux.py":"scripts/apk_analysis/npv_termux.py",
       "npv_recipient_capture.js":"scripts/apk_analysis/npv_recipient_capture.js",
       "npvs.py":"decoders/Python/npvs.py",
       "npvs_identity.py":"decoders/Python/npvs_identity.py",
       "README.md":"docs/NPV_RECIPIENT_TERMUX.md"}


def build(output):
    with zipfile.ZipFile(output,"x",compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for name,source in sorted(FILES.items()):
            info=zipfile.ZipInfo(name,(2026,10,25,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=(0o100600 << 16);archive.writestr(info,(ROOT/source).read_bytes())


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("output",type=Path)
    build(parser.parse_args().output)
