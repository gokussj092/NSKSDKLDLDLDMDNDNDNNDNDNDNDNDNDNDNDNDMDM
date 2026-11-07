#!/usr/bin/env python3
"""P05 offline APK/APKS structural gate. NOT a signature or malware verifier.

No researcher tools or user APK code are executed. Bounded output codes only.
Nested APKS require quota-limited scratch before production (A4/A5).
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import sys
import tempfile
import zipfile

MAX_INPUT=300*1024*1024
MAX_ENTRY=300*1024*1024
MAX_EXPANDED=600*1024*1024
MAX_ENTRIES=20000
MAX_RATIO=400
MAX_APKS=200
MAX_MANIFEST=8*1024*1024
DEX=re.compile(r"classes(?:[1-9][0-9]*)?\.dex\Z")


class GateError(ValueError):
    pass


def safe_name(name: str) -> None:
    if (not name or len(name)>512 or "\\" in name
        or any(ord(c)<32 or ord(c)==127 for c in name)
        or name.startswith(("/", "./"))
        or re.match(r"^[A-Za-z]:",name)
        or any(part in ("", ".", "..") for part in name.strip("/").split("/"))):
        raise GateError("ZIP_ENTRY_UNSAFE")


def scan(z: zipfile.ZipFile, *, apk: bool) -> dict:
    infos=z.infolist()
    if not infos or len(infos)>MAX_ENTRIES:
        raise GateError("ZIP_ENTRY_COUNT")
    seen=set()
    total=0
    dex=0
    manifest=None
    for item in infos:
        safe_name(item.filename)
        key=item.filename.rstrip("/")
        if key in seen:
            raise GateError("ZIP_DUPLICATE")
        seen.add(key)
        mode=(item.external_attr>>16)&0xffff
        if stat.S_ISLNK(mode) or (mode and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))):
            raise GateError("ZIP_UNSAFE_TYPE")
        if item.flag_bits & 1:
            raise GateError("ZIP_ENCRYPTED")
        if item.file_size>MAX_ENTRY or item.file_size<0:
            raise GateError("ZIP_ENTRY_SIZE")
        if item.file_size>MAX_RATIO*max(1,item.compress_size):
            raise GateError("ZIP_RATIO")
        total+=item.file_size
        if total>MAX_EXPANDED:
            raise GateError("ZIP_EXPANDED_SIZE")
        if apk and not item.is_dir():
            if item.filename=="AndroidManifest.xml":
                manifest=item
            if DEX.fullmatch(item.filename):
                dex+=1
    if apk:
        if manifest is None or not 8<=manifest.file_size<=MAX_MANIFEST:
            raise GateError("APK_MANIFEST")
        try:
            with z.open(manifest) as stream:
                header=stream.read(8)
        except (OSError,RuntimeError,EOFError,zipfile.BadZipFile):
            raise GateError("APK_MANIFEST") from None
        # Compiled Android binary XML, not a plain XML file renamed .apk.
        if header[:4]!=b"\x03\x00\x08\x00":
            raise GateError("APK_MANIFEST")
    return {"entries":len(infos),"expanded_bytes":total,"dex_count":dex}


def nested_apk(parent:zipfile.ZipFile, member:zipfile.ZipInfo) -> dict:
    # Spool with bounded memory, and reject size/CRC mismatches.
    with tempfile.SpooledTemporaryFile(mode="w+b",max_size=8*1024*1024) as tmp:
        count=0
        try:
            with parent.open(member) as file:
                while chunk:=file.read(1024*1024):
                    count+=len(chunk)
                    if count>MAX_ENTRY or count>member.file_size:
                        raise GateError("APKS_MEMBER_SIZE")
                    tmp.write(chunk)
        except (OSError,EOFError,RuntimeError,zipfile.BadZipFile):
            raise GateError("APKS_MEMBER_CORRUPT") from None
        if count!=member.file_size:
            raise GateError("APKS_MEMBER_CORRUPT")
        tmp.seek(0)
        try:
            with zipfile.ZipFile(tmp) as z:
                return scan(z,apk=True)
        except (zipfile.BadZipFile,zipfile.LargeZipFile):
            raise GateError("APKS_NESTED_INVALID") from None


def inspect_input(path:Path) -> dict:
    path=Path(path)
    if path.is_symlink() or not path.is_file():
        raise GateError("INPUT_NOT_REGULAR")
    if path.suffix.lower() not in (".apk",".apks"):
        raise GateError("INPUT_EXTENSION")
    length=path.stat().st_size
    if not 1<=length<=MAX_INPUT:
        raise GateError("INPUT_SIZE")
    sha=hashlib.sha256()
    with path.open("rb") as inp:
        while data:=inp.read(1024*1024):
            sha.update(data)
    apk=path.suffix.lower()==".apk"
    try:
        with zipfile.ZipFile(path) as outer:
            stats=scan(outer,apk=apk)
            if apk:
                return {"format":"APK","input_sha256":sha.hexdigest(),"input_bytes":length,
                        "apk_count":1,"members":stats["entries"],"dex_count":stats["dex_count"]}
            members=[info for info in outer.infolist()
                     if info.filename.endswith(".apk") and not info.is_dir()]
            if not members or len(members)>MAX_APKS:
                raise GateError("APKS_COUNT")
            if any("/" in item.filename for item in members):
                raise GateError("APKS_UNSUPPORTED_LAYOUT")
            if len(members)>1 and sum(i.filename=="base.apk" for i in members)!=1:
                raise GateError("APKS_NO_BASE")
            expanded=stats["expanded_bytes"]
            entries=stats["entries"]
            dex=0
            for member in members:
                nested=nested_apk(outer,member)
                expanded+=nested["expanded_bytes"]
                entries+=nested["entries"]
                dex+=nested["dex_count"]
                if expanded>MAX_EXPANDED or entries>MAX_ENTRIES:
                    raise GateError("APKS_NESTED_LIMIT")
            return {"format":"APKS","input_sha256":sha.hexdigest(),"input_bytes":length,
                    "apk_count":len(members),"members":entries,"dex_count":dex}
    except (zipfile.BadZipFile,zipfile.LargeZipFile):
        raise GateError("ZIP_INVALID") from None


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source",type=Path)
    args=parser.parse_args()
    try:
        print(json.dumps({"status":"ACCEPTED",**inspect_input(args.source)},sort_keys=True))
        return 0
    except GateError as e:
        print(json.dumps({"status":"REJECTED","code":str(e)},sort_keys=True))
        return 2


if __name__=="__main__":
    sys.exit(main())
