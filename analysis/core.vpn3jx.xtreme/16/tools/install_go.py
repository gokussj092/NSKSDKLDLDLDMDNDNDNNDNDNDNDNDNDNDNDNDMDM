#!/usr/bin/env python3
"""Install the reviewed official Go compiler into a private research directory."""
import argparse,hashlib,tarfile
from pathlib import Path
from urllib.request import urlopen
VERSION="go1.27.3"
SHA256="65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40"
URL="https://go.dev/dl/"+VERSION+".linux-amd64.tar.gz"
def install(folder):
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=True);folder.chmod(0o700)
    archive=folder/(VERSION+".tar.gz")
    if not archive.is_file():
        digest=hashlib.sha256();size=0
        with urlopen(URL,timeout=45) as source,archive.open("xb") as target:
            while chunk:=source.read(262144):
                size+=len(chunk)
                if size>90*1024*1024:raise ValueError("GO_ARCHIVE_BOUNDS")
                digest.update(chunk);target.write(chunk)
        if digest.hexdigest()!=SHA256:archive.unlink();raise ValueError("GO_CHECKSUM_MISMATCH")
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=SHA256:raise ValueError("GO_CHECKSUM_MISMATCH")
    with tarfile.open(archive) as tar:
        for member in tar:
            parts=Path(member.name).parts
            if not parts or parts[0]!="go" or ".." in parts:raise ValueError("UNSAFE_GO_ARCHIVE")
            if not member.isfile():continue
            if member.size>100*1024*1024:raise ValueError("GO_MEMBER_BOUNDS")
            target=folder.joinpath(*parts)
            if target.exists():continue
            target.parent.mkdir(parents=True,exist_ok=True)
            with tar.extractfile(member) as source,target.open("xb") as output:
                while b:=source.read(262144):output.write(b)
            target.chmod(0o700 if member.mode&0o111 else 0o600)
    return folder/"go/bin/go"
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("folder",type=Path);a=p.parse_args();print(install(a.folder))

