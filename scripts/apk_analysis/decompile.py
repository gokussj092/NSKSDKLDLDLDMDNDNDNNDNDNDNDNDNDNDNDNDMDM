#!/usr/bin/env python3
"""Run checksum-pinned JADX 1.5.6 without executing upstream shell scripts."""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile
from urllib.request import urlopen
import zipfile

VERSION='1.5.6'
URL=f'https://github.com/skylot/jadx/releases/download/v{VERSION}/jadx-{VERSION}.zip'
ZIP_SHA256='545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974'
JAR_SHA256='fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b'
CACHE=Path(__file__).resolve().parent/'cache'


def verified_jar(path: Path) -> Path:
    if hashlib.sha256(path.read_bytes()).hexdigest()!=JAR_SHA256:
        raise ValueError('JADX JAR checksum mismatch')
    return path


def install() -> Path:
    CACHE.mkdir(parents=True,exist_ok=True)
    target=CACHE/f'jadx-{VERSION}-all.jar'
    if target.exists():return verified_jar(target)
    with tempfile.TemporaryDirectory(prefix='spdecode-jadx-') as tmp:
        archive=Path(tmp)/'jadx.zip';digest=hashlib.sha256();size=0
        with urlopen(URL,timeout=30) as response,archive.open('wb') as stream:
            while chunk:=response.read(1024*1024):
                size+=len(chunk)
                if size>80*1024*1024:raise ValueError('JADX archive exceeds limit')
                digest.update(chunk);stream.write(chunk)
        if digest.hexdigest()!=ZIP_SHA256:raise ValueError('JADX archive checksum mismatch')
        with zipfile.ZipFile(archive) as z:
            jar=z.read(f'lib/jadx-{VERSION}-all.jar')
        if hashlib.sha256(jar).hexdigest()!=JAR_SHA256:raise ValueError('JADX JAR checksum mismatch')
        target.write_bytes(jar)
    return target


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('input',type=Path,nargs='?')
    p.add_argument('output',type=Path,nargs='?')
    p.add_argument('--jar',type=Path,help='Existing JAR; checksum is still checked')
    p.add_argument('--install',action='store_true',help='Download the official pinned release if absent')
    a=p.parse_args()
    jar=verified_jar(a.jar) if a.jar else (install() if a.install else verified_jar(CACHE/f'jadx-{VERSION}-all.jar'))
    if a.input is None and a.output is None and a.install:return
    if a.input is None or a.output is None:p.error('Provide both input and output')
    source=a.input.resolve();output=a.output.resolve()
    if source==output or source in output.parents or output in source.parents:
        p.error('Input and output must be separate and not nested')
    output.mkdir(parents=True,exist_ok=True,mode=0o700)
    log=output/'jadx.log'
    with log.open('wb') as stream:
        result=subprocess.run(['java','-Xmx2200m','-cp',str(jar.resolve()),'jadx.cli.JadxCLI',
            '--no-res','--decompilation-mode','simple','-j','4','-d',str(output),str(source)],
            stdout=stream,stderr=subprocess.STDOUT,timeout=300)
    log.chmod(0o600)
    print(f'JADX exit={result.returncode}; inspect jadx.log and generated sources. Partial decompilation is not proof of a valid decoder.')
    raise SystemExit(result.returncode)

if __name__=='__main__':main()
