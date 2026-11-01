#!/usr/bin/env python3
"""Reproduce build-47 MM updater evidence from the pinned original XAPK.

Static ZIP/ELF reads only. Never load or execute code from the APK. Output
contains the fixed request recipe and hashes, never decrypted VPN contents.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import re
import struct
from pathlib import Path
import zipfile

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile

XAPK_SHA256 = "8cf714a8545caa92a85bf956af8ab61a8edc3f385914533877d34ef29338b1e1"
BASE_SHA256 = "ef20dcf63aa6a011bc22d927a0f383a884e8924a9df1909ca555121e9e9d4d40"
SO_SHA256 = "b030c0f2b7684becfba0bad7e44b0873206359bb4017ac7e9eb549e377ab90c2"


def checked(data, expected):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("Original build-47 hash mismatch")
    return data


def read_entry(archive, name):
    if archive.namelist().count(name) != 1 or archive.getinfo(name).file_size > 80*1024*1024:
        raise ValueError("Invalid original archive")
    return archive.read(name)


def inspect(original):
    checked(original, XAPK_SHA256)
    with zipfile.ZipFile(io.BytesIO(original)) as z:
        base=checked(read_entry(z,"co.strongteam.marvsudp.apk"),BASE_SHA256)
        split=read_entry(z,"config.armeabi_v7a.apk")
    with zipfile.ZipFile(io.BytesIO(split)) as z:
        native=checked(read_entry(z,"lib/armeabi-v7a/libgojni.so"),SO_SHA256)
    elf=ELFFile(io.BytesIO(native))
    if elf['e_machine'] != 'EM_ARM':raise ValueError("Expected original ARM ELF")

    def read(address,size):
        for segment in elf.iter_segments():
            start=segment['p_vaddr']
            if start<=address and address+size<=start+segment['p_filesz']:
                offset=segment['p_offset']+address-start
                return native[offset:offset+size]
        raise ValueError("Address outside original ELF")

    def literal(add_pc,length):
        instructions=list(Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN).disasm(
            read(add_pc-4,8),add_pc-4))
        load,add=instructions
        match=re.fullmatch(r'(r\d+), \[pc, #(0x[0-9a-f]+)\]',load.op_str)
        if load.mnemonic!='ldr' or not match or add.mnemonic!='add' or add.op_str!=f'{match[1]}, pc, {match[1]}':
            raise ValueError("Unexpected original PC-relative load")
        delta=struct.unpack('<I',read(load.address+8+int(match[2],16),4))[0]
        address=(add_pc+8+delta)&0xffffffff
        return address,read(address,length)

    recipe={}
    for name,pc,length,expected in (
        ('method',0xfd72f0,4,b'POST'),
        ('url',0xfd7304,35,b'https://strongteam.co/api/mmtunnel/'),
        ('formKey',0xfd71fc,4,b'hash'),
        ('formValue',0xfd71dc,14,b'xsandokUpdatex'),
        ('header',0xfd734c,12,b'Content-Type'),
        ('contentType',0xfd7394,33,b'application/x-www-form-urlencoded'),
    ):
        address,value=literal(pc,length)
        if value!=expected:raise ValueError("Original updater recipe mismatch")
        recipe[name]={'address':hex(address),'value':value.decode()}
    # Exact source constants are verified by fingerprints, not emitted.
    format_keys=[]
    for pc,length,expected in (
        (0xfd2ef0,32,'iOi/hqT/TocUv0UbDImfWPGR1mfSdzzX'),
        (0xfd3bfc,21,'NewDecryptLibPassword'),
    ):
        address,value=literal(pc,length)
        if value!=expected.encode():raise ValueError("Original format key mismatch")
        format_keys.append({'address':hex(address),'bytes':length,'sha256':hashlib.sha256(value).hexdigest()})
    with zipfile.ZipFile(io.BytesIO(base)) as z:
        asset=read_entry(z,'assets/configfile.json')
        icon=read_entry(z,'res/drawable/icon.png')
    return {'package':'co.strongteam.marvsudp','versionName':'v1.10.30.2','versionCode':47,
            'xapkSha256':XAPK_SHA256,'baseSha256':BASE_SHA256,'nativeSha256':SO_SHA256,
            'updaterAddress':'0xfd7154','recipe':recipe,'formatKeys':format_keys,
            'assetSha256':hashlib.sha256(asset).hexdigest(),'iconSha256':hashlib.sha256(icon).hexdigest()}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('xapk',type=Path)
    args=parser.parse_args()
    if not 0<args.xapk.stat().st_size<=80*1024*1024:parser.error('Invalid original size')
    print(json.dumps(inspect(args.xapk.read_bytes()),indent=2))


if __name__=='__main__':main()
