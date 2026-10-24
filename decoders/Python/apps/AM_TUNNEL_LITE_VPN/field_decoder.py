#!/usr/bin/env python3
"""AM build 63 PUtils fields only. The protected outer catalog is not supported."""
from __future__ import annotations
import argparse,json,re,sys
from pathlib import Path

MAX_BYTES=1024*1024
# xorWithKey at 0x1466d4 in the exact libputils.so recorded in manifest.json.
FIELD_KEY=b'4%PdXch>fkP]'


class DecodeError(ValueError):
    pass


def decode_modified_utf8(raw: bytes) -> str:
    """JNI NewStringUTF encoding: UTF-16 units, C0 80 for NUL, surrogate pairs."""
    units=bytearray();i=0
    while i<len(raw):
        a=raw[i];i+=1
        if 0<a<128:value=a
        elif 0xc0<=a<=0xdf and i<len(raw):
            b=raw[i];i+=1
            if b&0xc0!=0x80:raise DecodeError('Campo UTF modificado inválido.')
            value=((a&31)<<6)|(b&63)
            if value<128 and (a,b)!=(0xc0,0x80):raise DecodeError('Campo UTF modificado inválido.')
        elif 0xe0<=a<=0xef and i+1<len(raw):
            b,c=raw[i:i+2];i+=2
            if b&0xc0!=0x80 or c&0xc0!=0x80:raise DecodeError('Campo UTF modificado inválido.')
            value=((a&15)<<12)|((b&63)<<6)|(c&63)
            if value<0x800:raise DecodeError('Campo UTF modificado inválido.')
        else:raise DecodeError('Campo UTF modificado inválido.')
        units.extend(value.to_bytes(2,'big'))
    try:return units.decode('utf-16-be')
    except UnicodeError:raise DecodeError('Campo UTF modificado inválido.') from None


def decode_field(text: str) -> str:
    if not isinstance(text,str) or not text or len(text)>MAX_BYTES or len(text)%2 or not re.fullmatch('[0-9a-fA-F]+',text):
        raise DecodeError('Campo hexadecimal inválido.')
    raw=bytes.fromhex(text)
    return decode_modified_utf8(bytes(value^FIELD_KEY[i%len(FIELD_KEY)] for i,value in enumerate(raw)))


def run(data: bytes) -> str:
    if not isinstance(data,bytes) or not data or len(data)>MAX_BYTES:raise DecodeError('Entrada vacía o excesiva.')
    try:value=decode_field(data.decode('ascii').strip())
    except (UnicodeError,ValueError):raise DecodeError('Campo AM incompatible.') from None
    return json.dumps({'field':value},ensure_ascii=False,allow_nan=False,indent=2)+'\n'


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('field_file',nargs='?',type=Path);a=p.parse_args()
    try:
        if a.field_file:
            with a.field_file.open('rb') as stream:data=stream.read(MAX_BYTES+1)
        else:data=sys.stdin.buffer.read(MAX_BYTES+1)
        sys.stdout.write(run(data));return 0
    except (OSError,ValueError):
        print('No se pudo leer el campo AM. Este auxiliar no abre catálogos.',file=sys.stderr);return 1

if __name__=='__main__':raise SystemExit(main())
