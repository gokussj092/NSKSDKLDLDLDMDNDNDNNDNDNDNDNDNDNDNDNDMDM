#!/usr/bin/env python3
"""Recover build76 catalog format locally; private values and JSON stay private."""
import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.request import Request, build_opener, HTTPRedirectHandler

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data)
    path.chmod(0o600)


def outer(password, data):
    raw = base64.b64decode(data)
    if raw[:8] != b'WakkoDev':
        raise ValueError('Unexpected outer header')
    material = last = b''
    while len(material) < 48:
        last = hashlib.md5(last + password.encode() + raw[8:16]).digest()
        material += last
    return unpad(AES.new(material[:32], AES.MODE_CBC, material[32:48]).decrypt(raw[16:]), 16)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('private', type=Path)
    p.add_argument('--download', action='store_true')
    a = p.parse_args()
    root = a.private
    inv = json.loads((root/'unpacked/inventory.json').read_text())
    if inv['metadata']['baseSha256'] != '172da6fc4405d1cc4b70f69ce48b0f17f1b867c89a01017c991234f58ade229d':
        raise ValueError('Unexpected base APK')
    assets = root/'unpacked/extracted/com.doriaxvip.tunnel/assets'
    props = {}
    for line in (assets/'LICENSE').read_text(encoding='latin1').splitlines():
        if not line or line.lstrip().startswith(('#', '!')):
            continue
        key, sep, value = line.partition('=')
        if sep:
            props[key.strip()] = value.strip()
    constants = {'outerPassword': props['NIGHT_MODE'], 'innerPassword': props['SSH_UDP'], 'shift': int(props['INPUT'])}
    source = (root/'jadx1/sources/defpackage/BF.java').read_text()
    text = source[source.index('public String toString()'):]
    text = text[:text.index('L5:')]
    registers = {'r20':121, 'r22':4, 'r23':73, 'r25':12, 'r26':204, 'r2':176}
    pairs = re.findall(r'\(byte\)\s*\(?\(?(-?\d+)\)?\s*\^\s*(r\d+)\)?', text)
    url = bytes((int(v) ^ registers[r]) & 255 for v, r in pairs).decode()
    if not url.startswith('https://'):
        raise ValueError('Unexpected updater URL')
    constants['source'] = url
    write(root/'constants.json', (json.dumps(constants, indent=2)+'\n').encode())
    results = {}
    for name, file in [('included', 'config.png'), ('included-users', 'usr.png')]:
        data = (assets/'flags'/file).read_bytes()
        plain = outer(constants['outerPassword'], data)
        doc = json.loads(plain)
        write(root/(name+'.outer.json'), plain)
        results[name] = {'inputBytes':len(data), 'inputSha256':hashlib.sha256(data).hexdigest(),
                         'version':doc.get('Version'), 'keys':list(doc),
                         'sections':{k:len(v) for k,v in doc.items() if isinstance(v, list)}}
    if a.download:
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                raise ValueError('Redirect denied')
        with build_opener(NoRedirect()).open(Request(url, headers={'User-Agent':'Dalvik/2.1.0 (Linux; U; Android 14)', 'Accept-Encoding':'identity'}), timeout=30) as response:
            data = response.read(8*1024*1024+1)
            status = response.status
            content_type = response.headers.get('Content-Type')
        if len(data)>8*1024*1024:
            raise ValueError('Oversized response')
        write(root/'remote.enc', data)
        plain = outer(constants['outerPassword'], data)
        doc = json.loads(plain)
        write(root/'remote.outer.json', plain)
        results['remote'] = {'httpStatus':status, 'contentType':content_type,'inputBytes':len(data),
                             'inputSha256':hashlib.sha256(data).hexdigest(),'version':doc.get('Version'),
                             'keys':list(doc),'sections':{k:len(v) for k,v in doc.items() if isinstance(v,list)}}
    write(root/'recovery.json', (json.dumps(results,indent=2)+'\n').encode())
    print(json.dumps(results,indent=2))


if __name__ == '__main__':
    main()
