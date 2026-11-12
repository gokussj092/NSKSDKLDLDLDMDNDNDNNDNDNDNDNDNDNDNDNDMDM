#!/usr/bin/env python3
"""Install APK format constants recovered locally; no network or Android edits."""
import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('private', type=Path)
    a = p.parse_args()
    inv = json.loads((a.private/'unpacked/inventory.json').read_text())
    assert inv['metadata']['baseSha256'] == '172da6fc4405d1cc4b70f69ce48b0f17f1b867c89a01017c991234f58ade229d'
    path = a.private/'unpacked/extracted/com.doriaxvip.tunnel/assets/LICENSE'
    expected = next(e['sha256'] for e in inv['entries'] if e['path']=='assets/LICENSE')
    assert hashlib.sha256(path.read_bytes()).hexdigest() == expected
    constants = json.loads((a.private/'constants.json').read_text())
    assert constants['shift']==4 and constants['source']=='https://raw.githubusercontent.com/nemygoku/genisvpn/refs/heads/main/genis'
    path = ROOT/'decoders/Python/apps/Genis_VPN/codec.py'
    source = path.read_text()
    for name, value in [('CATALOG_PASSWORD', constants['outerPassword'].encode()),
                        ('FIELD_KEY', constants['innerPassword'].encode().ljust(32,b'\0')[:32])]:
        source = re.sub(r'^'+name+r' = .*$', lambda _: name+' = '+repr(value), source, flags=re.M)
    fields=set()
    for name in ('included','included-users','remote'):
        document=json.loads((a.private/(name+'.outer.json')).read_text())
        for section in ('Servers','Usuarios'):
            for row in document.get(section,[]):
                fields.update(k for k,v in row.items() if isinstance(v,str))
    source=re.sub(r'^STRING_FIELDS = .*$',lambda _: 'STRING_FIELDS = frozenset('+repr(tuple(sorted(fields)))+')',source,flags=re.M)
    path.write_text(source)
    print('Installed build76 format constants without external secret files.')


if __name__ == '__main__':
    main()
