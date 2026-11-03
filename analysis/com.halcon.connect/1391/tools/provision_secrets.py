#!/usr/bin/env python3
"""Prepare the two exact backend variables from the private, verified APK recipe.

Output is a private deployment artifact, NEVER a Git input. Does not change VPS
or an existing env file. Keep values out of shell arguments and chat messages.
"""
import argparse
import json
from pathlib import Path
import re

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('recipe',type=Path)
    p.add_argument('private_output',type=Path)
    a=p.parse_args()
    r=json.loads(a.recipe.read_text())
    values={'SPDECODE_HALCON_REQUEST_SECRET':r['request_secret'],
            'SPDECODE_HALCON_CATALOG_PASSWORD':r['catalog_password']}
    if not re.fullmatch(r'[!-~]{22}',values['SPDECODE_HALCON_REQUEST_SECRET']):raise ValueError('Invalid request secret')
    if not re.fullmatch(r'[!-~]{65}[0-9A-F]{64}',values['SPDECODE_HALCON_CATALOG_PASSWORD']):raise ValueError('Invalid catalog key')
    if any("'" in x for x in values.values()):raise ValueError('Requires reviewed dotenv escaping')
    a.private_output.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with a.private_output.open('x',encoding='utf8') as stream:
        a.private_output.chmod(0o600)
        stream.write('# Private Halcon build1391 backend configuration. Never commit.\n')
        for key,value in values.items():stream.write(key+"='"+value+"'\n")
    print('Prepared two private backend variables; values not displayed.')

if __name__=='__main__':main()
