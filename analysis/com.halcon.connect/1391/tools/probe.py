#!/usr/bin/env python3
"""Replay the observed catalog bootstrap, using a private recipe, without logging secrets.

Only the two fixed catalog hosts observed in build1391 are allowed. Does not
replay VIP, rewards, payment, device access or licensing operations.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_BYTES = 8 * 1024 * 1024

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Redirect not authorized by this recipe')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('recipe', type=Path)
    p.add_argument('private_output', type=Path)
    p.add_argument('--source', choices=['primary', 'backup'], required=True)
    p.add_argument('--authorized-primary', action='store_true',
                   help='Use only AFTER explicit owner authorization; does not replace approval')
    a = p.parse_args()
    if a.source == 'primary' and not a.authorized_primary:
        p.error('Authenticated primary replay is blocked pending explicit owner approval')
    r = json.loads(a.recipe.read_text())
    url = r[a.source]
    u = urllib.parse.urlsplit(url)
    if u.scheme != 'https' or u.username or u.password or u.hostname not in {
        'panel-apk.viofull.com', 'raw.githubusercontent.com'
    }:
        raise ValueError('Unrecognized catalog destination')
    data = None
    headers = {'User-Agent': 'Dalvik/2.1.0'}
    if a.source == 'primary':
        timestamp = str(int(time.time()))
        signature = hashlib.sha256((timestamp + r['request_secret']).encode()).hexdigest()
        data = urllib.parse.urlencode({'hash': signature, 'timestamp': timestamp}).encode()
        headers.update({'X-Auth-Hash': signature, 'X-Timestamp': timestamp,
                        'X-App-ID': 'HalconRNet_2026',
                        'Content-Type': 'application/x-www-form-urlencoded'})
    req = urllib.request.Request(url, data=data, headers=headers)
    result = {'source': a.source, 'method': req.get_method(), 'observed_at': int(time.time())}
    body = b''
    try:
        response = urllib.request.build_opener(NoRedirect()).open(req, timeout=30)
    except urllib.error.HTTPError as e:
        response = e
    except (OSError, ValueError) as e:
        result.update(status='NETWORK_UNAVAILABLE', error_type=type(e).__name__)
        response = None
    if response is not None:
        with response:
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise ValueError('Catalog body exceeds bound')
            result.update(http=response.code, content_type=response.headers.get_content_type(),
                          bytes=len(body), sha256=hashlib.sha256(body).hexdigest(),
                          html=body.lstrip().lower().startswith((b'<html', b'<!doctype')))
    a.private_output.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, content in [(a.source + '.response', body),
                          (a.source + '.summary.json', (json.dumps(result, indent=2) + '\n').encode())]:
        path = a.private_output / name
        path.touch(mode=0o600, exist_ok=True)
        path.chmod(0o600)
        path.write_bytes(content)
    print(json.dumps(result))
    return 0 if result.get('http') == 200 and body and not result.get('html') else 3

if __name__ == '__main__':
    raise SystemExit(main())
