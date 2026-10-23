#!/usr/bin/env python3
"""Probe only the fixed CREEB 50.0 updater; no fabricated Play Integrity token.

Default GET. --empty-token-post reproduces the app's token-failure path with
truthful offline diagnostics. A response must pass the catalog reader before
remote support can be enabled. Never print response bodies/configurations.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import uuid
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler,Request,build_opener

URL='https://app.creebnet.com/api/app-update-manifest'
LIMIT=8*1024*1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args):return None


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--empty-token-post',action='store_true')
    p.add_argument('--output',type=Path,help='Optional private response; must not exist')
    a=p.parse_args()
    if a.output and a.output.exists():p.error('Output already exists')
    body=None
    if a.empty_token_post:
        body=json.dumps({'integrityToken':'','nonce':base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip('='),
            'packageName':'com.creebtunnel.vpn','diagnostics':{'eventId':str(uuid.uuid4()),'appVersion':'50.0','appBuild':'50',
            'androidSdk':0,'deviceModel':'SP-DECODE offline analysis','clientStage':'token_request_failed',
            'clientFailure':'token_request_failed'}}).encode()
    request=Request(URL,body,headers={'User-Agent':'CREEB-VPN-Android','Accept':'text/plain, application/json, */*',
                                     'Content-Type':'application/json; charset=utf-8'})
    try:
        try:response=build_opener(NoRedirect()).open(request,timeout=25)
        except HTTPError as error:response=error
        with response:
            data=response.read(LIMIT+1)
            if len(data)>LIMIT:raise ValueError('Response exceeds limit')
            report={'method':'POST' if body is not None else 'GET','status':response.status,
                    'contentType':response.headers.get('Content-Type'),'bytes':len(data),
                    'sha256':hashlib.sha256(data).hexdigest()}
        if a.output:
            fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as out:out.write(data)
        print(json.dumps(report));return 0
    except (OSError,ValueError):
        print(json.dumps({'error':'REMOTE_SOURCE_UNAVAILABLE'}));return 1


if __name__=='__main__':raise SystemExit(main())
