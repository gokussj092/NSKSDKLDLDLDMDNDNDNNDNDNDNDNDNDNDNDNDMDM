#!/usr/bin/env python3
"""Fixed CREEB50 updater: original GET preflight, then an explicit original POST.

A fresh original request may be supplied in a private file. No token is minted,
modified, renewed or replayed automatically. Bodies and credentials stay private.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys
import uuid
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoders.Python.apps.CREEB_VPN import codec

URL = 'https://app.creebnet.com/api/app-update-manifest'
LIMIT = 8 * 1024 * 1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):return None


def exchange(body=None):
    headers = {'User-Agent': 'CREEB-VPN-Android',
               'Accept': 'application/json' if body is None else 'text/plain, application/json, */*'}
    if body is not None:headers['Content-Type'] = 'application/json; charset=utf-8'
    request = Request(URL, body, headers=headers)
    try:response = build_opener(NoRedirect()).open(request, timeout=15 if body is None else 60)
    except HTTPError as error:response = error
    with response:
        data = response.read(LIMIT + 1)
        if len(data) > LIMIT:raise ValueError('Response exceeds limit')
        report = {'method': request.get_method(), 'status': response.status,
                  'contentType': response.headers.get('Content-Type'), 'bytes': len(data),
                  'sha256': hashlib.sha256(data).hexdigest()}
    return data, report


def preflight(data, cached=None):
    """Mirror mv0: valid digest + existing raw cache precede server's flag."""
    try:document = codec._json(data.decode('utf-8'))
    except (ValueError, UnicodeError):return 'unavailable'
    if not isinstance(document, dict) or not isinstance(document.get('digest'), str):return 'unavailable'
    if not re.fullmatch(r'[0-9a-fA-F]{64}', document['digest']):return 'unavailable'
    if not cached:return 'integrity-required'
    if hashlib.sha256(cached).hexdigest().lower() == document['digest'].lower():return 'up-to-date'
    if document.get('bypassActive') is True:return 'server-authorized-tokenless'
    return 'integrity-required'


def original_request(path, state):
    if path.stat().st_mode & 0o077:raise ValueError('Request file must be private mode0600')
    with path.open('rb') as stream:raw = stream.read(128 * 1024 + 1)
    if not 0 < len(raw) <= 128 * 1024:raise ValueError('Request size')
    document = codec._json(raw.decode('utf-8'))
    if not isinstance(document, dict) or set(document) != {'integrityToken','nonce','packageName','diagnostics'}:
        raise ValueError('Original request schema')
    if document['packageName'] != 'com.creebtunnel.vpn':raise ValueError('Wrong package')
    token, nonce, diagnostics = document['integrityToken'], document['nonce'], document['diagnostics']
    if not isinstance(token, str) or len(token.encode()) > 64 * 1024:raise ValueError('Invalid token field')
    if not isinstance(nonce, str) or not re.fullmatch(r'[A-Za-z0-9_-]{22}', nonce):raise ValueError('Invalid original nonce')
    if len(base64.urlsafe_b64decode(nonce + '==')) != 16:raise ValueError('Invalid nonce length')
    required = {'eventId','appVersion','appBuild','androidSdk','deviceModel','clientStage'}
    if not isinstance(diagnostics, dict) or not required <= diagnostics.keys() or diagnostics.keys() - required - {'clientFailure','integrityErrorCode'}:
        raise ValueError('Original diagnostics schema')
    if not isinstance(diagnostics['eventId'], str):raise ValueError('Original event ID required')
    uuid.UUID(diagnostics['eventId'])
    if diagnostics['appVersion'] != '50.0' or diagnostics['appBuild'] != '50':raise ValueError('Wrong build')
    if type(diagnostics['androidSdk']) is not int or not 1 <= diagnostics['androidSdk'] <= 100:raise ValueError('Original Android SDK required')
    if not isinstance(diagnostics['deviceModel'], str) or not 0 < len(diagnostics['deviceModel']) <= 512:raise ValueError('Original model required')
    if diagnostics['clientStage'] not in ('request_sent','token_request_failed'):raise ValueError('Original stage')
    if 'clientFailure' in diagnostics and (diagnostics['clientStage'] != 'token_request_failed' or diagnostics['clientFailure'] not in ('token_request_failed','token_empty')):
        raise ValueError('Original failure diagnostics required')
    if 'integrityErrorCode' in diagnostics and type(diagnostics['integrityErrorCode']) is not int:
        raise ValueError('Original Integrity error code required')
    if not token and state != 'server-authorized-tokenless' and diagnostics.get('clientFailure') not in ('token_request_failed','token_empty'):
        raise ValueError('Token missing without original failure or server authorization')
    return raw


def offline_failure_request():
    # Explicitly offline: do not pretend this is a successful Android attestation.
    return json.dumps({'integrityToken':'', 'nonce':base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip('='),
        'packageName':'com.creebtunnel.vpn', 'diagnostics':{'eventId':str(uuid.uuid4()),
        'appVersion':'50.0','appBuild':'50','androidSdk':0,'deviceModel':'SP-DECODE offline analysis',
        'clientStage':'token_request_failed','clientFailure':'token_request_failed'}}, separators=(',',':')).encode()


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:stream.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--empty-token-post', action='store_true', help='Explicit truthful offline token-failure diagnostic, not a valid attestation')
    group.add_argument('--request-file', type=Path, help='Fresh original request JSON, mode0600; token and nonce stay unchanged')
    parser.add_argument('--cached-catalog', type=Path, help='Exact current raw cache for original digest comparison')
    parser.add_argument('--output', type=Path, help='New private final response file')
    parser.add_argument('--catalog-output', type=Path, help='New complete decoded JSON only after a real successful POST')
    args = parser.parse_args()
    if any(p and p.exists() for p in (args.output,args.catalog_output)):parser.error('Output already exists')
    report = {}
    try:
        cached = None
        if args.cached_catalog:
            with args.cached_catalog.open('rb') as stream:cached = stream.read(LIMIT+1)
            if len(cached) > LIMIT:raise ValueError('Cache limit')
            cached.decode('utf-8')
        try:
            data, meta = exchange()
            state = preflight(data, cached) if 200 <= meta['status'] < 300 else 'unavailable'
            report['preflight'] = {**meta, 'state':state}
        except (OSError,ValueError):
            data = b'';state = 'unavailable';report['preflight'] = {'state':state,'error':'PREFLIGHT_UNAVAILABLE'}
        if not args.request_file and not args.empty_token_post:
            if args.output:write_private(args.output,data)
            report['catalogValid'] = False
            if args.catalog_output:report['error'] = 'FRESH_ORIGINAL_REQUEST_REQUIRED'
            print(json.dumps(report));return 1 if args.catalog_output else 0
        if state == 'up-to-date':
            print(json.dumps({**report,'catalogValid':False,'state':'UP_TO_DATE_NO_DOWNLOAD'}));return 3
        body = original_request(args.request_file,state) if args.request_file else offline_failure_request()
        data, meta = exchange(body)
        report['post'] = meta
        if args.output:write_private(args.output,data)
        document = codec.decode(data,catalog=True) if 200 <= meta['status'] < 300 else None
        if document is None:raise ValueError('Invalid remote status')
        if args.catalog_output:write_private(args.catalog_output,(codec.render(document)+'\n').encode())
        report.update(catalogValid=True,version=document.get('Version'),servers=len(document['Servers']),tweaks=len(document['Tweaks']))
        print(json.dumps(report));return 0
    except (OSError,ValueError,TypeError,KeyError):
        print(json.dumps({**report,'catalogValid':False,'error':'REMOTE_CATALOG_NOT_VALIDATED'}));return 1


if __name__ == '__main__':raise SystemExit(main())
