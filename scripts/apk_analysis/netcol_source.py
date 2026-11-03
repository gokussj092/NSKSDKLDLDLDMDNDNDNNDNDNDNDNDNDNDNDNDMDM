#!/usr/bin/env python3
"""Inspect the pinned Netcol 142 APK and optionally read its Remote Config URL.

No app code executes. Public SDK metadata is read from resources; API keys are
never printed. The discovery result never automatically changes broker targets.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import sys
from urllib.parse import urlsplit
from urllib.request import Request, HTTPRedirectHandler, build_opener

APK_SHA256 = '1f449d216199f5f6ebc55087e6e8cbe8248aafa3fe158e898d9abbc17d68dd7a'
PINNED_SOURCE = 'https://raw.githubusercontent.com/jdavidag/setting/main/tO6oD1drTvL2.json'

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('Remote Config redirected')

def inspect(apk, fetch=False):
    if hashlib.sha256(Path(apk).read_bytes()).hexdigest() != APK_SHA256:
        raise ValueError('Unsupported Netcol APK')
    from loguru import logger
    logger.remove()
    from androguard.core.apk import APK
    app = APK(str(apk))
    certificates = app.get_certificates_der_v2()
    if len(certificates) != 1 or app.get_package() != 'com.netcol.vpn':
        raise ValueError('Unexpected Netcol identity')
    sha1 = hashlib.sha1(certificates[0]).hexdigest()
    if sha1 != '782749d51dc4c29b560d51b032b98490c287f988':
        raise ValueError('Unexpected signer')
    result = {'package': app.get_package(), 'version': app.get_androidversion_name(),
              'versionCode': app.get_androidversion_code(), 'apkSha256': APK_SHA256,
              'signerSha1': sha1, 'pinnedSource': PINNED_SOURCE}
    if not fetch:
        return result
    resources = app.get_android_resources()
    metadata = {name: resources.get_string(app.get_package(), name)[1]
                for name in ('google_api_key', 'google_app_id', 'gcm_defaultSenderId')}
    raw = bytearray(secrets.token_bytes(17))
    raw[0] = (raw[0] & 15) | 112
    fid = base64.urlsafe_b64encode(raw).decode().rstrip('=')[:22]
    body = {'appId': metadata['google_app_id'], 'appInstanceId': fid, 'appVersion': '14.2',
            'appBuild': '142', 'languageCode': 'es', 'countryCode': 'CO', 'sdkVersion': '22.1.1',
            'platformVersion': '35', 'packageName': 'com.netcol.vpn'}
    url = ('https://firebaseremoteconfig.googleapis.com/v1/projects/' + metadata['gcm_defaultSenderId']
           + '/namespaces/firebase:fetch?key=' + metadata['google_api_key'])
    req = Request(url, data=json.dumps(body).encode(), method='POST', headers={
        'Content-Type': 'application/json', 'Accept-Encoding': 'identity',
        'X-Android-Package': app.get_package(), 'X-Android-Cert': sha1.upper()})
    with build_opener(NoRedirect()).open(req, timeout=25) as response:
        if response.status != 200 or response.headers.get('Content-Encoding', 'identity') != 'identity':
            raise ValueError('Unexpected Remote Config reply')
        data = response.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise ValueError('Remote Config size limit')
    source = json.loads(data).get('entries', {}).get('NEW_URL_UPDATE')
    if not isinstance(source, str):
        raise ValueError('Missing updater source')
    parsed = urlsplit(source)
    if (parsed.scheme != 'https' or parsed.hostname != 'raw.githubusercontent.com' or parsed.port
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError('Unapproved discovered source')
    result.update({'remoteConfigSource': source, 'matchesPinnedSource': source == PINNED_SOURCE,
                   'responseSha256': hashlib.sha256(data).hexdigest()})
    return result

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apk', type=Path)
    parser.add_argument('--fetch', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(inspect(args.apk, args.fetch)))
    except (ValueError, OSError, KeyError, TypeError, IndexError):
        print('Netcol source verification failed; no credentials or response content logged.', file=sys.stderr)
        raise SystemExit(1)
