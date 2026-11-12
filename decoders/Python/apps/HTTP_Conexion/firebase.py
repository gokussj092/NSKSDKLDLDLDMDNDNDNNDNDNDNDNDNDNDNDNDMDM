"""Build129 public Firebase client protocol; no Admin credentials or attestation.

Config pairs are immutable, cached for one hour and fetched once per process
at a time. FIS tokens are temporary and never persisted or sent to the updater.
"""
import base64
import gzip
import json
import secrets
import threading
import time
from urllib.parse import urlsplit
from urllib.request import Request, HTTPRedirectHandler, build_opener
from .codec import CatalogError

PUBLIC_OPTIONS = {'api_key': 'AIzaSyCs8YtS4f6yvDiqWdhhWng6YvT6hbyjQmU', 'app_id': '1:149721662763:android:43dfafdbb13e6a8016b16e', 'project_id': 'http-conexion', 'certificate_sha1': '38E634DA612E9CAE1D15584EE20A05486F47E04B'}
PACKAGE = 'com.doriaxvpn.unlimited'
TTL_SECONDS = 3600
FAILURE_SECONDS = 60
_lock = threading.Lock()
_cached = None
_expires = 0
_retry_after = 0


def select_config(reply):
    entries = reply.get('entries') if isinstance(reply, dict) else None
    if not isinstance(entries, dict):
        raise CatalogError('HTTP Conexión Remote Config inválido')
    source, password = entries.get('ockla_url'), entries.get('gretta_pass')
    if not isinstance(source, str) or not 1 <= len(source) <= 2048:
        raise CatalogError('HTTP Conexión Remote Config inválido')
    parsed = urlsplit(source)
    if (not source.startswith('https://raw.githubusercontent.com/') or parsed.scheme != 'https' or parsed.netloc != 'raw.githubusercontent.com'
            or parsed.query or parsed.fragment or not parsed.path.startswith('/')
            or any(ord(c)<=32 or ord(c)==127 or c=='\\' for c in source) or len(parsed.path.split('/')) < 5):
        raise CatalogError('HTTP Conexión updater no aprobado')
    if not isinstance(password, str) or not password or '\x00' in password or len(password.encode('utf-8')) > 1024:
        raise CatalogError('HTTP Conexión contraseña de formato inválida')
    return {'source': source, 'password': password}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise CatalogError('HTTP Conexión Firebase redirect denied')


def request(url, headers, body=None, method='POST'):
    data = None if body is None else json.dumps(body, separators=(',', ':')).encode()
    if headers.get('Content-Encoding') == 'gzip':
        data = gzip.compress(data, mtime=0)
    try:
        with build_opener(NoRedirect()).open(Request(url, data=data, headers=headers, method=method), timeout=10) as response:
            raw = response.read(1024*1024+1)
            if response.status != 200 or len(raw) > 1024*1024 or response.headers.get('Content-Encoding', 'identity') != 'identity':
                raise CatalogError('HTTP Conexión Firebase unavailable')
            return json.loads(raw) if raw else {}
    except (OSError, ValueError, UnicodeError):
        raise CatalogError('HTTP Conexión Firebase unavailable') from None


def fetch_config(transport=request):
    options = PUBLIC_OPTIONS
    base = 'https://firebaseinstallations.googleapis.com/v1/projects/'+options['project_id']+'/installations'
    remote = 'https://firebaseremoteconfig.googleapis.com/v1/projects/'+options['app_id'].split(':')[1]+'/namespaces/firebase:fetch'
    headers = {'X-Goog-Api-Key': options['api_key'], 'X-Android-Package': PACKAGE,
               'X-Android-Cert': options['certificate_sha1'], 'Content-Type': 'application/json',
               'Accept': 'application/json', 'Accept-Encoding': 'identity', 'Cache-Control': 'no-cache'}
    bits = bytearray(secrets.token_bytes(17)); bits[16] = bits[0]; bits[0] = (bits[0] & 15) | 112
    fid = base64.urlsafe_b64encode(bits).decode()[:22]
    installation = None
    try:
        installation = transport(base, {**headers, 'Content-Encoding': 'gzip'},
                                 {'fid': fid, 'appId': options['app_id'], 'authVersion': 'FIS_v2', 'sdkVersion': 'a:18.0.0'})
        if not isinstance(installation,dict) or not isinstance(installation.get('authToken'),dict):
            raise CatalogError('HTTP Conexión FIS response invalid')
        fid = installation.get('fid')
        token = installation.get('authToken', {}).get('token')
        refresh = installation.get('refreshToken')
        if (not isinstance(fid, str) or len(fid)!=22 or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-' for c in fid)
                or not isinstance(token, str) or not 1<=len(token)<=16384 or '\r' in token or '\n' in token
                or not isinstance(refresh, str) or not 1<=len(refresh)<=16384 or '\r' in refresh or '\n' in refresh):
            raise CatalogError('HTTP Conexión FIS response invalid')
        body = {'appInstanceId': fid, 'appInstanceIdToken': token, 'appId': options['app_id'],
                'countryCode': 'MX', 'languageCode': 'es-MX', 'platformVersion': '34',
                'timeZone': 'America/Tijuana', 'appVersion': '1.2.9', 'appBuild': '129',
                'packageName': PACKAGE, 'sdkVersion': '22.1.0', 'analyticsUserProperties': {}}
        reply = transport(remote, {**headers, 'X-Goog-Firebase-Installations-Auth': token,
                                   'X-Google-GFE-Can-Retry': 'yes'}, body)
        return select_config(reply)
    finally:
        if isinstance(installation, dict):
            fid, refresh = installation.get('fid'), installation.get('refreshToken')
            if (isinstance(fid, str) and len(fid)==22 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-' for c in fid)
                    and isinstance(refresh, str) and 1<=len(refresh)<=16384 and '\r' not in refresh and '\n' not in refresh):
                try:
                    transport(base+'/'+fid, {**headers, 'Authorization': 'FIS_v2 '+refresh}, method='DELETE')
                except (ValueError, OSError):
                    pass  # Bounded best-effort deletion, never retain or expose tokens.


def resolve_config(*, force=False):
    global _cached, _expires, _retry_after
    with _lock:
        now = time.monotonic()
        if not force and _cached is not None and now < _expires:
            return dict(_cached)
        if now < _retry_after:
            raise CatalogError('HTTP Conexión Firebase temporarily unavailable')
        try:
            value = fetch_config()
        except (ValueError, OSError, TypeError, KeyError):
            _cached = None; _expires = 0; _retry_after = now + FAILURE_SECONDS
            raise CatalogError('HTTP Conexión Firebase temporarily unavailable') from None
        _cached = dict(value); _expires = now + TTL_SECONDS; _retry_after = 0
        return dict(value)
