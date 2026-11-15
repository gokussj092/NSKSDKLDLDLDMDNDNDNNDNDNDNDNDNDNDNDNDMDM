#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTTP Tweak — catalogo publico de servidores.
SP-DECODE / com.wyrhub.tun 1.8.17 (versionCode 632), arm64-v8a.

Origen del catalogo (verificado en vivo 2026-11-14):
  Primario: el JSON publico que la propia app lee de su repo GitHub
  (campo github.public_servers del config descifrado):
    https://raw.githubusercontent.com/Wyr-Hub/HTTPTweak/refs/heads/main/public_servers.json
  Respaldo: la pagina web renderizada https://httptweak.com/public-servers
  (misma lista, sin cargas ni detalles; solo tipos de tunel).
  Tweaks publicos (hoy vacio {}):
    https://raw.githubusercontent.com/Wyr-Hub/HTTPTweak/refs/heads/main/public_tweaks.json

La app (cliente Ltb) hace GET con:
  Accept: application/json,text/plain,*/*
  timeout de conexion 15 s, lectura 30 s.
No requiere API key, registro ni HWID para el catalogo PUBLICO.
El resto de la API (/v1/config/*, /v1/device/*, /v1/auth/*) si requiere
registro de dispositivo / API key de usuario; no se usa aqui.

Servidores en vivo (2026-11-14, los 5 online):
  atl-global     Global   SSH              15%
  atl-global-cf  Global   SSH              20%
  vb-pl-1        Poland   V2Ray Shadowsocks 34%
  vb-pl-2        Poland   V2Ray Shadowsocks 45%
  vb-ca-1        Canada   V2Ray Shadowsocks 29%

Solo stdlib. Salida JSON por stdout (o --out archivo).
"""
import argparse
import json
import re
import sys
import urllib.error
import urllib.request

APP_PACKAGE = 'com.wyrhub.tun'
APP_VERSION = '1.8.17'
APP_VERSION_CODE = 632

PUBLIC_SERVERS_URL = ('https://raw.githubusercontent.com/Wyr-Hub/HTTPTweak/'
                      'refs/heads/main/public_servers.json')
PUBLIC_TWEAKS_URL = ('https://raw.githubusercontent.com/Wyr-Hub/HTTPTweak/'
                     'refs/heads/main/public_tweaks.json')
PUBLIC_SERVERS_PAGE = 'https://httptweak.com/public-servers'
API_BASE = 'https://httptweak.com/api'

# La app usa HttpURLConnection (Java) con estos headers en el cliente Ltb.
HEADERS = {
    'Accept': 'application/json,text/plain,*/*',
    'User-Agent': ('Mozilla/5.0 (Linux; Android 14; Pixel 9) AppleWebKit/537.36 '
                   '(KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36'),
}


def _get(url, timeout=30):
    req = urllib.request.Request(url, headers=HEADERS, method='GET')
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read()


def fetch_public_servers(url=PUBLIC_SERVERS_URL):
    """Devuelve el dict del catalogo publico (tunnel_types + servers)."""
    status, data = _get(url)
    if status != 200:
        raise RuntimeError('HTTP %s en %s' % (status, url))
    doc = json.loads(data.decode('utf-8'))
    if not isinstance(doc, dict) or 'servers' not in doc:
        raise ValueError('el JSON no trae "servers": %s' % url)
    return doc


def fetch_public_tweaks(url=PUBLIC_TWEAKS_URL):
    status, data = _get(url)
    if status != 200:
        raise RuntimeError('HTTP %s en %s' % (status, url))
    return json.loads(data.decode('utf-8'))


def fetch_public_servers_page(url=PUBLIC_SERVERS_PAGE):
    """Respaldo: la pagina web lista los tipos de tunel (sin detalle)."""
    status, data = _get(url)
    if status != 200:
        raise RuntimeError('HTTP %s en %s' % (status, url))
    text = data.decode('utf-8', errors='replace')
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def catalog(url=PUBLIC_SERVERS_URL):
    doc = fetch_public_servers(url)
    servers = []
    for s in doc.get('servers', []):
        servers.append({
            'id': s.get('id'),
            'country': s.get('country'),
            'name': s.get('name'),
            'tunnel_type': s.get('tunnel_type'),
            'status': s.get('status'),
            'load_percent': s.get('load_percent'),
            'tier': s.get('tier', ''),
            'tags': s.get('tags', []),
        })
    return {
        'app': 'HTTP Tweak',
        'package': APP_PACKAGE,
        'version': APP_VERSION,
        'version_code': APP_VERSION_CODE,
        'tunnel_types': doc.get('tunnel_types', {}),
        'servers': servers,
        'servers_online': sum(1 for s in servers if s['status'] == 'online'),
        'servers_total': len(servers),
    }


def _self_test():
    print('self-test: catalogo en vivo desde %s' % PUBLIC_SERVERS_URL)
    cat = catalog()
    assert cat['servers_total'] >= 1, 'sin servidores'
    assert cat['servers_online'] == cat['servers_total'], \
        'hay servidores no online: %s' % cat
    ids = {s['id'] for s in cat['servers']}
    for want in ('atl-global', 'vb-pl-1', 'vb-ca-1'):
        assert want in ids, 'falta servidor esperado %s (ids: %s)' % (want, ids)
    for s in cat['servers']:
        assert s['tunnel_type'] in ('ssh', 'v2ray_ss'), \
            'tunnel_type inesperado: %r' % s['tunnel_type']
        assert s['status'] == 'online'
    print('self-test OK: %d servidores, %d online; tipos %s'
          % (cat['servers_total'], cat['servers_online'],
             sorted({s['tunnel_type'] for s in cat['servers']})))
    for s in cat['servers']:
        print('  - %-14s %-8s %-28s %s%%' % (
            s['id'], s['country'], s['name'], s['load_percent']))
    tw = fetch_public_tweaks()
    print('self-test OK: public_tweaks.json responde (%s)'
          % ('vacio' if not tw else '%d claves' % len(tw)))
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='Catalogo publico de servidores de HTTP Tweak.')
    ap.add_argument('--url', default=PUBLIC_SERVERS_URL,
                    help='URL del JSON de servidores publicos')
    ap.add_argument('--out', help='escribir el JSON del catalogo en archivo')
    ap.add_argument('--tweaks', action='store_true',
                    help='incluir tambien public_tweaks.json')
    ap.add_argument('--self-test', action='store_true',
                    help='verificar el catalogo en vivo y salir')
    args = ap.parse_args(argv)
    if args.self_test:
        return 0 if _self_test() else 1
    cat = catalog(args.url)
    if args.tweaks:
        cat['public_tweaks'] = fetch_public_tweaks()
    out = json.dumps(cat, indent=2, ensure_ascii=False)
    if args.out:
        with open(args.out, 'w', encoding='utf-8') as fh:
            fh.write(out)
        print('escrito %s (%d servidores)' % (args.out, cat['servers_total']))
    else:
        print(out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
