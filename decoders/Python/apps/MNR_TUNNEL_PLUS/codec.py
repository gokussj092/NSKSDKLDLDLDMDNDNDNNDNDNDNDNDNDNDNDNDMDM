#!/usr/bin/env python3
"""MNR TUNNEL PLUS 3.1: catalogs, .stp/clipboard and Firebase references.

Standalone Python + PyCryptodome. No APK, user password or device ID needed.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

MAX_BYTES = 8 * 1024 * 1024
OUTER_ALPHABET = "¹²³⁴⁵⁶⁷⁸⁹⁰·,‽:'′"
FIELD_ALPHABET = ''.join(chr(0x2000 + i) for i in range(16))
FIELD_SECRET = '❤️🧑\u200d💻Bøbõ⁰⁰!!'
CATALOG_URL = 'https://raw.githubusercontent.com/buttacuore2025/up/refs/heads/main/plusfast'
REFERENCE_PREFIX = 'mnrtunneludp://'
BUCKET = 'hamovpn.firebasestorage.app'
STORAGE_BASE = 'https://firebasestorage.googleapis.com/v0/b/' + BUCKET + '/o/'
SERVER_FIELDS = frozenset(('ServerIP', 'ServerUser', 'ServerPass', 'v2rayurl', 'UdpIP',
                          'Obfs_Str', 'Auth_Str', 'chaveKey', 'serverNameKey'))
NETWORK_FIELDS = frozenset(('Payload', 'SNI', 'dnsKey', 'ProxyIP', 'v2Address', 'v2Host',
                           'v2SNI', 'udpIP', 'udpObfs', 'udpAuth', 'PREFIX', 'DNS_RESOLVER_MANUAL'))


class DecodeError(ValueError):
    """Sanitized errors; never include a profile, key, URL token or password."""


def _bounded(data: bytes) -> bytes:
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError('Entrada vacía o superior a 8 MiB.')
    return data


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DecodeError('JSON con claves duplicadas.')
        result[key] = value
    return result


def _nonfinite(_value):
    raise DecodeError('JSON con números no finitos.')


def _validate(value):
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > 64 or count > 200_000:
            raise DecodeError('Complejidad superior al límite.')
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
            pending.extend((k, depth + 1) for k in item)
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
        elif isinstance(item, str):
            item.encode('utf-8')
        elif isinstance(item, float) and not math.isfinite(item):
            raise DecodeError('Número fuera de rango.')
    return value


def load_json(text: str) -> dict:
    value = json.loads(text, object_pairs_hook=_unique, parse_constant=_nonfinite)
    if not isinstance(value, dict):
        raise DecodeError('Se esperaba un objeto JSON.')
    return _validate(value)


def _key(secret: str) -> bytes:
    return hashlib.sha256(secret.encode('utf-8').hex().upper().encode('ascii')).digest()


def decrypt_layer(text: str, secret: str, alphabet=OUTER_ALPHABET) -> str:
    # U+2000..U+200F are ciphertext digits, including Unicode whitespace.
    # Never strip them, normalize Unicode or use a whitespace Base64 filter.
    if not isinstance(text, str) or not text or len(text) % 2 or any(c not in alphabet for c in text):
        raise DecodeError('Alfabeto cifrado inválido.')
    raw = bytes(alphabet.index(text[i]) * 16 + alphabet.index(text[i + 1]) for i in range(0, len(text), 2))
    sealed = base64.b64decode(raw, validate=True)
    if not sealed or len(sealed) % 16 or base64.b64encode(sealed) != raw:
        raise DecodeError('Contenedor AES-CBC inválido.')
    return unpad(AES.new(_key(secret), AES.MODE_CBC, bytes(16)).decrypt(sealed), 16).decode('utf-8')


def _outer(data: bytes, secret: str) -> dict:
    text = _bounded(data).decode('utf-8-sig').strip(' \t\r\n')
    return load_json(decrypt_layer(text, secret))


def decode_catalog(data: bytes) -> dict:
    try:
        obj = _outer(data, 'devpro')
        if not isinstance(obj.get('Version'), str) or not obj['Version']:
            raise DecodeError('Versión de catálogo inválida.')
        for name, fields in (('Servers', SERVER_FIELDS), ('Networks', NETWORK_FIELDS)):
            rows = obj.get(name)
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise DecodeError('Lista de catálogo inválida.')
            for row in rows:
                if not isinstance(row.get('Name'), str):
                    raise DecodeError('Perfil sin nombre.')
                for field in fields & row.keys():
                    if not isinstance(row[field], str):
                        raise DecodeError('Campo cifrado sin texto.')
                    if row[field] != '':
                        row[field] = decrypt_layer(row[field], FIELD_SECRET, FIELD_ALPHABET)
        return _validate(obj)
    except (ValueError, UnicodeError, RecursionError, TypeError, OverflowError) as exc:
        raise DecodeError('Catálogo inválido o incompatible con MNR TUNNEL PLUS 3.1.') from exc


def decode_profile(data: bytes) -> dict:
    try:
        obj = _outer(data, 'demondevs')
        if (type(obj.get('TunnelType')) is not int or type(obj.get('isPassON')) is not bool or
                not isinstance(obj.get('MyPass'), str) or not isinstance(obj.get('DeviceID'), str) or
                type(obj.get('ExpireDate')) is not int):
            raise DecodeError('Estructura de perfil incompatible.')
        # G5.f local/clipboard and G5.h cloud use different JSON field names.
        # Preserve both entire schemas and every restriction without renaming.
        if not any(key in obj for key in ('http_p', 'v2_c', 'udp_s', 'CPayload', 'V2Ray', 'UdpServer')):
            raise DecodeError('El documento no contiene un perfil MNR.')
        return obj
    except (ValueError, UnicodeError, RecursionError, TypeError, OverflowError) as exc:
        raise DecodeError('Perfil inválido o incompatible con MNR TUNNEL PLUS 3.1.') from exc


def is_profile_text(value: str) -> bool:
    return isinstance(value, str) and len(value) >= 64 and all(c in OUTER_ALPHABET for c in value)


def render(obj: dict) -> str:
    try:
        output = json.dumps(_validate(obj), ensure_ascii=False, indent=2, allow_nan=False)
        if len(output.encode('utf-8')) > MAX_BYTES:
            raise DecodeError('Salida superior a 8 MiB.')
        return output
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError('No se pudo generar el JSON completo.') from exc


def parse_reference(value: str) -> str:
    if not isinstance(value, str) or len(value) > 64:
        raise DecodeError('Referencia MNR inválida.')
    value = value.strip(' \t\r\n')
    if value.startswith(REFERENCE_PREFIX):
        value = value[len(REFERENCE_PREFIX):]
    if not re.fullmatch(r'[A-Za-z0-9]{10}', value):
        raise DecodeError('Referencia MNR inválida.')
    return value


def reference_url(value: str) -> str:
    # Firebase child() normalizes consecutive slashes before URI encoding:
    # mnrtunneludp://ID.sky -> mnrtunneludp:/ID.sky (literal object path).
    return STORAGE_BASE + quote('mnrtunneludp:/' + parse_reference(value) + '.sky', safe='')


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise DecodeError('Redirección remota no permitida.')


def _download(url: str, limit=MAX_BYTES) -> bytes:
    request = Request(url, headers={'User-Agent': 'MNR TUNNEL PLUS/3.1', 'Accept-Encoding': 'identity'})
    with build_opener(_NoRedirect()).open(request, timeout=25) as response:
        if response.status != 200 or response.headers.get('Content-Encoding', 'identity') != 'identity':
            raise DecodeError('Respuesta remota incompatible.')
        data = response.read(limit + 1)
    if not data or len(data) > limit:
        raise DecodeError('Respuesta remota vacía o demasiado grande.')
    return data


def download_catalog() -> bytes:
    return _download(CATALOG_URL)


def download_profile(reference: str) -> bytes:
    try:
        url = reference_url(reference)
        metadata = load_json(_download(url, 256 * 1024).decode('utf-8'))
        if (metadata.get('bucket') != BUCKET or
                metadata.get('name') != 'mnrtunneludp:/' + parse_reference(reference) + '.sky' or
                not isinstance(metadata.get('downloadTokens'), str)):
            raise DecodeError('Metadatos de importación incompatibles.')
        token = metadata['downloadTokens'].split(',')[0]
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,256}', token):
            raise DecodeError('Token de descarga inválido.')
        return _download(url + '?alt=media&token=' + token)
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError('No se pudo descargar el perfil MNR; la referencia puede no estar disponible.') from exc


def _read(path: Path) -> bytes:
    with path.open('rb') as stream:
        return stream.read(MAX_BYTES + 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sources = parser.add_mutually_exclusive_group()
    sources.add_argument('--input', type=Path, help='Catálogo cifrado guardado')
    sources.add_argument('--apks', type=Path, help='Leer asset incluido, sin red')
    sources.add_argument('--file', type=Path, help='Perfil .stp')
    sources.add_argument('--text', help='Texto cifrado del portapapeles')
    sources.add_argument('--online', help='Enlace mnrtunneludp:// o ID de diez caracteres')
    parser.add_argument('--output', '-o', type=Path)
    parser.add_argument('--summary', action='store_true', help='Solo versión y recuentos, sin datos del perfil')
    args = parser.parse_args()
    try:
        profile = bool(args.file or args.text is not None or args.online is not None)
        if args.file:
            data = _read(args.file)
        elif args.text is not None:
            data = args.text.encode('utf-8')
        elif args.online is not None:
            data = download_profile(args.online)
        elif args.apks:
            with zipfile.ZipFile(args.apks) as outer:
                if outer.namelist().count('base.apk') != 1 or outer.getinfo('base.apk').file_size > 100 * 1024 * 1024:
                    raise DecodeError('APKS incompatible.')
                import io
                with zipfile.ZipFile(io.BytesIO(outer.read('base.apk'))) as apk:
                    name = 'assets/config/config.json'
                    if apk.namelist().count(name) != 1 or apk.getinfo(name).file_size > MAX_BYTES:
                        raise DecodeError('Asset incompatible.')
                    data = apk.read(name)
        else:
            data = _read(args.input) if args.input else download_catalog()
        obj = decode_profile(data) if profile else decode_catalog(data)
        if args.summary:
            print(json.dumps({'kind': 'profile'} if profile else
                {'version': obj['Version'], 'servers': len(obj['Servers']), 'networks': len(obj['Networks'])}))
        else:
            output = args.output or Path('mnr_perfil.json' if profile else 'mnr_catalogo.json')
            text = render(obj) + '\n'
            with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w', encoding='utf-8') as stream:
                stream.write(text)
            print('JSON completo guardado.')
        return 0
    except (OSError, ValueError, zipfile.BadZipFile):
        print('No se pudo completar MNR; comprueba la entrada o conexión y usa una salida nueva.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
