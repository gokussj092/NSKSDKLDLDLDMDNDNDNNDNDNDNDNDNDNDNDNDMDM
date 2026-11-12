"""Genis VPN 2.2.6/build76: WakkoDev envelope + CBC fields + Java ROT22.

The inline constants describe this APK format, not HTTP authentication.
AES-CBC has no authentication tag. Output preserves all original JSON keys.
"""
import hashlib
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from decoders.Python.apps.HTTP_FenixVPN import codec as shared

DecodeError = shared.DecodeError
MAX_BYTES = shared.MAX_BYTES
render = shared.render
STRING_FIELDS = frozenset(('2kDKELRmSE143VdcX3FPzw==', '66P9ZUEM1ju4WGhv856BSg==', 'ACqWMY4zuZWzSEs8cZMXIw==', 'Auth', 'B5jcTSGuJUFbTtH5O1IaBg==', 'Fo3TT4oONvv69IQIMg1aLg==', 'ID', 'ITkWvEHp29BmMaLMEGUFcw==', 'Lp3vN9tYsKdE6rWqZuJb1A==', 'MkRXl4D9vpREVCJ0w4qrgg==', 'Name', 'Obfs', 'PFFSWRJKZmOcNLTZxFwgjQ==', 'Password', 'Path', 'QSln2zKCBJvqH9qV4M0ifg==', 'Qz8kR1uPmNvT4sXbHc2AwQ==', 'SbDP19AbQur0YtkkyRlVMA==', 'U7V8DoP4cYkXJjCnpqW6nQ==', 'Username', 'UxdyIntdYykCdV76crKnwg==', 'asmRO4zXsRjhDYX42dbNuw==', 'b3MPypEFR83rzFKUa4UbCw==', 'iW1aO5DgThVAeo23xTsXSw==', 'l7MIgkbuXMmGaaQGd54F2w==', 'mtw364P3ZslP2CZYuHTCHQ==', 'p0PgL3l0d89mnssz7ImPJA==', 'p9ZPlMv9V7gDszRoUaNaJw==', 'tmSbWiCK1hvytJ9f3gflkQ==', 'vXfVafVdyaCRTDj6uBT6lg=='))
# Filled by the checksum-pinned local recovery recipe before verification.
CATALOG_PASSWORD = b'eDios12@gokum'
FIELD_KEY = b'SonGok@$!sN@gD4l\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


def decode_field(value):
    if not isinstance(value, str):
        raise DecodeError('Campo Genis inválido.')
    if not value:
        return value
    raw = shared._base64(value, urlsafe=True)
    if len(raw) < 32 or len(raw) % 16:
        raise DecodeError('Campo Genis incompleto.')
    text = unpad(AES.new(FIELD_KEY, AES.MODE_CBC, raw[:16]).decrypt(raw[16:]), 16).decode('utf-8')
    return shared.rotate_java(text, 22)


def decode_catalog(data):
    try:
        raw = shared._base64(shared._bounded(data).decode('utf-8-sig').strip())
        if len(raw) < 32 or raw[:8] != b'WakkoDev' or (len(raw)-16) % 16:
            raise DecodeError('Sobre Genis inválido.')
        material = previous = b''
        while len(material) < 48:
            previous = hashlib.md5(previous + CATALOG_PASSWORD + raw[8:16]).digest()
            material += previous
        clear = unpad(AES.new(material[:32], AES.MODE_CBC, material[32:48]).decrypt(raw[16:]), 16)
        obj = json.loads(clear.decode('utf-8'), object_pairs_hook=shared._unique, parse_constant=shared._constant)
        shared._validate(obj)
        if not isinstance(obj, dict) or not isinstance(obj.get('Version'), str) or not obj['Version']:
            raise DecodeError('Versión Genis inválida.')
        sections = [k for k in ('Servers', 'Usuarios') if k in obj]
        if len(sections) != 1:
            raise DecodeError('Sección Genis incompatible.')
        if 'ReleaseNotes' in obj and not isinstance(obj['ReleaseNotes'], str):
            raise DecodeError('Notas Genis incompatibles.')
        section = sections[0]
        name = 'p0PgL3l0d89mnssz7ImPJA==' if section == 'Servers' else 'Name'
        rows = obj[section]
        if not isinstance(rows, list) or not rows or any(not isinstance(row, dict) for row in rows):
            raise DecodeError('Perfiles Genis incompletos.')
        for row in rows:
            if not isinstance(row.get(name), str) or not row[name]:
                raise DecodeError('Nombre Genis ausente.')
            # Every string in these build76 profile rows is a CBC field or an
            # empty optional value. Decode all of them, including new keys.
            for key, value in row.items():
                if key in STRING_FIELDS and not isinstance(value, str):
                    raise DecodeError('Tipo de campo Genis inválido.')
                if isinstance(value, str):
                    row[key] = decode_field(value)
            if not row[name]:
                raise DecodeError('Nombre Genis vacío.')
        shared._validate(obj)
        return obj
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise DecodeError('Catálogo inválido o incompatible con Genis VPN 2.2.6.') from None
