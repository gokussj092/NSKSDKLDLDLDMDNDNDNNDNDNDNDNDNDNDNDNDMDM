"""Wolf builds 13/16: authenticated native catalogs and compatible profiles."""
from __future__ import annotations
import base64
import json
from pathlib import Path
import re
import sys
from Crypto.Cipher import AES

if __package__ and '.' in __package__:
    from ..HTTP_FenixVPN import codec as shared
    from . import codec_v16
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from HTTP_FenixVPN import codec as shared
    import codec_v16

DecodeError = shared.DecodeError
MAX_BYTES = shared.MAX_BYTES
MAX_FILE_BYTES = shared.MAX_FILE_BYTES
render = shared.render
# Raw 32 bytes loaded by Go Encrypt/Decrypt from libgojni.so VA 0x363810.
# This ASCII-looking key is used directly; it is NOT Base64-decoded or hashed.
KEY = b'qkKG+glMDxozePe5/Kcm+ZLeba+jJIrF'
# HTTP injector fields also use main.Decrypt2 in libgoinjector.so, VA 0x87e7a.
INJECTOR_KEY = b'Li96biGlJWFeNwKxWR6RrC3IGBu0CsXO'
TOP_FIELDS = frozenset(('DefOVPNUser', 'DefOVPNPass', 'HysteriaUser', 'HysteriaOBFS', 'DefaultOVPNCert'))
SERVER_FIELDS = frozenset(('ServerIPHost', 'OVPNUser', 'OVPNPass', 'UDP_obfs', 'UDP_user',
    'CustomCertificate', 'SlowDNSHost', 'SlowDNSKey', 'V2rayUUID', 'H2pass', 'TrojanPass', 'V2rayPath'))
NETWORK_FIELDS = frozenset(('Payload', 'SNI', 'CustomProxy', 'V2rayConfig', 'BugDNS',
    'V2rayAddress', 'V2rayHost', 'V2raySNI'))
NESTED_FIELDS = {'UDPHysteria': frozenset(('obfs', 'pass', 'user')),
                 'V2ray': frozenset(('Path', 'UUID', 'trojanPass'))}


class EnvelopeError(DecodeError):
    """No modern envelope authenticated; a historical file reader may be tried."""


def decrypt(value: str, *, injector=False) -> str:
    if not isinstance(value,str) or len(value.encode("utf-8"))>MAX_BYTES:
        raise EnvelopeError("Sobre Wolf inválido o no compatible.")
    text=value.replace("\r","").replace("\n","")
    # Build16 transport has one explicit inserted character. Raw field/asset
    # envelopes retain ordinary Base64. Every accepted route authenticates.
    if len(text)%4==1:
        try:return codec_v16.decrypt(text,transport=True)
        except codec_v16.AuthenticatedTextError:
            raise DecodeError("Texto Wolf incompatible.") from None
        except (ValueError,UnicodeError):
            raise EnvelopeError("Sobre Wolf inválido o no compatible.") from None
    try:
        raw=base64.b64decode(text,validate=True)
        if len(raw)<28:raise ValueError()
    except ValueError:
        raise EnvelopeError("Sobre Wolf inválido o no compatible.") from None
    for key in ((KEY,INJECTOR_KEY) if injector else (KEY,)):
        try:
            clear=AES.new(key,AES.MODE_GCM,nonce=raw[:12]).decrypt_and_verify(raw[12:-16],raw[-16:])
        except ValueError:
            continue
        try:return clear.decode("utf-8")
        except UnicodeError:
            raise DecodeError("Texto Wolf incompatible.") from None
    try:return codec_v16.decrypt(text)
    except codec_v16.AuthenticatedTextError:
        raise DecodeError("Texto Wolf incompatible.") from None
    except (ValueError,UnicodeError):
        raise EnvelopeError("Sobre Wolf inválido o no compatible.") from None


def parse_document(text: str) -> dict:
    try:
        value = json.loads(text, object_pairs_hook=shared._unique, parse_constant=shared._constant)
        shared._validate(value)
        if not isinstance(value, dict):
            raise DecodeError('Documento Wolf incompatible.')
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError('Documento Wolf inválido.') from exc


def open_document(data: bytes, *, limit=MAX_BYTES) -> dict:
    try:
        text = shared._bounded(data, limit).decode('utf-8-sig').strip()
    except UnicodeError as exc:
        raise DecodeError('Entrada Wolf incompatible.') from exc
    return parse_document(text if text.startswith('{') else decrypt(text))


def _record(item: dict, fields: frozenset) -> dict:
    result = item.copy()
    for key in fields & item.keys():
        value = item[key]
        if not isinstance(value, str):
            raise DecodeError('Campo Wolf incompatible.')
        # The app also stores plaintext in these fields. A syntactically packed
        # modern envelope must authenticate; never silently retain a bad tag.
        packed = value.replace('\r', '').replace('\n', '')
        if len(packed) >= 40 and re.fullmatch(r'[A-Za-z0-9+/]*={0,2}', packed):
            result[key] = decrypt(value, injector=key in ('Payload', 'CustomProxy', 'SNI'))
    return result


def decode_catalog(data: bytes) -> dict:
    obj = open_document(data)
    if (not isinstance(obj.get('Version'), str) or not obj['Version'] or
            any(not isinstance(obj.get(k), list) or not obj[k] for k in ('Servers', 'Networks'))):
        raise DecodeError('Catálogo Wolf incompatible.')
    result = _record(obj, TOP_FIELDS)
    for section, fields in (('Servers', SERVER_FIELDS), ('Networks', NETWORK_FIELDS)):
        result[section] = []
        for item in obj[section]:
            if not isinstance(item, dict) or not isinstance(item.get('Name'), str):
                raise DecodeError('Perfil Wolf incompatible.')
            entry = _record(item, fields)
            if section == 'Servers':
                for key, nested_fields in NESTED_FIELDS.items():
                    nested = item.get(key)
                    if nested is not None:
                        if not isinstance(nested, dict):
                            raise DecodeError('Ajustes Wolf incompatibles.')
                        entry[key] = _record(nested, nested_fields)
            result[section].append(entry)
    shared._validate(result)
    render(result)
    return result


def decode_profile_document(obj: dict) -> dict:
    if not isinstance(obj.get('Name'), str) or not isinstance(obj.get('TunnelType'), str):
        raise DecodeError('Archivo Wolf incompatible.')
    result = _record(obj, NETWORK_FIELDS)
    render(result)
    return result

