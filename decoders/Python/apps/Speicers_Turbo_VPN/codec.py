"""217.4.4/217: WakkoDev MD5/CBC and IV/CBC/Java ROT21 fields.

Inline APK format constants, not HTTP authentication. CBC is not authenticated.
"""
import hashlib,json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from decoders.Python.apps.HTTP_FenixVPN import codec as shared
DecodeError=shared.DecodeError
MAX_BYTES=shared.MAX_BYTES
SERVER_FIELDS=shared.SERVER_FIELDS
USER_FIELDS=shared.USER_FIELDS
render=shared.render
CATALOG_PASSWORD = b'R&a$Ta#PuT@A'
FIELD_KEY = b'Diablo2105AZW8Es\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
def decode_field(value):
    if not isinstance(value,str):raise DecodeError('Campo Speicers Turbo inválido.')
    if not value:return value
    raw=shared._base64(value,urlsafe=True)
    if len(raw)<32 or len(raw)%16:raise DecodeError('Campo Speicers Turbo incompleto.')
    return shared.rotate_java(unpad(AES.new(FIELD_KEY,AES.MODE_CBC,raw[:16]).decrypt(raw[16:]),16).decode('utf-8'),21)
def decode_catalog(data):
    try:
        shared._bounded(data);raw=shared._base64(data.decode('utf-8-sig').strip())
        if len(raw)<32 or raw[:8]!=b'WakkoDev' or (len(raw)-16)%16:raise DecodeError('Sobre inválido.')
        material=previous=b''
        while len(material)<48:previous=hashlib.md5(previous+CATALOG_PASSWORD+raw[8:16]).digest();material+=previous
        clear=unpad(AES.new(material[:32],AES.MODE_CBC,material[32:48]).decrypt(raw[16:]),16)
        obj=json.loads(clear.decode('utf-8'),object_pairs_hook=shared._unique,parse_constant=shared._constant);shared._validate(obj)
        if not isinstance(obj,dict) or not isinstance(obj.get('Version'),str) or not obj['Version']:raise DecodeError('Versión inválida.')
        sections=[k for k in ('Servers','Usuarios') if k in obj]
        if len(sections)!=1:raise DecodeError('Sección incompatible.')
        if 'ReleaseNotes' in obj and not isinstance(obj['ReleaseNotes'],str):raise DecodeError('Notas incompatibles.')
        section=sections[0];rows=obj[section];fields=SERVER_FIELDS if section=='Servers' else USER_FIELDS;name='p0PgL3l0d89mnssz7ImPJA==' if section=='Servers' else 'Name'
        if not isinstance(rows,list) or not rows or any(not isinstance(r,dict) or not isinstance(r.get(name),str) or not r[name] for r in rows):raise DecodeError('Perfiles incompletos.')
        for row in rows:
            for key in fields & row.keys():row[key]=decode_field(row[key])
        shared._validate(obj);return obj
    except (ValueError,UnicodeError,TypeError,RecursionError):raise DecodeError('Catálogo inválido o incompatible con Speicers Turbo VPN 217.4.4.') from None
