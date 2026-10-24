"""Complete 7NET VPN 5.6 catalogs, with the APK-confirmed field dispatch."""
from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path
import struct
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

if __package__ and __package__.startswith('decoders.'):
    from ... import renz as shared
else:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    import renz as shared

MAX_BYTES = 8 * 1024 * 1024
MATERIAL = shared.RENZ_KEYS['7net']
KEY16 = hashlib.sha256(MATERIAL['KEY_SEED']).digest()[:16]
HKDF16 = shared.renz_generate_hkdf_key(MATERIAL['KEY_SEED'], MATERIAL['FIXED_SALT'])
HKDF32 = shared.renz_generate_hkdf32_key(MATERIAL['KEY_SEED'], MATERIAL['FIXED_SALT'])
PBKDF32 = hashlib.pbkdf2_hmac('sha256', MATERIAL['KEY_SEED'], MATERIAL['FIXED_SALT'], 100000, 32)
# Exact consumers recovered from SEVENNETVPNMain.O0, selectors and the build-56 native dispatch.
SERVER_FIELDS = {0: ('Name','Subname','OpenVPNTCPPort','OpenVPNSSLPort','UDPSSLPort','CloudfrontDNS','flag','Obfs','CustomCert'),
                 1: ('ServerIPHost',), 2: ('Username','Password')}
NETWORK_FIELDS = {0: ('Name','Info','DNSResolver','TLSVersion'), 1: ('SNIHost','Payload','UDPv4Port')}
NESTED_FIELDS = {
    ('Servers','SlowDNS'): {0: ('NSNameServer','PubKey')},
    ('Servers','V2Ray'): {0: ('UUID',), 1: ('PATH','V2RayHost')},
    ('Networks','ProxySettings'): {0: ('Squid','Port')},
    ('Networks','UDPOptions'): {0: ('UpMbps','DlMbps','RecvConnectionWindow')},
    ('Networks','V2Ray'): {1: ('SNIHost','CustomV2RAYConfig')},
}


class DecodeError(ValueError):
    pass


def _b64(text: str) -> bytes:
    if not isinstance(text,str) or not text or len(text.encode('utf-8')) > MAX_BYTES:
        raise DecodeError('Campo Base64 inválido.')
    return base64.b64decode(''.join(text.split()), validate=True)


def _xxtea(raw: bytes, key: bytes) -> bytes:
    if len(raw) < 8 or len(raw) % 4:
        raise DecodeError('Longitud XXTEA inválida.')
    value, length = shared.renz_xxtea_decrypt_custom(raw, key)
    if not length:
        raise DecodeError('Contenido XXTEA inválido.')
    return value


def decode_main(text: str) -> str:
    raw = _b64(text)
    if not raw or len(raw) % 16:
        raise DecodeError('Sobre CBC inválido.')
    plain = unpad(AES.new(KEY16,AES.MODE_CBC,MATERIAL['IV']).decrypt(raw),16)
    return bytes((v-2)&255 for v in _xxtea(plain,KEY16)).decode('utf-8')


def decode_special(text: str) -> str:
    raw = _b64(text)
    if not raw or len(raw) % 32:
        raise DecodeError('Bloques Threefish incompletos.')
    words = list(struct.unpack('<4Q',HKDF32)); clear=bytearray()
    for offset in range(0,len(raw),32):
        index=offset//32
        subkeys=shared.threefish_set_key(256,words,[index,0])
        out=[0,0,0,0]
        shared.threefish_decrypt256_block(subkeys,list(struct.unpack('<4Q',raw[offset:offset+32])),out)
        clear.extend(struct.pack('<4Q',*out))
    # Remove zero fill in CBC blocks. The APK's byte-wise trim also cuts
    # legitimate ciphertext zeros.
    # Keep those bytes through the next AES boundary, then validate padding.
    size=((len(bytes(clear).rstrip(b'\0'))+15)//16)*16
    clear=bytes(clear[:size])
    if not clear or len(clear)%16:
        raise DecodeError('Contenido Threefish/CBC inválido.')
    return unpad(AES.new(HKDF16,AES.MODE_CBC,MATERIAL['IV']).decrypt(clear),16).decode('utf-8')


def decode_sensitive(text: str) -> str:
    raw=_b64(text)
    clear=_xxtea(raw,PBKDF32)
    if len(clear)<32 or len(clear)%16:
        raise DecodeError('Sobre de credenciales inválido.')
    # Current native AES-256-CBC uses the first 16 bytes as the IV, not plaintext.
    return unpad(AES.new(PBKDF32,AES.MODE_CBC,clear[:16]).decrypt(clear[16:]),16).decode('utf-8')


def _unique(pairs):
    out={}
    for key,value in pairs:
        if key in out:
            raise DecodeError('JSON ambiguo.')
        out[key]=value
    return out


def _invalid_constant(value):
    raise DecodeError('Constante JSON inválida.')


def open_outer(data: bytes):
    if not isinstance(data,bytes) or not data or len(data)>MAX_BYTES:
        raise DecodeError('Entrada vacía o superior a 8 MiB.')
    return json.loads(decode_main(data.decode('utf-8-sig').strip()),object_pairs_hook=_unique,parse_constant=_invalid_constant)


def decode_catalog(data: bytes) -> dict:
    try:
        doc=open_outer(data)
        if (not isinstance(doc,dict) or 'Version' not in doc or
                any(not isinstance(doc.get(k),list) or not doc[k] for k in ('Servers','Networks'))):
            raise DecodeError('Faltan secciones completas del catálogo.')
        cache={}
        def fields(record,schema):
            if not isinstance(record,dict):
                raise DecodeError('Registro de catálogo inválido.')
            for mode,names in schema.items():
                for name in names:
                    if name not in record or record[name] is None or record[name]=='':
                        continue
                    value=record[name]
                    if not isinstance(value,str):
                        raise DecodeError('Tipo de campo cifrado inválido.')
                    identity=(mode,value)
                    if identity not in cache:
                        cache[identity]=(decode_main,decode_special,decode_sensitive)[mode](value)
                    record[name]=cache[identity]
        fields(doc,{2:('Username','Password')})
        for section,schema in (('Servers',SERVER_FIELDS),('Networks',NETWORK_FIELDS)):
            for record in doc[section]:
                fields(record,schema)
                for (parent,nested),nested_schema in NESTED_FIELDS.items():
                    if parent==section and nested in record and record[nested] is not None:
                        fields(record[nested],nested_schema)
        return doc
    except (ValueError,UnicodeError,KeyError,TypeError,RecursionError,OverflowError):
        raise DecodeError('Catálogo inválido o incompatible con 7NET VPN 5.6.') from None


def render(doc) -> str:
    return json.dumps(doc,ensure_ascii=False,indent=2,allow_nan=False)+'\n'
