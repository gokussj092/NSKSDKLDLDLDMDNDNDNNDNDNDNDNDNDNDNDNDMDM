"""V2ray Tunnel Plus 10.0.0 public subscription reader; no VPN connections."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, unquote_plus, urlsplit
if __package__ and '.' in __package__:
    from ..HTTP_FenixVPN import codec as shared
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from HTTP_FenixVPN import codec as shared
DecodeError = shared.DecodeError
MAX_BYTES = shared.MAX_BYTES
render = shared.render
SCHEMES = frozenset(('vmess','vless','trojan','ss','socks','wireguard','hysteria2','hy2'))


def _decode64(text: str) -> str:
    return shared._base64(text, urlsafe=True).decode('utf-8-sig')


def _unquote(text: str, *, plus=False) -> str:
    if re.search(r'%(?![0-9A-Fa-f]{2})',text):
        raise DecodeError('Escape URI inválido.')
    return (unquote_plus if plus else unquote)(text, encoding='utf-8',errors='strict')


def decode_uri(uri: str) -> dict:
    """Expose all source data; never apply device settings, filters or defaults."""
    scheme, marker, body = uri.partition('://')
    if not marker or scheme not in SCHEMES or any(c in '\r\n\t\0' for c in uri):
        raise DecodeError('Protocolo de suscripción inválido o incompatible.')
    if scheme=='vmess' and '@' not in body:
        obj=json.loads(_decode64(body),object_pairs_hook=shared._unique,parse_constant=shared._constant)
        shared._validate(obj)
        if not isinstance(obj,dict) or any(not obj.get(k) for k in ('add','port','id','net')):
            raise DecodeError('Documento VMess inválido.')
        return {'protocol':scheme,'uri':uri,'encoding':'base64-json','config':obj}
    parse_uri=uri
    if scheme=='ss' and '@' not in body:
        token,sep,fragment=body.partition('#')
        parse_uri='ss://'+_decode64(token)+(sep+fragment if sep else '')
    split=urlsplit(parse_uri)
    host=split.hostname
    port=split.port
    if not host or port is None or not 1<=port<=65535:
        raise DecodeError('Servidor o puerto de suscripción inválido.')
    userinfo=split.netloc.rsplit('@',1)[0] if '@' in split.netloc else ''
    userinfo=_unquote(userinfo)
    # java.net.URI decodes the fragment once; Utils.urlDecode performs a second
    # form-decoding pass. Preserve the exact original URI as well.
    fragment=_unquote(_unquote(split.fragment),plus=True)
    query=[]
    if split.query:
        for part in split.query.split('&'):
            key,sep,value=part.partition('=')
            query.append([_unquote(key,plus=True),_unquote(value,plus=True)])
    entry={'protocol':scheme,'uri':uri,'encoding':'uri','host':host.lower(),
           'port':port,'userInfo':userinfo,'path':_unquote(split.path),
           'query':query,'fragment':fragment}
    if scheme=='ss':
        credentials=userinfo if ':' in userinfo else _decode64(userinfo)
        method,sep,password=credentials.partition(':')
        if not sep or not method:
            raise DecodeError('Credenciales Shadowsocks inválidas.')
        entry['credentials']={'method':method,'password':password}
    elif scheme=='socks' and userinfo:
        credentials=_decode64(userinfo)
        username,sep,password=credentials.partition(':')
        if not sep:raise DecodeError('Credenciales SOCKS inválidas.')
        entry['credentials']={'username':username,'password':password}
    elif scheme!='socks' and not userinfo:
        raise DecodeError('Identificador de suscripción ausente.')
    return entry


def decode_catalog(data: bytes, *, expected_encoding: str | None=None) -> dict:
    try:
        original=shared._bounded(data).decode('utf-8-sig')
        if expected_encoding not in (None,'base64','plain'):
            raise DecodeError('Tipo de fuente inválido.')
        encoding=expected_encoding or ('plain' if '://' in original else 'base64')
        text=_decode64(original) if encoding=='base64' else original
        if not text or len(text.encode('utf-8'))>MAX_BYTES:
            raise DecodeError('Suscripción vacía o superior al límite.')
        profiles=[]
        for number,line in enumerate(text.splitlines(),1):
            uri=line.strip()
            if uri:profiles.append({'line':number,**decode_uri(uri)})
        if not profiles:raise DecodeError('La suscripción no contiene perfiles.')
        result={'encoding':encoding,'sourceSha256':hashlib.sha256(data).hexdigest(),
                'text':text,'count':len(profiles),'profiles':profiles}
        shared._validate(result)
        return result
    except (ValueError,UnicodeError,RecursionError,TypeError) as exc:
        raise DecodeError('Catálogo inválido o no compatible con V2ray Tunnel Plus 10.0.0.') from exc
