"""Complete XXPICore Tunnel 118 catalog, with all original field modes.

The build-118 ELF independently matches Xhypher 43's cipher material and
primitives. Reuse those tested primitives; keep XXPICore's schema separate.
"""
from ..Xhypher_Tunnel_Pro.codec import (
    MAX_BYTES, DecodeError, decode_main, decode_special, decode_sensitive,
    open_outer, render,
)

SERVER_FIELDS={0:('Name','Subname','OpenVPNTCPPort','OpenVPNSSLPort','CloudfrontDNS','flag','Obfs','CustomCert'),
               1:('ServerIPHost',),2:('Username','Password')}
NETWORK_FIELDS={0:('Name','Info','DNSResolver','TLSVersion'),1:('SNIHost','Payload')}
NESTED_FIELDS={
    ('Servers','SlowDNS'):{0:('NSNameServer','PubKey')},
    ('Servers','V2Ray'):{0:('UUID',),1:('PATH','V2RayHost')},
    ('Networks','ProxySettings'):{0:('Squid','Port')},
    ('Networks','UDPOptions'):{0:('UpMbps','DlMbps','RecvConnectionWindow')},
    ('Networks','V2Ray'):{1:('SNIHost','CustomV2RAYConfig')},
}

def decode_catalog(data:bytes)->dict:
    try:
        doc=open_outer(data)
        if (not isinstance(doc,dict) or not isinstance(doc.get('Version'),str) or not doc['Version'] or
            any(not isinstance(doc.get(k),list) or not doc[k] for k in ('Servers','Networks'))):
            raise DecodeError('Catálogo incompleto.')
        cache={}
        def fields(record,schema):
            if not isinstance(record,dict):raise DecodeError('Registro inválido.')
            for mode,names in schema.items():
                for name in names:
                    if name not in record or record[name] is None or record[name]=='':continue
                    value=record[name]
                    if not isinstance(value,str):raise DecodeError('Campo cifrado inválido.')
                    identity=mode,value
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
        raise DecodeError('Catálogo inválido o incompatible con XXPICore Tunnel 118.') from None

def run(data:bytes)->str:
    return render(decode_catalog(data))
