"""ZiG Tunnel Play1.0: source-confirmed XXTEA(delta772515655), UTF16 shift."""
from __future__ import annotations
import base64,json,struct,sys
from pathlib import Path
if __package__ and '.' in __package__:
 from ..HTTP_FenixVPN import codec as shared
else:
 sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
 from HTTP_FenixVPN import codec as shared
DecodeError=shared.DecodeError
MAX_BYTES=shared.MAX_BYTES
render=shared.render
DELTA=772515655
KEY=struct.unpack('<4I',b'4669'+bytes(12))
MASK=0xffffffff

def decrypt(text):
 try:
  if not isinstance(text,str) or not text or len(text.encode())>MAX_BYTES:raise ValueError()
  raw=base64.b64decode(''.join(text.split()),validate=True)
  if len(raw)<8 or len(raw)%4:raise ValueError()
  words=list(struct.unpack('<'+'I'*(len(raw)//4),raw));n=len(words);total=((6+52//n)*DELTA)&MASK;y=words[0]
  def mx(z,y,p,e):return ((((z>>5)^(y<<2))+((y>>3)^(z<<4)))^((total^y)+(KEY[(p&3)^e]^z)))&MASK
  while total:
   e=(total>>2)&3
   for p in range(n-1,0,-1):words[p]=(words[p]-mx(words[p-1],y,p,e))&MASK;y=words[p]
   words[0]=(words[0]-mx(words[-1],y,0,e))&MASK;y=words[0];total=(total-DELTA)&MASK
  size=words[-1]
  if not len(raw)-7<=size<=len(raw)-4:raise ValueError()
  clear=struct.pack('<'+'I'*n,*words)[:size].decode('utf-8')
  units=bytearray(clear.encode('utf-16-le'))
  for i in range(0,len(units),2):units[i:i+2]=(((int.from_bytes(units[i:i+2],'little')-9338)&65535).to_bytes(2,'little'))
  return units.decode('utf-16-le')
 except (ValueError,UnicodeError,TypeError,struct.error) as exc:raise DecodeError('Sobre ZiG incompatible.') from exc

def open_outer(data):
 try:
  text=shared._bounded(data).decode('utf-8-sig').strip()
  doc=json.loads(decrypt(text),object_pairs_hook=shared._unique,parse_constant=shared._constant);shared._validate(doc)
  if not isinstance(doc,dict):raise ValueError()
  return doc
 except (ValueError,UnicodeError,RecursionError) as exc:raise DecodeError('Catálogo ZiG incompatible.') from exc

TOP_FIELDS=('config_url','account_api','upload_get_api','upload_post_api','AppConfPass','Ovpn_Cert')
SERVER_FIELDS=('ServerIP','ServerCloudFront','ServerHTTP','ProxyHost','Username','Password','ovpnCertificate')
NETWORK_FIELDS=('NetworkPayload','NetworkFrontQuery','NetworkBackQuery','SquidProxy','SSLSNI','SSLPayload')
NETWORK_LISTS=('HTTPNetworks','DirectNetworks','DNSNetworks','UDPNetworks','SSLNetworks')

def decode_catalog(data):
 doc=open_outer(data)
 if (not isinstance(doc.get('Version'),str) or not doc['Version'] or not isinstance(doc.get('Servers'),list) or not doc['Servers'] or
     not any(k in doc for k in NETWORK_LISTS)):
  raise DecodeError('Catálogo ZiG incompleto.')
 cache={}
 def fields(row,names):
  if not isinstance(row,dict):raise DecodeError('Registro ZiG incompatible.')
  for key in names:
   if key not in row or row[key] is None or row[key]=='':continue
   value=row[key]
   if not isinstance(value,str):raise DecodeError('Campo ZiG incompatible.')
   if value not in cache:cache[value]=decrypt(value)
   row[key]=cache[value]
 fields(doc,TOP_FIELDS)
 for key in ('Servers',)+NETWORK_LISTS:
  if key not in doc:continue
  rows=doc[key]
  if not isinstance(rows,list):raise DecodeError('Lista ZiG incompatible.')
  for row in rows:
   if not isinstance(row,dict) or not isinstance(row.get('Name'),str):raise DecodeError('Perfil ZiG sin nombre.')
   fields(row,SERVER_FIELDS if key=='Servers' else NETWORK_FIELDS)
 shared._validate(doc);render(doc);return doc
