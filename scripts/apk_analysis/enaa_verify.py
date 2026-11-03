"""Full authorized Enaa parity against libsodium/JDK, without printing entries."""
from pathlib import Path
import argparse,base64,hashlib,importlib.util,json,subprocess,sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location('enaa_reference',ROOT/'tests/golden/enaa_reference.py');ref=importlib.util.module_from_spec(spec);spec.loader.exec_module(ref)
# Independently transcribed original getter contexts; preserve every other key.
TOP=('DefOVPNUser','DefOVPNPass','HysteriaUser','HysteriaOBFS','DefaultOVPNCert')
SERVER=('ServerIPHost','OVPNUser','OVPNPass','UDP_obfs','UDP_user','CustomCertificate','SlowDNSHost','SlowDNSKey','V2rayUUID','V2rayPath','H2pass','TrojanPass')
NETWORK=('Payload','CustomProxy','SNI','V2rayConfig','BugDNS','V2rayAddress','V2rayHost','V2raySNI')
def verify(path,expected=None):
 data=path.read_bytes();text=data.decode().strip();doc=json.loads(ref.open_many([(text,len(text)%4==1)])[0]);items=[]
 def add(obj,keys):
  for k in keys:
   v=obj.get(k)
   if isinstance(v,str):
    try:
     raw=base64.b64decode(v,validate=True)
     if len(raw)>=44:items.append((obj,k,v))
    except ValueError:pass
 add(doc,TOP)
 for rows,keys in ((doc['Servers'],SERVER),(doc['Networks'],NETWORK)):
  for row in rows:add(row,keys)
 unique=list(dict.fromkeys(v for _,_,v in items));values=ref.open_many([(v,False) for v in unique]);lookup=dict(zip(unique,values))
 for obj,k,v in items:obj[k]=lookup[v]
 if expected is not None and doc!=json.loads(expected.read_text()):raise ValueError('Full JSON differs from independent JCA/libsodium')
 return doc,{'source':path.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'version':doc['Version'],'servers':len(doc['Servers']),'networks':len(doc['Networks']),'fields':len(items),'uniqueFields':len(unique),'fullIndependentEqual':True}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('catalog',type=Path);p.add_argument('--expected',type=Path);a=p.parse_args();doc,report=verify(a.catalog,a.expected);print(json.dumps(report),flush=True)
