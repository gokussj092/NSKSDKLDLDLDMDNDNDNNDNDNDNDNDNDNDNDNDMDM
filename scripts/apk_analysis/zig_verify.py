"""Compare authorized ZiG catalog and confirmed field contexts with original Java."""
from pathlib import Path
import base64,subprocess,sys,json,hashlib,argparse
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
def oracle(mode,values):
 lines=''.join(mode+'\t'+base64.b64encode(s.encode()).decode()+'\n' for s in values)
 r=subprocess.run(['java',str(ROOT/'tests/golden/zig_oracle.java')],input=lines,text=True,capture_output=True,check=True,timeout=45)
 out=[base64.b64decode(x).decode() for x in r.stdout.splitlines()]
 if len(out)!=len(values):raise ValueError('Incomplete Java result')
 return out

def entries(doc):
 result=[]
 def add(row,names):
  for name in names:
   if row.get(name) not in (None,''):result.append((row,name,row[name]))
 add(doc,('config_url','account_api','upload_get_api','upload_post_api','AppConfPass','Ovpn_Cert'))
 for row in doc['Servers']:add(row,('ServerIP','ServerCloudFront','ServerHTTP','ProxyHost','Username','Password','ovpnCertificate'))
 for section in ('HTTPNetworks','DirectNetworks','DNSNetworks','UDPNetworks','SSLNetworks'):
  for row in doc.get(section,[]):add(row,('NetworkPayload','NetworkFrontQuery','NetworkBackQuery','SquidProxy','SSLSNI','SSLPayload'))
 return result

def verify(path,runtime=False):
 from decoders.Python.apps.ZiG_Tunnel.codec import decode_catalog
 data=path.read_bytes();doc=json.loads(oracle('D',[data.decode().strip()])[0]);items=entries(doc)
 unique=list(dict.fromkeys(v for _,_,v in items));mapping=dict(zip(unique,oracle('D',unique)))
 for row,k,v in items:row[k]=mapping[v]
 actual=decode_catalog(data)
 if actual!=doc:raise ValueError('Full JSON differs from original Java')
 report={'source':path.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'version':doc['Version'],'servers':len(doc['Servers']),'networks':{k:len(doc[k]) for k in ('HTTPNetworks','DirectNetworks','DNSNetworks','UDPNetworks','SSLNetworks') if k in doc},'fields':len(items),'uniqueFields':len(unique),'completeJavaEqual':True}
 if runtime:
  from cloud.workers.python.engine import decode_provider_catalog
  worker=decode_provider_catalog('zig-tunnel',data)
  if worker['structuredJson']!=doc or json.loads(worker['rawText'])!=doc:raise ValueError('Full worker differs')
  report['completeWorkerEqual']=True;report['rawBytes']=len(worker['rawText'].encode())
 return doc,report
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('catalog',type=Path);p.add_argument('--runtime',action='store_true');a=p.parse_args();_,r=verify(a.catalog,a.runtime);print(json.dumps(r))
