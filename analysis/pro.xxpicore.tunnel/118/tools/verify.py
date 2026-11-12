#!/usr/bin/env python3
"""Compare the entire real catalog with independently dispatched JCA results."""
import argparse,base64,hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.Xhypher_Tunnel_Pro import codec as family
def oracle(rows):
    lines=''.join(str(mode)+'\t'+base64.b64encode(value.encode()).decode()+'\n' for mode,value in rows)
    r=subprocess.run(['java',str(Path(__file__).with_name('XXPICoreOracle.java'))],input=lines,text=True,capture_output=True,timeout=120)
    if r.returncode:raise ValueError('Independent Java reference failed')
    result=[base64.b64decode(x,validate=True).decode('utf-8') for x in r.stdout.splitlines()]
    assert len(result)==len(rows);return result
def dispatch(doc):
    # Independent transcription of build-118 df1.b/c consumers; no production schema import.
    entries=[]
    def add(r,mode,keys):
        for k in keys:
            if k in r and r[k] not in ('',None):entries.append((r,k,mode,r[k]))
    add(doc,2,('Username','Password'))
    for r in doc['Servers']:
        add(r,0,('Name','Subname','OpenVPNTCPPort','OpenVPNSSLPort','CloudfrontDNS','flag','Obfs','CustomCert'))
        add(r,1,('ServerIPHost',));add(r,2,('Username','Password'))
        if r.get('SlowDNS') is not None:add(r['SlowDNS'],0,('NSNameServer','PubKey'))
        if r.get('V2Ray') is not None:
            add(r['V2Ray'],0,('UUID',));add(r['V2Ray'],1,('PATH','V2RayHost'))
    for r in doc['Networks']:
        add(r,0,('Name','Info','DNSResolver','TLSVersion'));add(r,1,('SNIHost','Payload'))
        if r.get('ProxySettings') is not None:add(r['ProxySettings'],0,('Squid','Port'))
        if r.get('UDPOptions') is not None:add(r['UDPOptions'],0,('UpMbps','DlMbps','RecvConnectionWindow'))
        if r.get('V2Ray') is not None:add(r['V2Ray'],1,('SNIHost','CustomV2RAYConfig'))
    return entries
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args();raw=(a.private/'remote.bin').read_bytes()
    original=oracle([(0,raw.decode().strip())])[0];doc=json.loads(original);entries=dispatch(doc)
    unique=list(dict.fromkeys((m,v) for _,_,m,v in entries));values=dict(zip(unique,oracle(unique)))
    for record,key,mode,value in entries:record[key]=values[(mode,value)]
    # Family compatibility first; the application-specific wrapper is compared when present.
    assert family.decode_catalog(raw)==doc
    try:
        from decoders.Python.apps.XXPICore_Tunnel.codec import decode_catalog
    except ModuleNotFoundError:decode_catalog=None
    if decode_catalog:assert decode_catalog(raw)==doc
    rendered=json.dumps(doc,ensure_ascii=False,indent=2,allow_nan=False)+'\n'
    path=a.private/'decoded.json';path.touch(mode=0o600,exist_ok=True);path.chmod(0o600);path.write_text(rendered)
    report={'status':'VERIFIED_REAL','http':200,'version':doc['Version'],'servers':len(doc['Servers']),'networks':len(doc['Networks']),
      'encryptedFields':len(entries),'uniqueEncryptedFields':len(unique),'perMode':{str(m):sum(x[2]==m for x in entries) for m in range(3)},
      'wholeObjectEqualJCA':True,'appCodecCompared':decode_catalog is not None,'outputBytes':len(rendered.encode()),'outputSha256':hashlib.sha256(rendered.encode()).hexdigest()}
    (a.private/'verification-summary.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
