#!/usr/bin/env python3
"""Compare whole real docs to independent Java/stdlib oracle, CLI and child worker."""
import argparse,base64,hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT))
from cloud.workers.python.engine import decode_provider_catalog
from decoders.Python.apps.KHAM_VPN.codec import SERVER_FIELDS,NETWORK_FIELDS
PROFILES=[('com.khamvpn.net',24,'kham-vpn','KHAM_VPN'),('thailand.vpn.globalvpn',3,'thailand-vpn','Thailand_VPN')]
def canonical(doc):return json.dumps(doc,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args()
    for package,build,identifier,decoder in PROFILES:
        private=a.private/package;wire=(private/'catalog.wire').read_bytes();count=0
        if identifier=='kham-vpn':
            oracle=json.loads((private/'oracle-outer.json').read_text());places=[]
            for rows,fields in [(oracle['Servers'],SERVER_FIELDS),(oracle['Networks'],NETWORK_FIELDS),([oracle],('setOpenVPN',))]:
                for row in rows:
                    for f in fields:
                        if f in row:places.append((row,f))
            lines='\n'.join(base64.b64encode(row[f].encode()).decode() for row,f in places)+'\n'
            result=subprocess.run(['java',str(Path(__file__).with_name('FieldOracle.java'))],input=lines,text=True,capture_output=True,check=True,timeout=60)
            values=result.stdout.splitlines();assert len(values)==len(places)
            for (row,f),v in zip(places,values):row[f]=base64.b64decode(v).decode()
            count=len(places)
        else:oracle=json.loads(base64.b64decode(wire))
        worker=decode_provider_catalog(identifier,wire);assert worker['structuredJson']==oracle
        assert json.loads(worker['rawText'])==oracle and worker['isPartial'] is False
        for mode in ('file','stdin'):
            args=[sys.executable,str(ROOT/'decoders/Python/apps'/decoder/'server_catalog_decoder.py')]
            args+=['--stdin'] if mode=='stdin' else [str(private/'catalog.wire')]
            r=subprocess.run(args,input=wire if mode=='stdin' else None,capture_output=True,check=True,timeout=60)
            assert json.loads(r.stdout)==oracle
        (private/'worker-result.json').write_text(json.dumps(worker))
        proof=dict(status='VERIFIED_REAL',wireBytes=len(wire),wireSha256=hashlib.sha256(wire).hexdigest(),
          completeDocumentSha256=hashlib.sha256(canonical(oracle)).hexdigest(),serverCount=len(oracle['Servers']),
          networkCount=len(oracle.get('Networks',[])),javaFieldsCompared=count,workerEqualsReference=True,
          cliFileEqualsReference=True,cliStdinEqualsReference=True,isPartial=False)
        target=ROOT/'analysis'/package/str(build)/'generated';target.mkdir(parents=True,exist_ok=True)
        (target/'validation.json').write_text(json.dumps(proof,indent=2)+'\n');print(identifier,json.dumps(proof))
