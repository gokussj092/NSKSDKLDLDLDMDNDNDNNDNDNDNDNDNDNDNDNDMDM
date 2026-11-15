#!/usr/bin/env python3
"""Whole real document parity: JCA/Python/CLI file+stdin/isolated paired worker."""
import argparse,json,hashlib,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from census import oracle
from recover import private
from decoders.Python.apps.Speicers_Turbo_VPN import codec,server_catalog_decoder as cli
from cloud.workers.python.engine import decode_provider_catalog
def main():
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);p.add_argument('--download',action='store_true');a=p.parse_args();d=a.private;recipe=json.loads((d/'recipe.json').read_text());assert recipe['remotePassword'].encode()==codec.CATALOG_PASSWORD
    out=d/'verified';out.mkdir(mode=0o700,exist_ok=True);reports=[];pairs=[('included',d/'unpacked/extracted/netfree.mx.anuncios/assets/flags/config.png',d/'unpacked/extracted/netfree.mx.anuncios/assets/flags/usr.png'),('remote',d/'servers.enc',d/'users.enc')]
    if a.download:
        for name in ['servers','users']:private(out/(name+'.enc'),cli.download(users=name=='users'))
        pairs.append(('downloaded',out/'servers.enc',out/'users.enc'))
    for label,servers,users in pairs:
        raw={k:p.read_bytes() for k,p in [('servers',servers),('users',users)]};docs={};counts={}
        for name,data in raw.items():
            doc=json.loads(oracle('O',codec.CATALOG_PASSWORD,[data])[0]);section='Servers' if name=='servers' else 'Usuarios';fields=codec.SERVER_FIELDS if name=='servers' else codec.USER_FIELDS
            values=list(dict.fromkeys(r[k] for r in doc[section] for k in fields&r.keys() if r[k]));opened=oracle('F',recipe['fieldPassword'].encode(),[v.encode() for v in values]);mapping=dict(zip(values,[v.decode() for v in opened]));count=0
            for row in doc[section]:
                for k in fields&row.keys():
                    if row[k]:row[k]=mapping[row[k]];count+=1
            assert codec.decode_catalog(data)==doc;docs[name]=doc;counts[name]={'version':doc['Version'],'rows':len(doc[section]),'encryptedFields':count,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
        bundle=cli.pack_catalogs(raw['servers'],raw['users']);path=out/(label+'.bundle');private(path,bundle);expected={'provider':'speicers-turbo-vpn','complete':True,'catalogs':docs};assert json.loads(cli.run(bundle))==expected
        for args in [[str(path.resolve())],['--stdin']]:
            result=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/Speicers_Turbo_VPN/server_catalog_decoder.py'),*args],input=bundle,capture_output=True,check=True,timeout=45);assert json.loads(result.stdout)==expected
        worker=decode_provider_catalog('speicers-turbo-vpn',bundle);assert worker['structuredJson']==expected and json.loads(worker['rawText'])==expected and not worker['isPartial']
        private(out/(label+'.json'),(json.dumps(expected,ensure_ascii=False,indent=2)+'\n').encode());private(out/(label+'.worker.json'),(json.dumps(worker,ensure_ascii=False,indent=2)+'\n').encode());reports.append({'source':label,'catalogs':counts,'wholeJcaEqual':True,'wholeCliFileAndStdinEqual':True,'wholeWorkerEqual':True})
    (out/'summary.json').write_text(json.dumps(reports,indent=2)+'\n');print(json.dumps(reports))
if __name__=='__main__':main()
