#!/usr/bin/env python3
"""Whole-document JCA/Python/CLI/worker verification, including every known GCM field."""
import argparse,json,hashlib,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from recover import oracle
from decoders.Python.apps.HTTP_Conexion import codec,server_catalog_decoder as catalog
HERE=Path(__file__).resolve().parents[1]
FIELDS=json.loads((HERE/'generated/protected-fields.json').read_text())
def reference(data,password,key):
    doc=json.loads(oracle('O',password,[data])[0]);found={};count=0
    for row in doc['Servers']:
        for name in FIELDS:
            value=row.get(name)
            if value not in (None,''):found[value]=None;count+=1
    values=list(found);opened=oracle('F',key,[v.encode() for v in values]) if values else []
    mapping=dict(zip(values,[v.decode('utf-8') for v in opened]))
    for row in doc['Servers']:
        for name in FIELDS:
            if row.get(name) not in (None,''):row[name]=mapping[row[name]]
    return doc,count,len(values)
def verify(path,recipe,out,worker=True):
    data=path.read_bytes();raw,password=codec.unpack_catalog(data)
    expected,count,unique=reference(raw,password if password is not None else recipe['password'].encode(),recipe['field_key'].encode())
    actual=json.loads(catalog.run(data));assert actual==expected,'Entire Python/JCA document differs'
    done=subprocess.run([sys.executable,str(ROOT/'decoders/Python/apps/HTTP_Conexion/server_catalog_decoder.py'),str(path.resolve())],
      capture_output=True,check=True,timeout=45)
    assert json.loads(done.stdout)==expected,'Entire CLI document differs'
    reports=[('.json',actual)]
    if worker:
        from cloud.workers.python.engine import decode_provider_catalog
        result=decode_provider_catalog('http-conexion',data)
        assert result['structuredJson']==expected and json.loads(result['rawText'])==expected and not result['isPartial']
        reports.append(('.worker.json',result))
    for suffix,value in reports:
        f=out/(path.stem+suffix);f.touch(mode=0o600,exist_ok=True);f.chmod(0o600);f.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
    return {'source':path.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
      'version':actual['Version'],'servers':len(actual['Servers']),'gcm_fields':count,'unique_gcm_fields':unique,
      'whole_jca_equal':True,'whole_cli_equal':True,'whole_worker_equal':worker}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);p.add_argument('catalogs',nargs='+',type=Path)
    p.add_argument('--download',action='store_true');p.add_argument('--no-worker',action='store_true');a=p.parse_args()
    recipe=json.loads((a.private/'recipe.json').read_text());assert codec.FIELD_KEY==recipe['field_key'].encode()
    out=a.private/'verified';out.mkdir(parents=True,exist_ok=True,mode=0o700);paths=a.catalogs
    if a.download:
        f=out/'downloaded.enc';f.touch(mode=0o600,exist_ok=True);f.chmod(0o600);f.write_bytes(catalog.download());paths.append(f)
    results=[verify(path,recipe,out,not a.no_worker) for path in paths]
    (out/'summary.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results))
if __name__=='__main__':main()
