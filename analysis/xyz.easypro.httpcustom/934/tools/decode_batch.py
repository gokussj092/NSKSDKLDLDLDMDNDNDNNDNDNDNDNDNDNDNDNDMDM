"""Private full-result batch runner for the explicitly provided HC reader.

Credentials are JSON on stdin. Results retain the main configuration, all
eleven profile fields, unknown options and optional sidecars. No cleartext or
credentials go to stdout. Unsupported cases produce explicit per-file errors.
"""
import argparse,base64,hashlib,importlib.util,json,os
from pathlib import Path
import sys

def write_private(path,data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(data)

def decode(reader,raw,auth):
    env,main,sections=reader._decrypt_parts_v4(raw,**auth)
    result={'format':{k:env.get(k) for k in ('a','b','c','d','e','f','h','n')},
            'main_config':json.loads(main.decode()),'profiles':[],'other_sections':[]}
    for label,plain,sidecar in sections:
        if plain.startswith(b'HPC1'):
            # Preserve options_text too, rather than losing original formatting.
            fields=reader._HPC1Reader(plain)
            if fields.take(4)!=b'HPC1' or fields.u32()!=11:raise ValueError('Invalid HPC1')
            name,protocol,host=fields.text(),fields.text(),fields.text()
            port=fields.u32();username,password,payload=fields.text(),fields.text(),fields.text()
            options_text=fields.text();flags,updated,mode=fields.u32(),fields.u64(),fields.text()
            if fields.offset!=len(plain):raise ValueError('HPC1 trailing bytes')
            try:options=json.loads(options_text) if options_text else {}
            except ValueError:options=options_text
            profile=dict(label=label,name=name,protocol=protocol,host=host,port=port,
                username=username,password=password,payload=payload,options=options,
                flags=flags,updated_at_ms=updated,mode=mode)
            if sidecar is not None:
                try:profile['custom_payload_sidecar']=sidecar.decode()
                except UnicodeError:profile['custom_payload_sidecar_base64']=base64.b64encode(sidecar).decode()
            result['profiles'].append(profile)
        else:
            try:
                content=plain.decode()
                try:content=json.loads(content)
                except ValueError:pass
            except UnicodeError:content={'base64':base64.b64encode(plain).decode()}
            item={'label':label,'content':content}
            if sidecar is not None:item['sidecar_base64']=base64.b64encode(sidecar).decode()
            result['other_sections'].append(item)
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--reader',type=Path,default=Path(__file__).with_name('HttpCustom_934_revisado.py'))
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('files',type=Path,nargs='+');a=p.parse_args()
    auth=json.load(sys.stdin)
    if set(auth)-{'password','hwid'}:raise ValueError('Unexpected auth members')
    spec=importlib.util.spec_from_file_location('hc_reader',a.reader)
    reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
    a.output.mkdir(mode=0o700,parents=True,exist_ok=True)
    report=[]
    for path in a.files:
        raw=path.read_bytes();row={'file':path.name,'sha256':hashlib.sha256(raw).hexdigest()}
        try:
            data=decode(reader,raw,auth)
            target=a.output/(path.stem+'.json')
            encoded=json.dumps(data,ensure_ascii=False,indent=2).encode()
            write_private(target,encoded)
            row.update(status='AUTHENTICATED',profiles=len(data['profiles']),output=target.name,
                       output_sha256=hashlib.sha256(encoded).hexdigest())
        except Exception as error:row.update(status='PENDING',error_type=type(error).__name__,error=str(error))
        report.append(row)
    write_private(a.output/'batch-status.json',json.dumps(report,ensure_ascii=False,indent=2).encode())
    print(json.dumps({'files':len(report),'authenticated':sum(x['status']=='AUTHENTICATED' for x in report),
                      'pending':sum(x['status']=='PENDING' for x in report)}))

if __name__=='__main__':main()
