"""Run the current file reader and worker on private owner inputs; emit counts only."""
import argparse,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.HTTP_Custom import codec
from cloud.workers.python.engine import decode_file,DecodeFailure

def main():
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--output',type=Path);a=p.parse_args()
    auth=json.load(sys.stdin)
    if set(auth)-{'password','hwid'}:raise ValueError('Unexpected credential field')
    report={'real_files':[],'full_json_authenticated':0}
    for path in sorted(a.directory.glob('*.hc')):
        data=path.read_bytes();item={'name':path.name,'sha256':hashlib.sha256(data).hexdigest()}
        try:
            result=codec.decrypt(data,**auth)
            item.update(status='FULL_JSON_AUTHENTICATED',profiles=len(result['config']))
            report['full_json_authenticated']+=1
        except codec.HCError as error:item.update(status='NOT_DECRYPTED',decoder_error=str(error))
        try:
            worker=decode_file('hc',data,credentials=auth)
            item['worker_status']=worker.get('status');item['worker_error']=worker.get('error')
        except DecodeFailure as error:item['worker_status']='error';item['worker_error']=str(error)
        report['real_files'].append(item)
    text=json.dumps(report,ensure_ascii=False,indent=2)+'\n'
    if a.output:a.output.write_text(text)
    else:print(text,end='')

if __name__=='__main__':main()
