#!/usr/bin/env python3
"""Check the traced SV5C primitive against private captures; metadata only."""
import argparse,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.SuperFlash_VPN import codec as wire
def check(folder):
    folder=Path(folder);m=json.loads((folder/'native-material.json').read_text());results={}
    for name in ['configs','ssh','embedded-configs','embedded-ssh']:
        raw=(folder/(name+'.bin')).read_bytes()
        doc=wire.decode_sv5c(raw,release_code=m['release'],signature_key=bytes.fromhex(m['signaturePublicKey']),root_key=bytes.fromhex(m['root']),context=bytes.fromhex(m['context']))
        section='Servers' if raw[5]==1 else 'Usuarios';fields=wire.SERVER_FIELDS if raw[5]==1 else wire.USER_FIELDS
        results[name]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'version':doc['Version'],'section':section,'records':len(doc[section]),'knownFields':sum(len(fields.intersection(row)) for row in doc[section]),'clearJsonSha256':hashlib.sha256(json.dumps(doc,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest(),'signatureAndAllRecordTagsVerified':True}
    (folder/'wire-proof.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();check(a.private)
