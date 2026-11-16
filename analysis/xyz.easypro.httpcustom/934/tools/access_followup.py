"""Inspect authenticated access-wrapper structure without printing recipient data."""
import base64,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.HTTP_Custom.codec import open_envelope
from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence

def b64(s):return base64.urlsafe_b64decode(s+'='*((-len(s))%4))
def shape(x):
    if isinstance(x,dict):return {k:shape(v) for k,v in x.items()}
    if isinstance(x,list):return [shape(v) for v in x]
    if isinstance(x,str):
        if len(x)<=24 and x.replace('-','').replace('_','').isalnum():return x
        return {'type':'string','length':len(x)}
    return x
def main():
    raw=Path(sys.argv[1]).read_bytes();e=open_envelope(raw)
    obj=json.loads(b64(e['c']));header=json.loads(b64(obj['h']))
    report={'outer_shape':shape(e),'wrapper_shape':shape(obj),'header_shape':shape(header),'recipients':[]}
    for rec in header['r']:
        cert=json.loads(b64(rec['c'].split('.')[0]));pub=RSA.import_key(b64(cert['p']))
        ident=b64(cert['id'].removeprefix('HC2-'))
        comparisons={}
        for label,key in [('spki',pub.export_key(format='DER')),('pkcs1',DerSequence([pub.n,pub.e]).encode())]:
            comparisons[label]=hashlib.sha256(key).digest()==ident
        report['recipients'].append({'certificate_shape':shape(cert),'id_matches_public_der_sha256':comparisons,'private':pub.has_private()})
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
