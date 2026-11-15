"""Inspect public access-ID wrapping metadata; never attempts private-key recovery."""
import argparse,base64,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.HTTP_Custom.codec import open_envelope
from Crypto.PublicKey import RSA

def b64(value):return base64.urlsafe_b64decode(value+'='*((-len(value))%4))

def inspect(data,access_id=None):
    env=open_envelope(data)
    if env.get('b')!=9:raise ValueError('Not an access wrapper')
    wrapped=json.loads(b64(env['c']));header=json.loads(b64(wrapped['h']))
    recipients=[]
    for item in header['r']:
        segments=item['c'].split('.')
        if len(segments)!=2:raise ValueError('Unrecognized signed public certificate')
        certificate=json.loads(b64(segments[0]))
        key=RSA.import_key(b64(certificate['p']))
        recipients.append({'public_key_bits':key.size_in_bits(),
          'private_key_present':key.has_private(),
          'wrapped_key_bytes':len(b64(item['w'])),
          'certificate_signature_bytes':len(b64(segments[1])),
          'provided_access_id_matches':None if access_id is None else certificate['id']==access_id})
    return {'sha256':hashlib.sha256(data).hexdigest(),'schema':9,'build':header['n'],
            'recipients':recipients,'section_count':len(wrapped.get('j',[])),
            'certificate_signature_verified':False,'payload_decrypted':False}

def main():
    p=argparse.ArgumentParser();p.add_argument('file',type=Path);p.add_argument('--access-id-stdin',action='store_true');a=p.parse_args()
    access_id=sys.stdin.read().strip() if a.access_id_stdin else None
    print(json.dumps(inspect(a.file.read_bytes(),access_id),indent=2))

if __name__=='__main__':main()
