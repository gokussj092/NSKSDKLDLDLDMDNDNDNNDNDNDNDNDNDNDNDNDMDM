"""Local public/private recipient demonstration. NOT an HTTP Custom HC2 identity.

The public ID names a public key; RSA-OAEP wraps a random AES-GCM content key.
An HTTP Custom registered certificate/activation is deliberately not simulated.
"""
import argparse,base64,hashlib,json,os
from pathlib import Path
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

SCHEMA='spdecode.recipient.lab.v1'
def enc(b):return base64.b64encode(b).decode()
def dec(s):return base64.b64decode(s,validate=True)
def public_id(key):
    digest=hashlib.sha256(key.public_key().export_key(format='DER')).digest()
    return 'SPHC-LAB-'+base64.urlsafe_b64encode(digest).decode().rstrip('=')
def public_record(key):
    return {'schema':SCHEMA,'id':public_id(key),'public_spki_base64':enc(key.public_key().export_key(format='DER')),
            'http_custom_registered':False}
def seal(public,config):
    key=RSA.import_key(dec(public['public_spki_base64']))
    if key.has_private() or public['schema']!=SCHEMA or public['id']!=public_id(key):raise ValueError('Invalid public identity')
    content_key=os.urandom(32);nonce=os.urandom(12)
    aad=(SCHEMA+'|'+public['id']).encode()
    cipher=AES.new(content_key,AES.MODE_GCM,nonce=nonce);cipher.update(aad)
    ct,tag=cipher.encrypt_and_digest(json.dumps(config,ensure_ascii=False,separators=(',',':')).encode())
    return {'schema':SCHEMA,'recipient_id':public['id'],'nonce':enc(nonce),'ciphertext':enc(ct),'tag':enc(tag),
            'wrapped_key':enc(PKCS1_OAEP.new(key,hashAlgo=SHA256,label=SCHEMA.encode()).encrypt(content_key)),
            'http_custom_compatible':False}
def unseal(private,wrapped):
    key=RSA.import_key(private)
    if not key.has_private():raise ValueError('Recipient private key required')
    if wrapped['schema']!=SCHEMA or wrapped['recipient_id']!=public_id(key):raise ValueError('Wrong recipient')
    secret=PKCS1_OAEP.new(key,hashAlgo=SHA256,label=SCHEMA.encode()).decrypt(dec(wrapped['wrapped_key']))
    cipher=AES.new(secret,AES.MODE_GCM,nonce=dec(wrapped['nonce']))
    cipher.update((SCHEMA+'|'+wrapped['recipient_id']).encode())
    return json.loads(cipher.decrypt_and_verify(dec(wrapped['ciphertext']),dec(wrapped['tag'])))
def write(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:f.write(value)
def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    g=sub.add_parser('create');g.add_argument('directory',type=Path)
    d=sub.add_parser('open');d.add_argument('private_key',type=Path);d.add_argument('file',type=Path);d.add_argument('output',type=Path)
    a=p.parse_args()
    if a.command=='create':
        a.directory.mkdir(mode=0o700,parents=True,exist_ok=True);key=RSA.generate(2048)
        pub=public_record(key)
        sample={'name':'SP-DECODE recipient lab','server':'example.org','port':22,'note':'Synthetic; no real account or VPN connection'}
        wrapped=seal(pub,sample)
        assert unseal(key.export_key(pkcs=8),wrapped)==sample
        write(a.directory/'public-id.json',json.dumps(pub,indent=2).encode())
        write(a.directory/'private-key.pem',key.export_key(pkcs=8))
        write(a.directory/'example.spdecode-lab.json',json.dumps(wrapped,indent=2).encode())
        print('Local keypair and authenticated synthetic file created. HTTP Custom registration: NOT DONE.')
    else:
        value=unseal(a.private_key.read_bytes(),json.loads(a.file.read_text()))
        write(a.output,json.dumps(value,ensure_ascii=False,indent=2).encode())
        print('Synthetic config authenticated and saved.')
if __name__=='__main__':main()
