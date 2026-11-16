"""HC2 public-ID derivation and recipient RSA unwrap observed in original build 934.

Generating a keypair is NOT registration. No issuer certificate, activation
grant, attestation or private key of another installation is manufactured.
The unwrap primitive does not claim that the whole HC payload is decoded.
"""
import argparse,base64,hashlib,hmac,json,os,sys,importlib.util
from pathlib import Path
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1,SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature.pss import MGF1

def b64u(data):return base64.urlsafe_b64encode(data).decode().rstrip('=')
def unb64u(data):
    if not isinstance(data,str) or len(data)>2*1024*1024:raise ValueError('Invalid base64url input')
    return base64.b64decode(data+'='*((-len(data))%4),altchars=b'-_',validate=True)
def access_id(public):
    key=RSA.import_key(public) if isinstance(public,(bytes,str)) else public
    return 'HC2-'+b64u(hashlib.sha256(key.public_key().export_key(format='DER')).digest())
def write_private(path,data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(data)
def generate(directory):
    directory=Path(directory);directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    key=RSA.generate(2048);public=key.public_key().export_key(format='DER')
    descriptor={'schema':'spdecode.httpcustom.hc2.identity.v1','access_id':access_id(key),
      'public_spki_base64url':b64u(public),'rsa_bits':2048,'registration_status':'UNREGISTERED',
      'issuer_certificate':None,'opens_other_recipients_files':False}
    write_private(directory/'private-key.pem',key.export_key(pkcs=8))
    write_private(directory/'public-key.der',public)
    write_private(directory/'identity.json',json.dumps(descriptor,indent=2).encode())
    return descriptor
def unwrap_header(header,private,passphrase=None):
    key=RSA.import_key(private,passphrase=passphrase)
    if not key.has_private():raise ValueError('RECIPIENT_PRIVATE_KEY_REQUIRED')
    ident=access_id(key);public=key.public_key().export_key(format='DER')
    recipients=header.get('r')
    if not isinstance(recipients,list) or not 0<len(recipients)<=100:raise ValueError('INVALID_RECIPIENTS')
    for recipient in recipients:
        token=recipient.get('c')
        if not isinstance(token,str) or token.count('.')!=1:raise ValueError('INVALID_RECIPIENT_CERTIFICATE')
        payload,signature=token.split('.')
        certificate=json.loads(unb64u(payload))
        if certificate.get('id')!=ident:continue
        supplied=RSA.import_key(unb64u(certificate['p']))
        if supplied.has_private() or not hmac.compare_digest(supplied.export_key(format='DER'),public):
            raise ValueError('RECIPIENT_PUBLIC_KEY_MISMATCH')
        wrapped=unb64u(recipient['w'])
        if len(wrapped)!=key.size_in_bytes():raise ValueError('INVALID_RSA_WRAPPED_KEY_SIZE')
        # Captured from E553... initializer: SHA-256, MGF1ParameterSpec.SHA1,
        # PSource.PSpecified.DEFAULT (empty label), not the library default.
        cipher=PKCS1_OAEP.new(key,hashAlgo=SHA256,mgfunc=lambda seed,length:MGF1(seed,length,SHA1),label=b'')
        value=cipher.decrypt(wrapped)
        if len(value)!=32:raise ValueError('INVALID_CONTENT_KEY_SIZE')
        return value,{'recipient_key_matches':True,'issuer_signature_verified':False,
                      'payload_decrypted':False,'primitive':'RSA-OAEP-SHA256-MGF1-SHA1'}
    raise ValueError('PRIVATE_KEY_IS_NOT_A_RECIPIENT')
def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    g=sub.add_parser('generate');g.add_argument('directory',type=Path)
    u=sub.add_parser('unwrap');u.add_argument('hc_file',type=Path);u.add_argument('private_key',type=Path);u.add_argument('key_output',type=Path)
    u.add_argument('--reader',type=Path,default=Path(__file__).with_name('HttpCustom_934_revisado.py'))
    a=p.parse_args()
    if a.command=='generate':
        result=generate(a.directory);print(json.dumps({'generated':True,'registration_status':result['registration_status']}));return
    root=Path(__file__).resolve().parents[4];sys.path.insert(0,str(root))
    try:
        from decoders.Python.apps.HTTP_Custom.codec import open_envelope
    except ImportError:
        spec=importlib.util.spec_from_file_location('hc_reader',a.reader)
        reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
        def open_envelope(data):
            if not isinstance(data,bytes) or not 40<=len(data)<=16*1024*1024:raise ValueError('INVALID_FILE_SIZE')
            for logical in reader._carrier_candidates(data):
                try:
                    raw=reader._xchacha20poly1305_decrypt(reader._v4_outer_key(),logical[:24],reader.V4_OUTER_AAD,logical[24:])
                    value=json.loads(raw.decode())
                    if value.get('a')!='HCCFG':raise ValueError('INVALID_ENVELOPE')
                    return value
                except (ValueError,UnicodeError):pass
            raise ValueError('HCX4_AUTHENTICATION_FAILED')
    env=open_envelope(a.hc_file.read_bytes())
    if env.get('b')!=9:raise ValueError('NOT_ACCESS_WRAPPER_9')
    wrapper=json.loads(unb64u(env['c']));header=json.loads(unb64u(wrapper['h']))
    value,metadata=unwrap_header(header,a.private_key.read_bytes())
    write_private(a.key_output,value);print(json.dumps(metadata))
if __name__=='__main__':main()
