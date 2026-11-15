#!/usr/bin/env python3
"""Whole JSON: independent JCA HMAC/AES/rotation + host libsodium vs reader/worker."""
import argparse,base64,ctypes as C,ctypes.util,hashlib,json,struct,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
FIELDS=json.loads((ROOT/'decoders/Python/apps/HTTP_FenixVPN/field_names.json').read_text())
PUBLIC=bytes.fromhex('4733a5521e426f82a124adc047e68e486579da747944cfe8d80081b3e2fc92ce')
def java(lines):
    with tempfile.TemporaryDirectory(prefix='speigo-jca-') as folder:
        p=Path(folder)/'commands.tsv';p.write_text(''.join(line+'\n' for line in lines));p.chmod(0o600)
        r=subprocess.run(['java',str(Path(__file__).with_name('SpeigoOracle.java')),str(p)],capture_output=True,timeout=60)
    if r.returncode:raise ValueError('JCA_FAILED')
    out=[base64.b64decode(s,validate=True) for s in r.stdout.splitlines()]
    if len(out)!=len(lines):raise ValueError('JCA_RESULT_COUNT')
    return out
def sodium():
    lib=C.CDLL(ctypes.util.find_library('sodium'));lib.sodium_init()
    lib.crypto_sign_verify_detached.argtypes=[C.c_char_p,C.c_char_p,C.c_ulonglong,C.c_char_p]
    lib.crypto_aead_xchacha20poly1305_ietf_decrypt.argtypes=[C.c_void_p,C.POINTER(C.c_ulonglong),C.c_void_p,C.c_char_p,C.c_ulonglong,C.c_char_p,C.c_ulonglong,C.c_char_p,C.c_char_p]
    return lib
def reference(data,public=PUBLIC):
    if len(data)<84 or data[:5]!=b'SV5C\2':raise ValueError('ORACLE_HEADER')
    purpose=data[5];release,count,size=struct.unpack_from('<III',data,8)
    if release!=112 or purpose not in (1,2):raise ValueError('ORACLE_SOURCE')
    lib=sodium();message=hashlib.sha256(b'SV5C-SIG-V2\0'+data[:-64]+bytes.fromhex('d2f5270a3b6c91e4')).digest()
    if lib.crypto_sign_verify_detached(data[-64:],message,32,public)!=0:raise ValueError('ORACLE_SIGNATURE')
    meta=data[20:20+size];doc=json.loads(meta);mh=hashlib.sha256(meta).digest();section='Servers' if purpose==1 else 'Usuarios';position=20+size
    keys=java(['key\t'+str(purpose)+'\t'+str(i)+'\t'+base64.b64encode(mh).decode() for i in range(count)])
    context=bytes.fromhex('af9d380863dc5c05851192e82d6fda880ce0346f877ab0c093000c7dbe372194');rows=[]
    for i,key in enumerate(keys):
        index,n=struct.unpack_from('<II',data,position)
        if index!=i or n<=0 or position+48+n>len(data)-64:raise ValueError('ORACLE_BOUNDS')
        aad=data[:20]+mh+bytes.fromhex('38d6e952af04b17b')+struct.pack('<III',112,i,n)+bytes([purpose])+context
        plain,actual=C.create_string_buffer(n),C.c_ulonglong()
        if lib.crypto_aead_xchacha20poly1305_ietf_decrypt(plain,C.byref(actual),None,data[position+32:position+48+n],n+16,aad,len(aad),data[position+8:position+32],key)!=0 or actual.value!=n:raise ValueError('ORACLE_RECORD_TAG')
        record=json.loads(plain.raw)
        if any(record[k]!=v for k,v in doc[section][i].items() if k in record):raise ValueError('ORACLE_METADATA_CONFLICT')
        rows.append({**doc[section][i],**record});position+=48+n
    if position!=len(data)-64:raise ValueError('ORACLE_TRAILING')
    fields=set(FIELDS['servers' if purpose==1 else 'users']);pending=[(r,k) for r in rows for k in sorted(fields.intersection(r))]
    for (row,k),plain in zip(pending,java(['field\t'+base64.b64encode(row[k].encode()).decode() for row,k in pending])):row[k]=plain.decode('utf-8')
    doc[section]=rows;return doc,len(pending)
def verify(path,worker=False):
    from decoders.Python.apps.SpeiGo_VPN import codec
    data=Path(path).read_bytes();purpose=data[5];expected,n=reference(data);actual=codec.decode_catalog(data,purpose)
    if actual!=expected:raise ValueError('WHOLE_JSON_MISMATCH')
    result={'inputBytes':len(data),'inputSha256':hashlib.sha256(data).hexdigest(),'purpose':purpose,'section':'Servers' if purpose==1 else 'Usuarios','version':actual['Version'],'records':len(actual['Servers' if purpose==1 else 'Usuarios']),'innerFieldsCompared':n,'wholeIndependentJcaSodiumParity':True,'signatureAndAllTagsVerified':True,'clearJsonSha256':hashlib.sha256(json.dumps(actual,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest(),'rawOutputBytes':len(codec.render(actual).encode()),'apkCodeExecuted':False}
    if worker:
        from cloud.workers.python.engine import decode_provider_catalog,DecodeFailure
        provider='speigo-vpn-configs' if purpose==1 else 'speigo-vpn-ssh';r=decode_provider_catalog(provider,data)
        if r['structuredJson']!=expected or json.loads(r['rawText'])!=expected or r['isPartial'] is not False:raise ValueError('WHOLE_WORKER_MISMATCH')
        try:decode_provider_catalog('speigo-vpn-ssh' if purpose==1 else 'speigo-vpn-configs',data)
        except DecodeFailure:pass
        else:raise ValueError('WORKER_ACCEPTED_WRONG_SECTION')
        result['wholeWorkerParity']=True;result['workerRejectsOppositeSection']=True
        script=ROOT/'decoders/Python/apps/SpeiGo_VPN'/('server_catalog_decoder.py' if purpose==1 else 'ssh_catalog_decoder.py')
        with tempfile.TemporaryDirectory() as cwd:
            r=subprocess.run([sys.executable,str(script),'--stdin'],input=data,cwd=cwd,capture_output=True,timeout=30)
        if r.returncode or json.loads(r.stdout)!=expected:raise ValueError('WHOLE_CLI_MISMATCH')
        result['wholeCliOutsideCheckoutParity']=True
    return result
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('catalog',type=Path);p.add_argument('--worker',action='store_true');p.add_argument('--report',type=Path);a=p.parse_args();r=verify(a.catalog,a.worker)
    if a.report:a.report.write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps(r))
