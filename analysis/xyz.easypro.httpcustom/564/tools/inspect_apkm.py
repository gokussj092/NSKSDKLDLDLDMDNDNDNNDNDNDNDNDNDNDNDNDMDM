"""Inventory authorized APKM and verify identity from binary AndroidManifest."""
import argparse,hashlib,json,struct,zipfile
from pathlib import Path

def manifest_identity(blob):
    strings=[];pos=8
    while pos+8<=len(blob):
        kind,header,size=struct.unpack_from('<HHI',blob,pos)
        assert size>=header>=8 and pos+size<=len(blob)
        if kind==1:
            count,styles,flags,start,_=struct.unpack_from('<IIIII',blob,pos+8)
            offsets=struct.unpack_from('<'+'I'*count,blob,pos+header)
            def length(at,utf8):
                if utf8:
                    n=blob[at];return (((n&127)<<8)|blob[at+1],at+2)if n&128 else(n,at+1)
                n=struct.unpack_from('<H',blob,at)[0]
                return (((n&32767)<<16)|struct.unpack_from('<H',blob,at+2)[0],at+4)if n&32768 else(n,at+2)
            for off in offsets:
                at=pos+start+off
                if flags&0x100:
                    _,at=length(at,True);n,at=length(at,True);strings.append(blob[at:at+n].decode('utf-8'))
                else:
                    n,at=length(at,False);strings.append(blob[at:at+n*2].decode('utf-16le'))
        elif kind==0x102:
            ns,name,attr_start,attr_size,count=struct.unpack_from('<IIHHH',blob,pos+16)
            if strings[name]=='manifest':
                result={}
                for i in range(count):
                    at=pos+16+attr_start+i*attr_size
                    ns,key,raw,sz,res0,typ,value=struct.unpack_from('<IIIHBBI',blob,at)
                    label=strings[key]
                    if label in ('package','versionCode','versionName'):
                        result[label]=strings[value]if typ==3 else value
                return result
        pos+=size
    raise ValueError('No binary manifest identity')

def main():
    p=argparse.ArgumentParser();p.add_argument('apkm',type=Path);p.add_argument('--output',type=Path)
    a=p.parse_args();report={'archive_sha256':hashlib.sha256(a.apkm.read_bytes()).hexdigest(),'apks':[]}
    with zipfile.ZipFile(a.apkm)as z:
        info=json.loads(z.read('info.json'));report['distribution_metadata']={k:info.get(k)for k in('pname','release_version','versioncode','min_api','arches')}
        for name in z.namelist():
            if not name.endswith('.apk'):continue
            data=z.read(name)
            import io
            with zipfile.ZipFile(io.BytesIO(data))as apk:
                item={'name':name,'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),
                      'identity':manifest_identity(apk.read('AndroidManifest.xml')),
                      'native_libraries':[]}
                for n in apk.namelist():
                    if n.endswith('.so'):
                        b=apk.read(n);item['native_libraries'].append({'name':n,'size':len(b),'sha256':hashlib.sha256(b).hexdigest()})
                report['apks'].append(item)
    text=json.dumps(report,indent=2)+'\n'
    if a.output:a.output.write_text(text)
    print(text)
if __name__=='__main__':main()
