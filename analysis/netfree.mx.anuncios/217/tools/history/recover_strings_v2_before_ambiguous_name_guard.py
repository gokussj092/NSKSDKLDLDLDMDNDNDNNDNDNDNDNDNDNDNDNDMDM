# Reconstructed historical recipe from the preserved conversation; see RESTORE.md.
#!/usr/bin/env python3
"""Offline data-only recovery of rolling-XOR literals; APK/JNI never execute."""
import argparse,hashlib,json,re
from pathlib import Path
def decode(value,seed,a,b):
    raw=bytearray.fromhex(value)
    if not raw:return ''
    raw[0]^=b
    for i in range(1,len(raw)):raw[i]^=raw[i-1]^((seed^a)&255)
    return raw.decode('utf-8')
def main():
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();d=a.private
    out=d/'decoded';out.mkdir(mode=0o700,exist_ok=True);records=[];files=0
    for source in d.glob('jadx*/sources/**/*.java'):
        text=source.read_text();methods={}
        for m in re.finditer(r'public static String (\w+)\(String (r\d+), int (r\d+)\) \{',text):
            body=text[m.end():];end=re.search(r'\n    (?:public|private|protected|static) ',body)
            if end:body=body[:end.start()]
            x=re.search(r'\('+m[3]+r' \^ (\d+)\)',body);arr=re.search(r'byte\[\] (r\d+) = new byte',body)
            y=re.search(r'\('+arr[1]+r'\[0\] \^ (\d+)\)',body) if arr else None
            if x and y:
                pair=int(x[1]),int(y[1])
                methods[m[1]]=pair
        if not methods:continue
        for name,(x,y) in methods.items():
            def replace(m):
                try:value=decode(m[1],int(m[2]),x,y)
                except (ValueError,UnicodeError):return m[0]
                records.append({'path':str(source.relative_to(d)),'function':name,'hex':m[1],'seed':int(m[2]),'rollingXor':x,'firstXor':y,'value':value})
                return json.dumps(value,ensure_ascii=False)
            text=re.sub(r'\b'+name+r'\("([0-9a-f]+)", (-?\d+)\)',replace,text)
        target=out/source.relative_to(d);target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text);target.chmod(0o600);files+=1
    target=d/'strings.json';target.write_text(json.dumps(records,ensure_ascii=False,indent=2));target.chmod(0o600)
    symbols=[]
    for source in (d/'unpacked/extracted').glob('**/*.so'):
        if source.name not in ('libm7z3r1.so','libspeigohcrnative.so'):continue
        b=source.read_bytes();found=[s.decode() for s in re.findall(rb'[\x20-\x7e]{7,}',b) if any(k.lower() in s.lower() for k in [b'Java_',b'JNI_OnLoad',b'SPCF',b'github',b'https',b'speigo',b'aes',b'key',b'config',b'chacha'])]
        symbols.append({'library':source.name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'strings':found})
    target=d/'native-strings.json';target.write_text(json.dumps(symbols,indent=2));target.chmod(0o600)
    report={'decodedFiles':files,'recoveredLiterals':len(records),'nativeLibrariesInspected':len(symbols)}
    (d/'strings-report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
