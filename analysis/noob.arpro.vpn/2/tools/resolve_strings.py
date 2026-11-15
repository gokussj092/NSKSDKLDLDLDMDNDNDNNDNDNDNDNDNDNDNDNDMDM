#!/usr/bin/env python3
"""Resolve this build's P60 literal arrays offline to private Java sources."""
import argparse,base64,json,re,subprocess
from pathlib import Path
PATTERN=re.compile(r'new P60\(new long\[\]\{([0-9L,\s-]+)\}\)\.toString\(\)')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('sources',type=Path);p.add_argument('private_output',type=Path);a=p.parse_args()
    if a.private_output.exists() and any(a.private_output.iterdir()):p.error('Output must be empty')
    a.private_output.mkdir(parents=True,mode=0o700,exist_ok=True)
    found=[];files=[]
    for path in a.sources.rglob('*.java'):
        text=path.read_text();matches=list(PATTERN.finditer(text))
        if matches:files.append((path,text,matches));found.extend(m.group(1).replace('L','') for m in matches)
    result=subprocess.run(['java',str(Path(__file__).with_name('StringOracle.java'))],input='\n'.join(found)+'\n',
        text=True,capture_output=True,check=True,timeout=60)
    decoded=[base64.b64decode(s).decode('utf-8') for s in result.stdout.splitlines()];assert len(decoded)==len(found)
    cursor=0
    for path,text,matches in files:
        strings=iter(decoded[cursor:cursor+len(matches)]);cursor+=len(matches)
        out=PATTERN.sub(lambda m:json.dumps(next(strings),ensure_ascii=True),text)
        target=a.private_output/path.relative_to(a.sources);target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        target.write_text(out);target.chmod(0o600)
    print(json.dumps({'literal_arrays':len(found),'sources':len(files),'oracle':'JDK Random; no APK/JNI execution'}))
if __name__=='__main__':main()
