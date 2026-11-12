#!/usr/bin/env python3
"""Retry the owner-provided MediaFire page via curl; never mistake HTML for APK.
Original invocation was inline Python on 2026-11-04; preserved unchanged here.
"""
from pathlib import Path
import subprocess,json,hashlib,re
p=Path('private/hexcustom/retry-20261104');p.mkdir(parents=True,exist_ok=True,mode=0o700)
u='https://www.mediafire.com/file/ypaiywpzrvslef1/Hex+Custom.apk/file'
r=subprocess.run(['curl','-sS','-L','--fail','--max-time','40','-A','Mozilla/5.0','-D',str(p/'headers.txt'),'-o',str(p/'page.html'),'-w','%{http_code} %{content_type} %{size_download}',u],capture_output=True,text=True)
b=(p/'page.html').read_bytes() if (p/'page.html').exists() else b''
links=re.findall(rb'https://download[^\s"<>]+',b)
print(json.dumps({'curlExit':r.returncode,'response':r.stdout,'error':r.stderr,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'title':re.findall(rb'<title>(.*?)</title>',b),'directLinks':links},default=lambda x:x.decode('utf-8','replace')))
