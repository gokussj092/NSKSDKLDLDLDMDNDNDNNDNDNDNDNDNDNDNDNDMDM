#!/usr/bin/env python3
"""Fixed build16 native POST recipe, retaining ciphertext only in private output."""
import argparse,hashlib,json,os
from pathlib import Path
from urllib.request import Request,HTTPRedirectHandler,build_opener
SOURCE="https://strongteam.co/api/wolfcustomv2/"
BODY=b"hash=xsandokUpdatex"
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError("REDIRECT_DENIED")
def download():
    headers={"User-Agent":"Go-http-client/1.1","Content-Type":"application/x-www-form-urlencoded","Accept-Encoding":"identity"}
    with build_opener(NoRedirect()).open(Request(SOURCE,data=BODY,headers=headers,method="POST"),timeout=30) as response:
        if response.status!=200 or response.headers.get("Content-Encoding","identity")!="identity":raise ValueError("INVALID_RESPONSE")
        data=response.read(8*1024*1024+1)
    if not data or len(data)>8*1024*1024 or data.lstrip().startswith(b"<"):raise ValueError("INVALID_CATALOG")
    return data
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);a=p.parse_args();data=download()
    a.output.parent.mkdir(parents=True,exist_ok=True);fd=os.open(a.output,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,"wb") as stream:stream.write(data)
    print(json.dumps({"httpStatus":200,"inputBytes":len(data),"inputSha256":hashlib.sha256(data).hexdigest(),"decryptionPerformed":False}))
if __name__=="__main__":main()

