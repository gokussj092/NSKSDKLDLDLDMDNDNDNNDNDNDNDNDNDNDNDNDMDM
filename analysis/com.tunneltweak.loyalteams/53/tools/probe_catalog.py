#!/usr/bin/env python3
"""Fixed build53 public updater probe; preserve ciphertext only in private output."""
import argparse,hashlib,json,os
from pathlib import Path
from urllib.request import Request,HTTPRedirectHandler,build_opener
from urllib.error import HTTPError
URL="https://tunneltweak.com/api/servers"
HEADERS={"User-Agent":"TunnelTweak/1.0 (Android)","ngrok-skip-browser-warning":"true",
         "x-app-version":"53","x-cfg-keyed":"1","Accept-Encoding":"identity"}
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError("REDIRECT_DENIED")
def download():
    with build_opener(NoRedirect()).open(Request(URL,headers=HEADERS),timeout=25) as response:
        if response.status!=200 or response.headers.get("Content-Encoding","identity")!="identity":raise ValueError("INVALID_RESPONSE")
        data=response.read(8*1024*1024+1)
    if not data or len(data)>8*1024*1024 or data.lstrip().startswith(b"<"):raise ValueError("INVALID_CATALOG")
    return data
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);args=p.parse_args()
    try:data=download()
    except HTTPError as e:
        print(json.dumps({"status":"pending","httpStatus":e.code}));return 1
    args.output.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(args.output,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,"wb") as stream:stream.write(data)
    obj=json.loads(data)
    print(json.dumps({"httpStatus":200,"inputBytes":len(data),"inputSha256":hashlib.sha256(data).hexdigest(),
        "outerFields":sorted(obj),"decryptionPerformed":False}))
    return 0
if __name__=="__main__":raise SystemExit(main())

