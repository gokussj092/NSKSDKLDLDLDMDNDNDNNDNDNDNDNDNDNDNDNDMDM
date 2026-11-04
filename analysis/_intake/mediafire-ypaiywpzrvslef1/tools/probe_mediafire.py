#!/usr/bin/env python3
"""Record the failed public acquisition without mistaking HTML for an APK.

--existing imports the three responses already obtained by curl/urllib.
Without it, repeats only the same three fixed public URLs through normal TLS.
No proxy bypass, login, CAPTCHA, app execution or arbitrary URL input.
"""
import argparse,datetime,hashlib,json,zipfile,io
from pathlib import Path
from urllib.request import Request,urlopen
URLS={
 'mediafire.html':'https://www.mediafire.com/file/ypaiywpzrvslef1/Hex+Custom.apk/file',
 'canonical.response':'https://www.mediafire.com/file/ypaiywpzrvslef1',
 'public-info.response':'https://www.mediafire.com/api/1.5/file/get_info.php?quick_key=ypaiywpzrvslef1&response_format=json',
}
def candidate(data):
    if not data.startswith(b'PK\x03\x04'):return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:return 'AndroidManifest.xml' in z.namelist()
    except zipfile.BadZipFile:return False
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);p.add_argument('report',type=Path);p.add_argument('--existing',action='store_true');a=p.parse_args();a.private.mkdir(exist_ok=True,parents=True,mode=0o700);rows=[]
    for name,url in URLS.items():
        status=ctype=None;origin='existing curl/urllib response; original status observed separately'
        if a.existing:
            b=(a.private/name).read_bytes()
            if hashlib.sha256(b).hexdigest() != '5b131ca14aa96311d3432b0062c7443d3b0e6346ec279bd376a75f0a76bcd5d7':
                raise ValueError('--existing only imports the recorded 2026-11-04 error responses')
            if name!='mediafire.html':status=200;ctype='text/html'
        else:
            origin='live request from this script'
            try:
                with urlopen(Request(url,headers={'User-Agent':'Mozilla/5.0'}),timeout=25) as r:b=r.read(2*1024*1024+1);status=r.status;ctype=r.headers.get('Content-Type')
                if len(b)>2*1024*1024:raise ValueError('Oversized page')
                path=a.private/name;path.write_bytes(b);path.chmod(0o600)
            except Exception as e:
                rows.append({'source':url,'status':'NETWORK_ERROR','exception':type(e).__name__});continue
        unavailable=b'<title>Site Unavailable</title>' in b
        is_candidate=candidate(b)
        if unavailable:assert not is_candidate,'HTML must never be accepted as an APK'
        rows.append({'source':url,'httpStatus':status,'contentType':ctype,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'title':'Site Unavailable' if unavailable else None,'apkContainerCandidate':is_candidate,'provenance':origin})
    report={'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'PENDING_APK_ACQUISITION','responses':rows,'apkReceived':any(x.get('apkContainerCandidate') for x in rows),'browserObservation':{'source':URLS['mediafire.html'],'title':'Site Unavailable','visibleText':'Unable to access this site.','observedDate':'2026-11-04','provenance':'Historical observation in cloud browser, not inferred from this script.'}}
    if not a.existing:
        report.pop('browserObservation')
        if report['apkReceived']:report['status']='PENDING_APK_VALIDATION'
    a.report.parent.mkdir(exist_ok=True,parents=True);a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'apkReceived':report['apkReceived'],'responses':len(rows)}))
if __name__=='__main__':main()
