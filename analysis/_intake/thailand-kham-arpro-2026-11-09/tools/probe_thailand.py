#!/usr/bin/env python3
"""Read public Firebase client config and probe the original Thailand updater.

Only transient FIS credentials in memory; delete the analytical installation.
Private bytes/summary go outside Git. No fabricated Integrity/authentication.
"""
import argparse,base64,hashlib,json,os
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request,urlopen
from androguard.core.apk import APK
from loguru import logger
logger.disable('androguard')
PACKAGE='thailand.vpn.globalvpn'

def request(url,headers,body=None,method=None):
    with urlopen(Request(url,data=None if body is None else json.dumps(body).encode(),headers=headers,method=method),timeout=30) as r:
        raw=r.read(8*1024*1024+1)
        if len(raw)>8*1024*1024:raise ValueError('SIZE')
        return r.status,raw

def probe(directory):
    apk=APK(str(directory/'base.apk'));resources=apk.get_android_resources()
    values=resources.get_resolved_strings()[PACKAGE]['DEFAULT']
    def get(name):
        item=resources.get_res_id_by_key(PACKAGE,'string',name)
        return values[item]
    options=dict(api_key=get('google_api_key'),app_id=get('google_app_id'),project_id=get('project_id'),
      certificate_sha1=apk.get_certificates()[0].sha1.hex().upper())
    (directory/'firebase-options.json').write_text(json.dumps(options,indent=2))
    headers={'X-Goog-Api-Key':options['api_key'],'X-Android-Package':PACKAGE,
      'X-Android-Cert':options['certificate_sha1'],'Content-Type':'application/json','Accept':'application/json'}
    base='https://firebaseinstallations.googleapis.com/v1/projects/'+options['project_id']+'/installations'
    remote='https://firebaseremoteconfig.googleapis.com/v1/projects/'+options['app_id'].split(':')[1]+'/namespaces/firebase:fetch'
    bits=bytearray(os.urandom(17));bits[0]=(bits[0]&15)|112
    fid=base64.urlsafe_b64encode(bits).decode()[:22];installation=None;summary={}
    try:
        status,raw=request(base,headers,dict(fid=fid,appId=options['app_id'],authVersion='FIS_v2',sdkVersion='a:18.0.0'))
        summary['fisHttp']=status;installation=json.loads(raw)
        token=installation['authToken']['token']
        status,raw=request(remote,{**headers,'X-Goog-Firebase-Installations-Auth':token},dict(
          appInstanceId=installation['fid'],appInstanceIdToken=token,appId=options['app_id'],
          countryCode='TH',languageCode='th-TH',platformVersion='34',timeZone='Asia/Bangkok',
          appVersion='1.0.3',appBuild='3',packageName=PACKAGE,sdkVersion='22.1.0',analyticsUserProperties={}))
        summary['configHttp']=status;config=json.loads(raw);source=config['entries']['serverUrl']
        u=urlsplit(source)
        if u.scheme!='https' or u.username or u.password or u.query or u.fragment:raise ValueError('SOURCE')
        (directory/'remote-config.json').write_text(json.dumps(config))
        url=source.rstrip('/')+'/server?package_name='+PACKAGE
        status,raw=request(url,{'User-Agent':'okhttp/4.12.0','Accept-Encoding':'identity'})
        (directory/'catalog.wire').write_bytes(raw)
        doc=json.loads(base64.b64decode(raw));(directory/'catalog.json').write_text(json.dumps(doc))
        summary.update(catalogHttp=status,sourceHost=u.hostname,catalogBytes=len(raw),wireSha256=hashlib.sha256(raw).hexdigest(),
          topKeys=list(doc),serverCount=len(doc.get('Servers',[])),status=doc.get('Status'))
    finally:
        if installation:
            try:summary['deleteHttp']=request(base+'/'+installation['fid'],{**headers,'Authorization':'FIS_v2 '+installation['refreshToken']},method='DELETE')[0]
            except Exception:summary['deleteHttp']=None
        (directory/'probe-summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();probe(a.private)
