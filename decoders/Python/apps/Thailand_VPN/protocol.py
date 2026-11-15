"""Original public Firebase source resolution; explicit CLI network only."""
import base64,json,os
from urllib.request import Request,build_opener,HTTPRedirectHandler
OPTIONS={'api_key': 'AIzaSyDHaIOwa7qoESPpRS5lXyVZixYOS5sIkW4', 'app_id': '1:376598045006:android:778874487f5eed6db2be1f', 'project_id': 'thiland-vpn', 'certificate_sha1': 'CFF514C9000704D8D59F28D7FFBB960EC22C2C00'}
PACKAGE='thailand.vpn.globalvpn'
class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*a,**k):raise ValueError('REDIRECT')
def request(url,headers,body=None,method=None):
    with build_opener(_NoRedirect()).open(Request(url,data=None if body is None else json.dumps(body).encode(),headers=headers,method=method),timeout=30) as r:
        raw=r.read(8*1024*1024+1)
        if len(raw)>8*1024*1024:raise ValueError('SIZE')
        return r.status,raw

def download():
    options=OPTIONS
    headers={'X-Goog-Api-Key':options['api_key'],'X-Android-Package':PACKAGE,'X-Android-Cert':options['certificate_sha1'],'Content-Type':'application/json','Accept':'application/json'}
    base='https://firebaseinstallations.googleapis.com/v1/projects/'+options['project_id']+'/installations'
    remote='https://firebaseremoteconfig.googleapis.com/v1/projects/'+options['app_id'].split(':')[1]+'/namespaces/firebase:fetch'
    bits=bytearray(os.urandom(17));bits[0]=(bits[0]&15)|112
    fid=base64.urlsafe_b64encode(bits).decode()[:22];installation=None
    try:
        _,raw=request(base,headers,dict(fid=fid,appId=options['app_id'],authVersion='FIS_v2',sdkVersion='a:18.0.0'))
        installation=json.loads(raw);token=installation['authToken']['token']
        _,raw=request(remote,{**headers,'X-Goog-Firebase-Installations-Auth':token},dict(appInstanceId=installation['fid'],appInstanceIdToken=token,appId=options['app_id'],countryCode='TH',languageCode='th-TH',platformVersion='34',timeZone='Asia/Bangkok',appVersion='1.0.3',appBuild='3',packageName=PACKAGE,sdkVersion='22.1.0',analyticsUserProperties={}))
        source=json.loads(raw)['entries']['serverUrl']
        if source not in ('https://globalvpn.uk/global_admin/api/','https://globalvpn.uk/global_admin/api'):raise ValueError('SOURCE')
        return request('https://globalvpn.uk/global_admin/api/server?package_name='+PACKAGE,{'User-Agent':'okhttp/4.12.0','Accept-Encoding':'identity'})[1]
    finally:
        if installation:
            try:request(base+'/'+installation['fid'],{**headers,'Authorization':'FIS_v2 '+installation['refreshToken']},method='DELETE')
            except (OSError,ValueError):pass
