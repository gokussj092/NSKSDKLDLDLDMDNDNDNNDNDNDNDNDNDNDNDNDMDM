#!/usr/bin/env python3
"""Observe the APK's Firebase client config with one fresh SDK-shaped installation.

Uses the app's public Android client options, authentic FIS-issued token and
normal TLS. No account, Play Integrity/App Check assertion or license bypass.
The temporary installation is deleted in finally when its refresh token exists.
All identifiers/tokens/full responses remain in the supplied private directory.
"""
import argparse,base64,gzip,hashlib,json,time,uuid
from pathlib import Path
from urllib.request import Request,HTTPRedirectHandler,build_opener
from urllib.error import HTTPError,URLError
from androguard.core.apk import APK
from loguru import logger
PACKAGE='com.doriaxvpn.unlimited'
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError('Firebase redirect denied')
def private(p,value):
    p.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n');p.chmod(0o600)
def request(url,headers,body=None,method='POST'):
    data=None if body is None else json.dumps(body,separators=(',',':')).encode()
    if headers.get('Content-Encoding')=='gzip':data=gzip.compress(data,mtime=0)
    try:
        with build_opener(NoRedirect()).open(Request(url,data=data,headers=headers,method=method),timeout=30) as r:
            raw=r.read(1024*1024+1);assert len(raw)<=1024*1024
            if r.headers.get('Content-Encoding')=='gzip':raw=gzip.decompress(raw)
            return r.status,json.loads(raw) if raw else {}
    except HTTPError as e:
        raw=e.read(1024*1024);return e.code,json.loads(raw) if raw.lstrip().startswith(b'{') else {'error':'non-JSON response'}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args();d=a.private
    base=d/'unpacked/apks/com.doriaxvpn.unlimited.apk'
    assert hashlib.sha256(base.read_bytes()).hexdigest()=='d55c4ce6181ccd82b1846fac4a2c2298b6e5f6e807b07509c84cfe654b777d82'
    logger.remove();app=APK(str(base));arsc=app.get_android_resources()
    def resource(name):
        pair=arsc.get_string(PACKAGE,name);assert pair and isinstance(pair[1],str);return pair[1]
    api_key=resource('google_api_key');app_id=resource('google_app_id');project=resource('project_id')
    cert=hashlib.sha1(app.get_certificates_der_v2()[0]).hexdigest().upper()
    options={'api_key':api_key,'app_id':app_id,'project_id':project,'certificate_sha1':cert};private(d/'firebase-options.json',options)
    headers={'X-Goog-Api-Key':api_key,'X-Android-Package':PACKAGE,'X-Android-Cert':cert,
      'Content-Type':'application/json','Accept':'application/json','Cache-Control':'no-cache'}
    bits=bytearray(uuid.uuid4().bytes)+bytearray(1);bits[16]=bits[0];bits[0]=(bits[0]&15)|112
    fid=base64.urlsafe_b64encode(bits).decode()[:22];installation=None
    report={'scope':'Fresh analytical client profile, not a physical device or attestation',
      'app_version':'1.2.9','app_build':129,'firebase_installations_sdk':'18.0.0','remote_config_sdk':'22.1.0',
      'profile':{'country':'MX','language':'es-MX','platform':'34','time_zone':'America/Tijuana'}}
    try:
        status,installation=request('https://firebaseinstallations.googleapis.com/v1/projects/'+project+'/installations',
          {**headers,'Content-Encoding':'gzip'},{'fid':fid,'appId':app_id,'authVersion':'FIS_v2','sdkVersion':'a:18.0.0'})
        report['installation_http']=status;private(d/'firebase-installation.json',installation)
        if status!=200:raise ValueError('FIS request not authorized or unavailable')
        token=installation['authToken']['token'];fid=installation['fid']
        body={'appInstanceId':fid,'appInstanceIdToken':token,'appId':app_id,'countryCode':'MX','languageCode':'es-MX',
          'platformVersion':'34','timeZone':'America/Tijuana','appVersion':'1.2.9','appBuild':'129',
          'packageName':PACKAGE,'sdkVersion':'22.1.0','analyticsUserProperties':{}}
        status,reply=request('https://firebaseremoteconfig.googleapis.com/v1/projects/'+app_id.split(':')[1]+'/namespaces/firebase:fetch',
          {**headers,'X-Goog-Firebase-Installations-Auth':token,'X-Google-GFE-Can-Retry':'yes'},body)
        report['remote_config_http']=status;private(d/'firebase-response.json',reply)
        if status!=200:raise ValueError('Remote Config request not authorized or unavailable')
        entries=reply.get('entries',{});defaults=json.loads((d/'recipe.json').read_text())
        chosen={'source':entries.get('ockla_url',defaults['source']),'password':entries.get('gretta_pass',defaults['password'])}
        private(d/'firebase-effective.json',chosen)
        report.update(state=reply.get('state'),template_version=reply.get('templateVersion'),
          updater_parameter_present='ockla_url' in entries,password_parameter_present='gretta_pass' in entries,
          source_matches_apk_default=chosen['source']==defaults['source'],password_matches_apk_default=chosen['password']==defaults['password'],
          chosen_password_sha256=hashlib.sha256(chosen['password'].encode()).hexdigest())
    except (ValueError,OSError,KeyError,URLError) as e:
        report['error_type']=type(e).__name__
    finally:
        if installation and installation.get('refreshToken') and installation.get('fid'):
            try:
                status,_=request('https://firebaseinstallations.googleapis.com/v1/projects/'+project+'/installations/'+installation['fid'],
                  {**headers,'Authorization':'FIS_v2 '+installation['refreshToken']},method='DELETE')
                report['installation_cleanup_http']=status
            except (ValueError,OSError,URLError):report['installation_cleanup_http']=None
        (d/'firebase-report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
