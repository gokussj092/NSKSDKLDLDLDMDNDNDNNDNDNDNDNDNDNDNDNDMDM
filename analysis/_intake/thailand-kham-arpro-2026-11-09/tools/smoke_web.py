#!/usr/bin/env python3
"""Start the production web build locally and verify actual catalog/icon responses."""
import argparse,base64,json,os,signal,subprocess,time
from pathlib import Path
from urllib.request import Request,build_opener,ProxyHandler
from urllib.error import HTTPError
ROOT=Path(__file__).resolve().parents[4]
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args()
    policy=a.private.resolve()/'smoke-policy';policy.mkdir(exist_ok=True)
    with (a.private/'web-smoke-start.log').open('wb') as log:
        proc=subprocess.Popen(['npm','start'],cwd=ROOT/'cloud/web',env={**os.environ,'PORT':'3034','CLOUD_V1_POLICY_ROOT':str(policy)},stdout=log,stderr=log,start_new_session=True)
        try:
            def post(route,data,bundle=False):
                headers={'Content-Type':'application/json'}
                if bundle:headers['x-spdecode-catalog-bundle']='1'
                # Local test traffic stays on loopback; external probes keep inherited proxy.
                with build_opener(ProxyHandler({})).open(Request('http://127.0.0.1:3034/api/v1/server-vpn/'+route,data=json.dumps(data).encode(),headers=headers),timeout=10) as r:return r.status,json.load(r)
            for _ in range(40):
                try:status,doc=post('catalog',{'knownVersion':0},True);break
                except HTTPError as error:raise RuntimeError('WEB_HTTP_'+str(error.code)) from error
                except OSError:
                    if proc.poll() is not None:raise RuntimeError('WEB_START_FAILED')
                    time.sleep(.2)
            else:raise RuntimeError('WEB_START_TIMEOUT')
            assert status==200
            for icon in doc['iconBundle']['icons']:
                assert icon['mimeType']=='image/png' and base64.b64decode(icon['contentBase64']).startswith(b'\x89PNG\r\n\x1a\n')
            for identifier in ('thailand-vpn','kham-vpn','ar-pro-vpn','md-proxy-vpn'):
                status,icon=post('icon',{'id':identifier});assert status==200 and icon['mimeType']=='image/png'
            proof=dict(status='PASSED',productionNextStart=True,catalogHttp=200,iconHttp=200,version=doc['catalogVersion'],
              appCount=len(doc['apps']),bundledIcons=doc['iconBundle']['count'],allActualPng=True)
            (a.private/'production-smoke.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof))
        finally:
            os.killpg(proc.pid,signal.SIGTERM);proc.wait(timeout=10)
