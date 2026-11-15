#!/usr/bin/env python3
"""Revalidate the unchanged build, fixed public recipe, and current download outcome."""
import argparse,hashlib,json,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.CATNET_VPN import server_catalog_decoder as cli
def main():
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();folder=a.private.resolve()
    identity=json.loads((folder/'identity.json').read_text())
    if identity['apkSha256']!='995d5d9d70e0f929bd92e29125bf1c9ab87f6f8a3d064b6657c6d230d8e8b31a':raise ValueError('UNEXPECTED_DISTRIBUTION')
    if hashlib.sha256((folder/'base.apk').read_bytes()).hexdigest()!=identity['apkSha256']:raise ValueError('APK_MISMATCH')
    sources=folder/'jadx/sources';checks={
      'net/xj/vpn/api/ApiClient.java':['https://pussyvpn.com/xjvpn/','https://xjdev.net/xjvpn/','pussy_vpn','net.catnet.vpn'],
      'net/xj/vpn/api/MobileApiService.java':['mobile/public/app-update','mobile/public/servers'],
      'defpackage/fe.java':['getIntegrity_required()']}
    digests={}
    for name,markers in checks.items():
        path=sources/name;text=path.read_text()
        if not all(x in text for x in markers):raise ValueError('STATIC_RECIPE_MISMATCH')
        digests[name]=hashlib.sha256(path.read_bytes()).hexdigest()
    report={'identityUnchanged':True,'sourceSha256':digests,'apkCodeExecuted':False,'retryLimitPerFixedRequest':2,
        'policyPreflightRequired':True,'integrityBypassed':False}
    start=time.monotonic()
    try:
        data=cli.download();target=folder/'catalog-current.json';target.write_bytes(data);target.chmod(0o600)
        report.update(status='DOWNLOADED_REQUIRES_WHOLE_PROOF',bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
    except cli.CatalogError:
        report.update(status='NETWORK_UNAVAILABLE',downloadVerified=False,servers=None)
    report['elapsedSeconds']=round(time.monotonic()-start,3)
    (folder/'maintenance-proof.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
