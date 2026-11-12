#!/usr/bin/env python3
"""Check exact APK/DEX source trace and publish only hashes and known API metadata."""
import argparse,hashlib,json,re
from pathlib import Path
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args();root=a.private
    assert sha(root/'CATNET-latest.xapk')=='70ba046c8e8da42bfb010b5a2d0ecc787b746e2eb39e2d5f74b53a34cba4dfb1'
    assert sha(root/'unpacked/apks/net.catnet.vpn.apk')=='995d5d9d70e0f929bd92e29125bf1c9ab87f6f8a3d064b6657c6d230d8e8b31a'
    src=root/'jadx1/sources'
    checks={'net/xj/vpn/api/ApiClient.java':['net.catnet.vpn','https://pussyvpn.com/xjvpn/',
        'https://xjdev.net/xjvpn/','mobile/public/servers','mobile/public/payloads','mobile/public/xray_payloads'],
        'net/xj/vpn/api/MobileApiService.java':['mobile/public/app-update','app_key','current_version_code'],
        'defpackage/fe.java':['integrity_required','Boolean.FALSE','setIntegritySession','Play token request','70000'],
        'defpackage/t8.java':['okhttp/4.12.0'],
        'net/xj/vpn/data/ServerDto.java':['servername','ip','password','gcp_host'],
        'net/xj/vpn/data/XjConfigCodec.java':['PBKDF2_ITERATIONS = 120000','AES/GCM/NoPadding','xj-link-v1']}
    report={'package':'net.catnet.vpn','build':27,'source_checks':{}}
    for name,tokens in checks.items():
        b=(src/name).read_bytes();assert all(t in b.decode() for t in tokens),name
        report['source_checks'][name]={'sha256':hashlib.sha256(b).hexdigest(),'verified_tokens':tokens}
    dex=json.loads((root/'api-dex.json').read_text())
    method=next(m for m in dex if m['name']=='intercept')
    headers=[i['output'].split('"')[1] for i in method['instructions'] if i['op']=='const-string' and '"X-' in i['output']]
    assert 'X-XJ-Integrity-Token' in headers and 'X-App-Key' in headers
    report['interceptor']={'class':method['class'],'method':'intercept','headers':headers,
        'conditional_integrity_headers':True,'app_key':'pussy_vpn','app_package':'net.catnet.vpn'}
    report['remote_scope']='complete public servers JSON only; payloads/xray endpoints unavailable'
    report['local_formats']='Observed XjConfigCodec and GcpHostUpdateCodec are NOT integrated/certified; no real file/link fixture provided.'
    report['jadx']={'exit':3,'errors':54,'version':'1.5.6','partial_sources':True}
    (root/'source-evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'sources_checked':len(checks),'headers':len(headers)}))
if __name__=='__main__':main()
