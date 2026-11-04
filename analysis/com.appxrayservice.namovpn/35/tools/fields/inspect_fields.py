#!/usr/bin/env python3
"""Reproduce field inventory and source tracing without shadowing stdlib inspect."""
import argparse,hashlib,json
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('private',type=Path);a=p.parse_args();root=a.private
    for name,sha in [('NAMO-VPN-35.xapk','d97d9f0625f5aecc6641569df709dc32f72a51015f0c3273a92d3e5526290fb1'),
        ('unpacked/apks/com.appxrayservice.namovpn.apk','1124a2344ec142526fc2b238f7333aa60a4fc624be3fa4b16846eaaad42516f6')]:
        assert hashlib.sha256((root/name).read_bytes()).hexdigest()==sha,name
    doc=json.loads((root/'outer.json').read_text())
    report={'remote_sha256':hashlib.sha256((root/'remote.enc').read_bytes()).hexdigest(),
        'version':doc['Version'],'counts':{},'field_shapes':{},'sources':{}}
    for group in ['Servers','Networks']:
        report['counts'][group]=len(doc[group]);report['field_shapes'][group]={}
        for k in sorted(set().union(*(r.keys() for r in doc[group]))):
            values=[r[k] for r in doc[group] if k in r]
            report['field_shapes'][group][k]={'types':sorted(set(type(v).__name__ for v in values)),
                'lengths':sorted(set(len(v) for v in values if isinstance(v,str))),
                'nonempty':sum(bool(v) for v in values)}
    checks={'defpackage/sd0.java':['"ServerIP"','"SquidProxy"','"OPENVPN_CINFIG"','"UDP_HYSTERIA"'],
        'defpackage/x93.java':['f60.m','"SERVER_HOST"','"DNSTT_DNS"','"PASSWORD_SERVER"'],
        'defpackage/bo.java':['f60.m','"DNSTT_SERVERNAME"'],
        'defpackage/d81.java':['f60.m','"UDP_HYSTERIA"'],
        'com/appxrayservice/namovpn/service/vpn/SSHCoreService.java':['f60.m','"PAYLOAD"','"SNI"'],
        'com/appxrayservice/namovpn/ui/activity/MainActivity.java':['f60.m','"V2RAY_CONTENT"']}
    for name,tokens in checks.items():
        source=(root/'resolved'/name).read_bytes()
        assert all(t in source.decode() for t in tokens),name
        report['sources'][name]={'sha256':hashlib.sha256(source).hexdigest(),'checks':tokens}
    raw=root/'jadx1/sources/defpackage/f60.java';source=raw.read_bytes()
    assert 'new String(Base64.decode(r3.getBytes(r1), 0), r1)' in source.decode()
    report['sources']['defpackage/f60.java']={'sha256':hashlib.sha256(source).hexdigest(),
        'method':'m: Base64.DEFAULT then UTF-8'}
    (root/'field-inspection.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'version':report['version'],'counts':report['counts'],'source_checks':len(report['sources'])}))
if __name__=='__main__':main()
