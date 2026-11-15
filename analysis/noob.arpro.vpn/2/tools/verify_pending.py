#!/usr/bin/env python3
"""Assert only observed scope; explicitly refuse to certify a remote catalog."""
import argparse,hashlib,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from probe import classify_response
from recover import keys,xts_open,gcm_open
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args();d=a.private
    short,xts=keys(d/'unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libovpn3.so')
    raw=(d/'noobdev.js').read_bytes()
    assert hashlib.sha256(raw).hexdigest()=='6e3e10f6c3efef1fbb6bac2595e6df1b27ffee7fe9495a17fccb09c03d40cc01'
    doc=json.loads(xts_open(raw,xts));assert isinstance(doc,dict) and len(doc['Servers'])==len(doc['Tweaks'])==1
    assert gcm_open(doc['Version'],short)=='1.0.0'
    assert gcm_open(doc['DefUpdateURL'],short)=='https://jezvpn.xyz/api/app?json=743ebcbbf84f7f9cac2f'
    assert gcm_open(doc['updater'],short)=='https://pastebin.com/raw/XrVPE3mj'
    bootstrap=(d/'remote/remote.enc').read_bytes();configured=(d/'configured-catalog.response').read_bytes()
    assert classify_response(200,bootstrap)=='HTML_NOT_CATALOG'
    assert classify_response(200,configured)=='HTML_NOT_CATALOG'
    app=json.loads((d/'app-update-metadata.response').read_text());assert 'noob.arpro.vpn' in app
    report={'status':'PARTIAL','remote_catalog':'NETWORK_UNAVAILABLE_IN_THIS_ENVIRONMENT',
        'remote_whole_document_verified':False,'included':{'outer_json_opened':True,'servers':1,'tweaks':1,'version':'1.0.0',
            'root_gcm_tags_verified':['Version','DefUpdateURL','updater'],
            'all_fields_decoded':False,'independent_xts_oracle':'PENDING'},
        'bootstrap_response':{'outcome':'HTML_NOT_CATALOG','bytes':len(bootstrap),'sha256':hashlib.sha256(bootstrap).hexdigest()},
        'configured_response':{'outcome':'HTML_NOT_CATALOG','bytes':len(configured),'sha256':hashlib.sha256(configured).hexdigest()},
        'app_update_metadata':'JSON contains matching package; no APK/artifact URL downloaded',
        'enabled':False,'cloud_runtime_changed':False}
    (d/'verification-pending.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
