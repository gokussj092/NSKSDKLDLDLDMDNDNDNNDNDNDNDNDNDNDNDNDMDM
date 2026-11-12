#!/usr/bin/env python3
"""Only fictional CATNET data; never copy live VPN rows into fixtures."""
import json
from pathlib import Path
def main():
    doc={'success':True,'message':'Ficticio ñ ไทย 🦊','servers':[
        {'id':1,'uuid':'fictional','servername':'Fictional server','ip':'vpn.example.org',
         'cloudfront':None,'gcp_host':'front.example.org','gcp_path':'/demo',
         'is_installed':True,'ulimit':0,'script':{'id':2,'name':'demo','type':'SSH','v2_type':'vless'},
         'Future':{'base64':'YWJjZA==','payload':'GET / HTTP/1.1\r\nHost: example.org\r\n\r\n','flags':[True,None,3]}},
        {'id':3,'servername':'Second fictional server','ip':'192.0.2.1','script':None}],
        'has_defaults':True,'def_user':'sample-user','def_pass_plain':'YWJjZA==',
        'back_user':'','back_pass_plain':'','futureMetadata':{'nested':[1,None,False]}}
    here=Path(__file__).resolve().parents[1]/'tests/fixtures';here.mkdir(parents=True,exist_ok=True)
    (here/'servers.json').write_text(json.dumps(doc,ensure_ascii=False,indent=2)+'\n')
    (here/'preflight.json').write_text(json.dumps({'success':True,'data':{'maintenance':False,'integrity_required':False,
        'integrity_session':None,'integrity_session_expires_at':None}})+'\n')
    (here/'site-unavailable.html').write_text('<html><head><title>Site Unavailable</title></head><body>Unable to access this site.</body></html>\n')
if __name__=='__main__':main()
