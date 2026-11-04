"""Independent catalog-field reference; no imports from the production codec."""
import base64,json,subprocess
from pathlib import Path

def field_oracle(mode,values):
    lines=''.join(mode+'\t'+base64.b64encode(v).decode()+'\n' for v in values)
    if not values:return []
    done=subprocess.run(['java',str(Path(__file__).with_name('FieldOracle.java'))],
        input=lines,text=True,capture_output=True,check=True,timeout=45)
    result=[base64.b64decode(line,validate=True) for line in done.stdout.splitlines()]
    if len(result)!=len(values):raise ValueError('Incomplete field reference')
    return result

def transform_fields(document,mode='D'):
    doc=json.loads(json.dumps(document,ensure_ascii=False))
    # Independently traced sd0.v -> preference -> f60.m consumers.
    groups=[(doc['Servers'],['ServerIP','Cloudfront','NameServer','PublicKey',
        'ServerDNS','ProxyIP','Username','Password','setOpenVPN','OvpnCertificate','V2Ray','UDPConfig']),
        (doc['Networks'],['Sni','ServerDNS','Payload','SquidProxy']),([doc],['setOpenVPN'])]
    slots=[(row,k) for rows,keys in groups for row in rows for k in keys if k in row]
    values=[row[k].encode('utf-8') for row,k in slots]
    for (row,k),value in zip(slots,field_oracle(mode,values)):row[k]=value.decode('utf-8')
    return doc
