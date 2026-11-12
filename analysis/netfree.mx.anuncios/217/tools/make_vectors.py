#!/usr/bin/env python3
"""Entirely fictional golden fixtures encrypted by the independent JCA oracle."""
import copy,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from census import oracle
from decoders.Python.apps.Speicers_Turbo_VPN import codec,server_catalog_decoder as cli
HERE=Path(__file__).resolve().parents[1]
def seal(doc):return oracle('E',codec.CATALOG_PASSWORD,[json.dumps(doc,ensure_ascii=False).encode()])[0]
def generate():
    row={k:'Example-'+str(i)+' abcXYZ 123 /\r\n' for i,k in enumerate(sorted(codec.SERVER_FIELDS))};row['p0PgL3l0d89mnssz7ImPJA==']='Example MX Server'
    row.update({'MIgkNbuX29MmGatZNVaFUj==':True,'serverType':0,'tunnelType':1,'ssh_userpass_enabled':False,'metadata':{'note':'México 🎯\r\n','preserve':['AA==',True,7,None]}})
    users={k:'Example '+k+' abcXYZ 123 /\r\n' for k in sorted(codec.USER_FIELDS)};users['Name']='Fictional user preset';users['metadata']={'tokenLike':'QUJDREVGRw==','bool':True}
    expected={'provider':'speicers-turbo-vpn','complete':True,'catalogs':{'servers':{'Version':'fiction-217','ReleaseNotes':'Solo pruebas 🎯','Servers':[row]},'users':{'Version':'fiction-2','Usuarios':[users]}}};wire=copy.deepcopy(expected['catalogs'])
    for name,section,fields in [('servers','Servers',codec.SERVER_FIELDS),('users','Usuarios',codec.USER_FIELDS)]:
        row=wire[name][section][0];keys=sorted(fields & row.keys());values=oracle('G',codec.FIELD_KEY,[row[k].encode() for k in keys])
        for k,v in zip(keys,values):row[k]=v.decode()
    encrypted={k:seal(doc) for k,doc in wire.items()};bundle=cli.pack_catalogs(encrypted['servers'],encrypted['users']);assert json.loads(cli.run(bundle))==expected
    return expected,wire,encrypted,bundle
def main():
    dest=HERE/'tests/fixtures';dest.mkdir(parents=True,exist_ok=True);expected,wire,encrypted,bundle=generate()
    for n,v in [('expected',expected),('wire',wire)]:(dest/(n+'.json')).write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n')
    for n,v in encrypted.items():(dest/(n+'.txt')).write_bytes(v)
    (dest/'bundle.json').write_bytes(bundle);print('Fictional JCA fixtures verified, both catalogs and all fields.')
if __name__=='__main__':main()
