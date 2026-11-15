#!/usr/bin/env python3
"""Idempotent Cloud-only wiring recipe; no Android/build/deploy/merge operations."""
from pathlib import Path
import re,shutil
ROOT=Path(__file__).resolve().parents[4]
TESTS=['http-conexion','namo-vpn','fnf-tunnel-bd','alsaher-vip','halcon-r-net','server-vpn-provider','server-vpn-worker-contract','alfaisal-tunnel-plus','server-vpn-catalog','zig-tunnel','mm-tunnel','text-format-catalog','vip-snipher-pro','server-vpn-any-speicers','enaa-tunnel','ultra-tunnel','jyfast-vpn-ultra']
def edit(path,old,new,marker):
    p=ROOT/path;s=p.read_text()
    if marker in s:return
    assert old in s,path;p.write_text(s.replace(old,new,1))
def main():
    edit('cloud/web/lib/server-vpn-provider.mjs','const TURBOMX_SOURCES=', '''const SPEICERS_TURBO_SOURCES=Object.freeze({
  servers:"https://raw.githubusercontent.com/apksdemons/apks2/refs/heads/main/speicers/spei_servrs",
  users:"https://raw.githubusercontent.com/apksdemons/apks2/refs/heads/main/speicers/spei_users",
});
const TURBOMX_SOURCES=''','const SPEICERS_TURBO_SOURCES=')
    edit('cloud/web/lib/server-vpn-provider.mjs','Object.freeze({"jyfast-vpn-ultra":JYFAST_SOURCES','Object.freeze({"speicers-turbo-vpn":SPEICERS_TURBO_SOURCES,"jyfast-vpn-ultra":JYFAST_SOURCES','"speicers-turbo-vpn":SPEICERS_TURBO_SOURCES')
    edit('cloud/web/lib/server-vpn-provider.mjs','const PROVIDERS = Object.freeze({','const PROVIDERS = Object.freeze({\n  // No app-specific UA; analytical Android runtime profile.\n  "speicers-turbo-vpn": {url:SPEICERS_TURBO_SOURCES.servers,agent:"Dalvik/2.1.0 (Linux; U; Android 14)"},','"speicers-turbo-vpn": {url:')
    edit('cloud/web/lib/paired-vpn-catalogs.mjs','const KINDS=Object.freeze({','const KINDS=Object.freeze({\n "speicers-turbo-vpn":{kind:"spdecode-speicers-turbo-vpn-catalogs-v1",sources:["servers","users"]},','"speicers-turbo-vpn":')
    edit('cloud/web/lib/server-vpn-gateway.mjs','["jyfast-vpn-ultra","abowaged-vpn"','["speicers-turbo-vpn","jyfast-vpn-ultra","abowaged-vpn"','"speicers-turbo-vpn"')
    contract='''if(kind==="server-vpn" && payload?.providerId==="speicers-turbo-vpn"){
      let parsed;
      try{parsed=JSON.parse(decoded.rawText);}catch{throw Error("INVALID_WORKER_RESULT");}
      if(decoded.kind!=="vpn_catalog" || decoded.providerId!==payload.providerId || !isRecord(parsed) ||
         parsed.provider!==payload.providerId || parsed.complete!==true || !isRecord(parsed.catalogs) ||
         Object.keys(parsed.catalogs).sort().join(",")!=="servers,users" || !isDeepStrictEqual(parsed,decoded.structuredJson))
        throw Error("INVALID_WORKER_RESULT");
      for(const [source,section,name] of [["servers","Servers","p0PgL3l0d89mnssz7ImPJA=="],["users","Usuarios","Name"]]){
        const doc=parsed.catalogs[source];
        if(!isRecord(doc) || typeof doc.Version!=="string" || !doc.Version || !Array.isArray(doc[section]) || !doc[section].length ||
           doc[section].some(row=>!isRecord(row) || typeof row[name]!=="string" || !row[name]) ||
           (Object.hasOwn(doc,"ReleaseNotes") && typeof doc.ReleaseNotes!=="string"))throw Error("INVALID_WORKER_RESULT");
      }
    }
    '''
    edit('cloud/web/lib/c3-gateway.mjs','if(kind==="server-vpn" && payload?.providerId==="http-conexion"){',contract+'if(kind==="server-vpn" && payload?.providerId==="http-conexion"){','payload?.providerId==="speicers-turbo-vpn"')
    p=ROOT/'cloud/web/lib/server-vpn-catalog.mjs';s=p.read_text();s=re.sub(r'(CATALOG_VERSION\s*=\s*)67\b',r'\g<1>68',s)
    if 'id:"speicers-turbo-vpn"' not in s:s=s.replace('{id:"http-conexion"','{id:"speicers-turbo-vpn",name:"Speicers`Turbo VPN",icon:"speicers-turbo-vpn.png",remote:"speicers-turbo-vpn"},\n  {id:"http-conexion"')
    p.write_text(s)
    edit('cloud/web/lib/c12-provider-controls.mjs','"http-conexion":"HTTP Conexión",','"speicers-turbo-vpn":"Speicers`Turbo VPN",\n  "http-conexion":"HTTP Conexión",','"speicers-turbo-vpn":')
    edit('cloud/workers/python/catalog_vpn_bridge.py','    "http-conexion":','    "speicers-turbo-vpn": "decoders.Python.apps.Speicers_Turbo_VPN.server_catalog_decoder",\n    "http-conexion":','"speicers-turbo-vpn":')
    edit('cloud/workers/python/engine.py','if provider_id not in ("http-conexion",','if provider_id not in ("speicers-turbo-vpn", "http-conexion",','if provider_id not in ("speicers-turbo-vpn",')
    shutil.copyfile(ROOT/'private/netfree/unpacked/inspected/icon.png',ROOT/'cloud/web/public/server-vpn-icons/speicers-turbo-vpn.png')
    for name in TESTS:
        p=ROOT/'cloud/web/tests'/(name+'.test.mjs');s=p.read_text();s=re.sub(r'(CATALOG_VERSION,\s*)67\b',r'\g<1>68',s);s=s.replace('.apps.length,63','.apps.length,64')
        if name=='server-vpn-catalog':s=s.replace('"speicers-pro-vpn","superflash-vpn"','"speicers-pro-vpn","speicers-turbo-vpn","superflash-vpn"')
        p.write_text(s)
    print('Cloud wiring and original icon installed; run verification before marking VERIFIED.')
if __name__=='__main__':main()
