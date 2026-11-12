#!/usr/bin/env python3
"""Cloud wiring only. Keeps operator choices and higher catalog versions intact."""
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]


def edit(name, old, new, marker):
    path = ROOT/name
    source = path.read_text()
    if marker in source:
        return
    assert old in source, name
    path.write_text(source.replace(old, new, 1))


def main():
    edit('cloud/web/lib/server-vpn-provider.mjs', 'const PROVIDERS = Object.freeze({',
         '''const PROVIDERS = Object.freeze({
  // Build76 updater sets no UA; analytical Android runtime profile.
  "genis-vpn": {url:"https://raw.githubusercontent.com/nemygoku/genisvpn/refs/heads/main/genis",agent:"Dalvik/2.1.0 (Linux; U; Android 14)"},''', '"genis-vpn": {url:')
    edit('cloud/web/lib/server-vpn-provider.mjs', '["http-conexion","namo-vpn"',
         '["genis-vpn","http-conexion","namo-vpn"', '["genis-vpn","http-conexion"')
    edit('cloud/workers/python/catalog_vpn_bridge.py', 'PROVIDERS = {',
         'PROVIDERS = {\n    "genis-vpn": "decoders.Python.apps.Genis_VPN.server_catalog_decoder",', '"genis-vpn":')
    edit('cloud/workers/python/engine.py', 'if provider_id not in ("speicers-turbo-vpn",',
         'if provider_id not in ("genis-vpn", "speicers-turbo-vpn",', 'if provider_id not in ("genis-vpn",')
    edit('cloud/web/lib/c12-provider-controls.mjs', '"speicers-turbo-vpn":"Speicers`Turbo VPN",',
         '"genis-vpn":"Genis VPN",\n  "speicers-turbo-vpn":"Speicers`Turbo VPN",', '"genis-vpn":')
    edit('cloud/web/lib/server-vpn-catalog.mjs', '{id:"speicers-turbo-vpn"',
         '{id:"genis-vpn",name:"Genis VPN",icon:"genis-vpn.png",remote:"genis-vpn"},\n  {id:"speicers-turbo-vpn"', 'id:"genis-vpn"')
    path = ROOT/'cloud/web/lib/server-vpn-catalog.mjs'
    source = re.sub(r'CATALOG_VERSION = 68;[^\n]*',
                    'CATALOG_VERSION = 69; // Genis VPN; preserve higher monotonic VPS versions.', path.read_text())
    path.write_text(source)
    contract = '''if(kind==="server-vpn" && payload?.providerId==="genis-vpn"){
      let parsed;
      try{parsed=JSON.parse(decoded.rawText);}catch{throw Error("INVALID_WORKER_RESULT");}
      if(decoded.kind!=="vpn_catalog" || decoded.providerId!==payload.providerId || !isRecord(parsed) ||
         !isDeepStrictEqual(parsed,decoded.structuredJson) || typeof parsed.Version!=="string" || !parsed.Version ||
         !Array.isArray(parsed.Servers) || !parsed.Servers.length || Object.hasOwn(parsed,"Usuarios") ||
         parsed.Servers.some(row=>!isRecord(row) || typeof row["p0PgL3l0d89mnssz7ImPJA=="]!=="string" ||
           !row["p0PgL3l0d89mnssz7ImPJA=="]) ||
         (Object.hasOwn(parsed,"ReleaseNotes") && typeof parsed.ReleaseNotes!=="string"))throw Error("INVALID_WORKER_RESULT");
    }
    '''
    edit('cloud/web/lib/c3-gateway.mjs', 'if(kind==="server-vpn" && payload?.providerId==="speicers-turbo-vpn"){',
         contract+'if(kind==="server-vpn" && payload?.providerId==="speicers-turbo-vpn"){', 'payload?.providerId==="genis-vpn"')
    shutil.copyfile(ROOT/'private/genis/icon.png', ROOT/'cloud/web/public/server-vpn-icons/genis-vpn.png')
    for path in (ROOT/'cloud/web/tests').glob('*.test.mjs'):
        source = path.read_text()
        new = re.sub(r'(CATALOG_VERSION,\s*)68\b', r'\g<1>69', source)
        new = re.sub(r'(\.apps\.length,\s*)64\b', r'\g<1>65', new)
        if path.name=='server-vpn-catalog.test.mjs':
            new = new.replace('"freedom-vpn","ha-tunnel-plus"', '"freedom-vpn","genis-vpn","ha-tunnel-plus"')
        if new!=source:
            path.write_text(new)
    print('Genis Cloud wiring installed; no Android/build/merge/deploy actions.')


if __name__=='__main__':
    main()
