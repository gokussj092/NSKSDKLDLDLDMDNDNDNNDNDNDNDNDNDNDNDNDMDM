#!/usr/bin/env python3
"""Export only allowlisted, profile-free evidence and metadata to the dossier."""
import argparse,hashlib,json
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];HERE=Path(__file__).resolve().parents[1]
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args();d=a.private;g=HERE/'generated';g.mkdir(exist_ok=True)
    refs=[]
    for src,target in [('unpacked/inventory.json','inventory.json'),('resource-summary.json','resource.json'),('native-summary.json','native-symbols.json'),
      ('probe-summary.json','probe.json'),('recovery-summary.json','recovery.json'),('verification-summary.json','verification.json'),
      ('native-verification.json','native-verification.json'),('cloud-verification.json','cloud.json'),('checks.json','checks.json'),('node-transport.json','node-transport.json')]:
        # These named producers emit only hashes, counts, class/symbol names and tool versions.
        obj=json.loads((d/src).read_text());(g/target).write_text(json.dumps(obj,indent=2,ensure_ascii=False)+'\n');refs.append(str((g/target).relative_to(ROOT)))
    inventory=json.loads((d/'unpacked/inventory.json').read_text());verification=json.loads((d/'verification-summary.json').read_text());lock=json.loads((HERE/'dependencies.lock.json').read_text())
    own=[{'path':str(f.relative_to(ROOT)),'sha256':digest(f),'origin':'project-owned manual research','approval':'UNREVIEWED_FOR_AUTOMATIC_PHASE_7'} for f in sorted((HERE/'tools').rglob('*')) if f.is_file() and '__pycache__' not in f.parts]
    artifacts=[('xapk',d/'XXPICore-latest.xapk','https://d.apkpure.com/b/XAPK/pro.xxpicore.tunnel?version=latest'),
      ('base_apk',d/'unpacked/apks/pro.xxpicore.tunnel.apk','XAPK/pro.xxpicore.tunnel.apk'),
      ('native',d/'unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libovpn3.so','XAPK/config.arm64_v8a.apk/lib/arm64-v8a/libovpn3.so'),
      ('remote_catalog',d/'remote.bin','https://raw.githubusercontent.com/XyrussProject/infinite88/refs/heads/main/xxpicoretunnel888.hs'),
      ('icon',d/'unpacked/inspected/icon.png','base APK/res/i/bn.png')]
    manifest={'schema_version':1,'package_name':'pro.xxpicore.tunnel','app_name':'XXPICore Tunnel','version_name':'1.0.18','version_code':118,
      'observed_at':datetime.now(timezone.utc).isoformat(),'source_category':'user_store_link_public_mirror','authorization_note':'Owner requested Cloud-only integration; no Android build, merge or deployment.',
      'status':'VERIFIED','targets':[{'kind':'catalog','status':'VERIFIED_REAL','http':200,'remote_version':verification['version'],'servers':verification['servers'],'networks':verification['networks'],'encrypted_fields':verification['encryptedFields'],'node_live_transport':'PENDING_NETWORK_UNAVAILABLE','production_review':'PENDING'},
        *[{'kind':k,'status':'NOT_CERTIFIED','enabled':False} for k in ['files','text','export']]],
      'inputs':[{'type':kind,'bytes':path.stat().st_size,'sha256':digest(path),'source':source} for kind,path,source in artifacts],
      'tooling':own+lock['shared_scripts'],
      'dependencies':[{'id':x['id'],'name':x['name'],'type':'pypi','version':x['version'],'source':x['source'],'lockfile':'dependencies.lock.json','license':x['license'],'license_review':x['license_review']} for x in lock['python_packages']],
      'runtime_dependencies':lock['environment'],'third_party_tools':lock['jadx'],
      'code_paths':['decoders/Python/apps/XXPICore_Tunnel/codec.py','decoders/Python/apps/XXPICore_Tunnel/server_catalog_decoder.py','decoders/Python/apps/Xhypher_Tunnel_Pro/codec.py','decoders/Python/renz.py','cloud/workers/python/catalog_vpn_bridge.py','cloud/workers/python/engine.py','cloud/web/lib/server-vpn-provider.mjs','cloud/web/lib/server-vpn-catalog.mjs','cloud/web/lib/c12-provider-controls.mjs','cloud/web/lib/c3-gateway.mjs'],
      'evidence_refs':refs+['analysis/pro.xxpicore.tunnel/118/tests/test_method.py','cloud/web/tests/xxpicore-tunnel.test.mjs'],
      'fixture_hashes':{str(f.relative_to(ROOT)):digest(f) for f in sorted((HERE/'tests/fixtures').iterdir()) if f.is_file()},
      'limitations':['CBC/XXTEA have no authenticity tag; equality is compatibility evidence, not cryptographic origin attestation.','Live Node transport denied in this executor; real Python GET/CLI passed and real-byte Node replay passed.','Included raw resource is mode3 decryptDex input, not verified as included catalog.','JADX exit3 for DEX1 and DEX3; inspected relevant consumers and verified native primitives independently.','No APK/artifact build, emulator, merge, VPS rollout or Android changes.','Human review and central automatic Phase7 dependency approval pending; evidence CI not implemented.'],
      'network_requirements':['public fixed HTTPS updater; no provider token/session','normal proxy/TLS trust; never bypass network restrictions'],
      'manual_steps':['Review proposal before production; verify Node egress on VPS and preserve higher effective catalog versions and operator switches.'],
      'unresolved_questions':['Other builds and file/text/export formats not certified.','Latest Play build cannot be guaranteed by mirror latest.']}
    (HERE/'MANIFEST.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps({'safe_evidence_files':len(refs),'own_tools':len(own),'dependencies':len(manifest['dependencies']),'status':manifest['status']}))
if __name__=='__main__':main()
