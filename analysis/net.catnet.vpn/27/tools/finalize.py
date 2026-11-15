#!/usr/bin/env python3
"""Finalize sanitized CATNET evidence; require complete server and check results."""
import argparse,hashlib,json,platform,subprocess
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];DOSSIER=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,value):p.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args();d=a.private
    inventory=json.loads((d/'unpacked/inventory.json').read_text())
    assert inventory['metadata']['package']=='net.catnet.vpn' and inventory['metadata']['versionCode']=='27'
    checks=json.loads((d/'checks/checks.json').read_text());assert [(r['exit_code'],r['tests']) for r in checks]==[(0,12),(0,15),(0,181)]
    verification=json.loads((d/'verified/summary.json').read_text());assert len(verification)==2
    assert all(r['servers']==6 and r['node_python_cli_worker_whole_equal'] for r in verification)
    probe=json.loads((d/'remote/probe-summary.json').read_text());assert probe['outcome']=='PREFLIGHT_ALLOWS_PUBLIC_CONFIG'
    sources=json.loads((d/'source-evidence.json').read_text());icon=json.loads((d/'icon-report.json').read_text())
    signature=json.loads((d/'signature.json').read_text())
    node_real=json.loads((d/'node-real.json').read_text());node_replay=json.loads((d/'node-replay.json').read_text())
    assert node_replay['whole_worker_equal'] and node_replay['calls']==2
    tools=[{'path':str(f.relative_to(ROOT)),'sha256':sha(f),'origin':'project-owned manual research',
        'approval':'UNREVIEWED_FOR_AUTOMATIC_PHASE_7'} for f in sorted((DOSSIER/'tools').rglob('*'))
        if f.is_file() and f.suffix in ('.py','.mjs')]
    lock=json.loads((DOSSIER/'dependencies.lock.json').read_text())
    lock['environment']['node']=subprocess.run(['node','--version'],capture_output=True,text=True,check=True).stdout.strip()
    lock['environment']['architecture']=platform.machine()
    lock['installed_scope']='42 installed packages for reproducibility, not a claim that all packages were executed. No new installations.'
    shared=[]
    for name in ['scripts/apk_analysis/inspect_apk.py','scripts/apk_analysis/decompile.py',
        'analysis/com.halcon.connect/1391/tools/dependency_inventory.py','decoders/Python/apps/BD_NET_VPN/codec.py']:
        shared.append({'path':name,'sha256':sha(ROOT/name),'source_commit':'2b7c842aa5ff67ec276aeaebded982e4c1eea121'})
    lock['shared_sources']=shared;save(DOSSIER/'dependencies.lock.json',lock)
    dependencies=[{'id':r['id'],'name':r['name'],'type':'PyPI','version':r['version'],
        'source':r['source'],'license':r['license'],'review':r['license_review'],
        'distribution_sha256':r['distribution_sha256'],'lockfile':'dependencies.lock.json'} for r in lock['python_packages']]
    for name,version,source,license in [('CPython','3.12.14','https://www.python.org/','PSF'),
        ('Node.js','24.22.1','https://nodejs.org/','MIT'),('OpenJDK','17.0.20+8','https://openjdk.org/','GPLv2 with Classpath Exception'),
        ('JADX','1.5.6','https://github.com/skylot/jadx/releases/tag/v1.5.6','Apache-2.0'),
        ('curl','8.5.0','https://curl.se/','curl license'),('ripgrep','15.2.0','https://github.com/BurntSushi/ripgrep','MIT/Unlicense'),
        ('Bash','5.2.21','https://www.gnu.org/software/bash/','GPLv3+')]:
        dependencies.append({'id':'tool:'+name,'name':name,'type':'runtime/tool','version':version,
            'source':source,'license':license,'lockfile':'dependencies.lock.json','review':'MANUAL_USE_NOT_PHASE7_APPROVAL'})
    inputs=[{'type':'xapk','bytes':inventory['bundleBytes'],'sha256':inventory['bundleSha256'],
        'source':'https://d.apkpure.com/b/XAPK/net.catnet.vpn?version=latest; pinned by hash, not future latest guarantee'},
        {'type':'apk','bytes':(d/'unpacked/apks/net.catnet.vpn.apk').stat().st_size,
         'sha256':inventory['metadata']['baseSha256'],'source':'XAPK/net.catnet.vpn.apk'},
        {'type':'native_inspected_only','bytes':6488968,
         'sha256':'93fe1e794ea5a008b6a6ff168167a93cd88bbe1a53525d0a4ead78c04cb1bb04','source':'ARM64 libapp.so'},
        {'type':'icon','bytes':icon['bytes'],'sha256':icon['sha256'],'source':icon['source']}]
    inputs.extend({'type':'remote_'+('servers' if r['source'].endswith('/servers') else 'preflight' if 'app-update?' in r['source'] else 'payload_unavailable'),
        'bytes':r['bytes'],'sha256':r['sha256'],'source':r['source'],'http_status':r['status']} for r in probe['requests'])
    report={'checks':checks,'verification':verification,'probe':probe,'source_trace':sources,'icon':icon,
        'signature':signature,'node_real':node_real,'node_replay':node_replay,
        'initial_python':'11/12; opener OSError handling corrected, 12/12 final',
        'scope':'Complete public servers only; no payload/xray success asserted','catalog_floor':72,'cards':66,'formats':256}
    for name,value in [('verification',verification),('probe',probe),('source-trace',sources),('checks',checks),
        ('icon',icon),('signature',signature),('results',report)]:save(DOSSIER/'generated'/(name+'.json'),value)
    manifest={'schema_version':1,'package_name':'net.catnet.vpn','app_name':'CATNET VPN | FAST SECURE VPN',
        'version_name':'1.2.5','version_code':27,'observed_at':datetime.now(timezone.utc).isoformat(),
        'source_category':'user_store_link_public_mirror','authorization_note':'User requested Cloud catalog integration using the original client flow, no Android build, merge or deployment.',
        'status':'VERIFIED','targets':[
            {'kind':'catalog','source':'mobile/public/servers','status':'VERIFIED_REAL','enabled_scope':'complete servers document',
             'http':200,'remote_version':None,'remote_version_note':'API does not publish a catalog version field','servers':6,
             'node_python_cli_worker_whole_equal':True,'node_vps_transport':'PENDING'},
            {'kind':'catalog_payloads','source':'mobile/public/payloads','status':'NETWORK_UNAVAILABLE','enabled':False,'http':200,'body':'HTML Site Unavailable'},
            {'kind':'catalog_xray_payloads','source':'mobile/public/xray_payloads','status':'NETWORK_UNAVAILABLE','enabled':False,'http':200,'body':'HTML Site Unavailable'},
            {'kind':'files','status':'STATIC_OBSERVATION_ONLY','enabled':False},
            {'kind':'text','status':'NOT_CERTIFIED','enabled':False},{'kind':'export','status':'NOT_CERTIFIED','enabled':False}],
        'inputs':inputs,'tooling':tools,'shared_tooling':shared,'dependencies':dependencies,
        'code_paths':{'codec':'decoders/Python/apps/CATNET_VPN/codec.py','cli':'decoders/Python/apps/CATNET_VPN/server_catalog_decoder.py',
            'bridge':'cloud/workers/python/catalog_vpn_bridge.py','engine':'cloud/workers/python/engine.py',
            'protocol':'cloud/web/lib/catnet-protocol.mjs','broker':'cloud/web/lib/server-vpn-provider.mjs',
            'contract':'cloud/web/lib/c3-gateway.mjs','controls':'cloud/web/lib/c12-provider-controls.mjs',
            'catalog':'cloud/web/lib/server-vpn-catalog.mjs','tests':['tests/test_catnet_vpn.py','cloud/web/tests/catnet-vpn.test.mjs']},
        'evidence_refs':['ANALYSIS.md','REPRODUCE.md','RESULTS.md','DEPENDENCIES.md','generated/results.json','tests/test_method.py'],
        'fixture_hashes':[{'path':str(f.relative_to(DOSSIER)),'sha256':sha(f)} for f in sorted((DOSSIER/'tests/fixtures').iterdir()) if f.is_file()],
        'limitations':['Mirror build; no latest official Play or signing equivalence certified.','JADX partial exit3/54 errors; missing interceptor inspected via DEX.',
            'Payload/xray routes return HTML200 and are NOT integrated; no combined snapshot claimed.',
            'No encryption layer observed in this server API; local encrypted files/links not certified.',
            'If Integrity is required, stop; no device token/session fabrication.','Node real transport pending on VPS; replay HTTP is simulated.',
            'No VPN/account tests, Android changes/builds, merge or deployment.','Distribution archive hashes unknown in reused analysis venv; licenses/transitive tools need review.',
            'Phase7 automatic reuse not approved; evidence CI validator not implemented.'],
        'network_requirements':['HTTPS APKPure acquisition; original fixed pussyvpn.com preflight and server routes. xjdev.net only investigated, not operationally requested.'],
        'manual_steps':['Review PR, verify real Node transport on VPS, bump effective configured catalog version monotonically before operator rollout.'],
        'unresolved_questions':['Payload/xray service availability.','Real Node transport on VPS.'],
        'source_commit':'2b7c842aa5ff67ec276aeaebded982e4c1eea121','branch':'feat/nuevas-integraciones',
        'apk_metadata':inventory['metadata'],'runtime_configuration':{'external_secrets':[],'static_app_key':'public client identifier from APK, inline',
            'preflight_required':'integrity_required must be exactly false; otherwise fail closed','catalog_floor':72,'cards':66,'formats':256}}
    save(DOSSIER/'MANIFEST.json',manifest)
    print(json.dumps({'servers':6,'python_tests':27,'node_tests':181,'own_tools':len(tools),'private_values_published':False}))
if __name__=='__main__':main()
