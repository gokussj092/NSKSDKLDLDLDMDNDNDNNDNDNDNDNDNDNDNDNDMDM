#!/usr/bin/env python3
"""Build sanitized evidence from actual private reports, hashes and passing logs."""
import argparse,hashlib,json,platform,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];HERE=Path(__file__).resolve().parents[1]
BASE='28cb4057fadae5eeaf139f059bca4fba52e41ca9'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path,value):path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args();d=a.private
    lock=json.loads((HERE/'dependencies.lock.json').read_text())
    shared=['scripts/apk_analysis/inspect_apk.py','scripts/apk_analysis/decompile.py',
      'scripts/apk_analysis/paranoid_strings.py','scripts/apk_analysis/elf_inspect.py',
      'scripts/apk_analysis/bd_net_verify.py','tests/golden/bd_net_oracle.java','tests/golden/apna_oracle.java',
      'decoders/Python/apps/BD_NET_VPN/codec.py','analysis/com.halcon.connect/1391/tools/dependency_inventory.py']
    lock['shared_sources']=[{'path':s,'sha256':sha(ROOT/s),'source_commit':BASE} for s in shared]
    lock['environment']['node']=subprocess.run(['node','--version'],capture_output=True,text=True,check=True).stdout.strip()
    lock['environment']['readelf']=subprocess.run(['readelf','--version'],capture_output=True,text=True,check=True).stdout.splitlines()[0]
    lock['environment']['architecture']=platform.machine()
    save(HERE/'dependencies.lock.json',lock)
    checks=json.loads((d/'checks/checks.json').read_text());assert all(x['exit_code']==0 for x in checks)
    py=(d/'checks/python.log').read_text();node=(d/'checks/node.log').read_text()
    assert 'Ran 11 tests' in py and '\nOK\n' in py
    count=int(re.search(r'tests (\d+)',node)[1]);assert re.search(r'fail 0',node)
    generated=HERE/'generated';generated.mkdir(exist_ok=True)
    recovery=json.loads((d/'recovery-report.json').read_text())
    verify=json.loads((d/'verified/summary.json').read_text())
    save(generated/'recovery.json',recovery);save(generated/'verification.json',verify)
    save(generated/'checks.json',{'python_tests':11,'node_tests':count,'all_passed':True,'commands':checks,
      'initial_broader_attempt':'30/40 then50/52; partial checkout lacked fixtures/routes and wrong cwd. Materialized unchanged baseline inputs, used cloud/web cwd; final suite passed.',
      'node_real':{'status':'NETWORK_UNAVAILABLE','code':'REMOTE_NETWORK_DENIED'},
      'node_replay':{'status':'PASS','transport':'SIMULATED_HTTP_REAL_BYTES','version':'82.0','servers':28}})
    manifest=json.loads((HERE/'MANIFEST.json').read_text());manifest['status']='VERIFIED'
    samples=[('xapk',d/'FNF-TUNNEL-BD-35.xapk','APKPure exact build35 URL in REPRODUCE'),
      ('apk',d/'apks/dastan.prince.myvpnksa.apk','XAPK/base package APK'),
      ('included_catalog',d/'gremlin.json','assets/gremlin.json'),
      ('native_inspected_only',d/'libputils.so','config.arm64_v8a.apk/lib/arm64-v8a/libputils.so'),
      ('remote_catalog',d/'remote.enc','fixed original public updater in server_catalog_decoder.py'),
      ('icon',d/'inspected/icon.png','res/drawable/ic_app_icon.png')]
    manifest['inputs']=[{'type':kind,'bytes':path.stat().st_size,'sha256':sha(path),'source':source} for kind,path,source in samples]
    manifest['targets']=[{'kind':'catalog','status':'VERIFIED_REAL','remote_http':200,'remote_version':'82.0',
      'counts':verify[1]['counts'],'included_version':'49.9','included_counts':verify[0]['counts'],
      'java_cli_worker_whole_document_equal':True,'node_vps_transport':'PENDING'},
      {'kind':'files','status':'NOT_INVESTIGATED'},{'kind':'text','status':'NOT_INVESTIGATED'},
      {'kind':'export','status':'NOT_CERTIFIED'}]
    manifest['tooling']=[{'path':str(f.relative_to(ROOT)),'sha256':sha(f),
      'approval':'MANUAL_RESEARCH_NOT_APPROVED_FOR_AUTOMATIC_PHASE7'} for f in sorted((HERE/'tools').rglob('*')) if f.suffix in ('.py','.mjs')]
    manifest['shared_tooling']=lock['shared_sources']
    deps=[{'id':x['id'],'name':x['name'],'type':'PyPI','version':x['version'],'source':x['source'],
      'license':x['license'],'review':'NEEDS_REVIEW','lockfile':str((HERE/'dependencies.lock.json').relative_to(ROOT)),
      'use':'inspection environment; direct/transitive roles in DEPENDENCIES.md'} for x in lock['python_packages']]
    for name,ver,src,lic in [('CPython','3.12.14','https://www.python.org/','PSF'),
      ('OpenJDK','17.0.20','https://openjdk.org/','GPL-2.0 WITH Classpath-exception-2.0'),
      ('JADX','1.5.6','https://github.com/skylot/jadx','Apache-2.0'),
      ('Node.js','24.22.1','https://nodejs.org/','MIT and bundled component licenses'),
      ('curl','8.5.0','https://curl.se/','curl'),('GNU readelf','2.42','https://www.gnu.org/software/binutils/','GPL-3.0-or-later')]:
        deps.append({'id':name,'name':name,'type':'runtime/tool','version':ver,'source':src,'license':lic,
          'review':'MANUAL_USE_ONLY','lockfile':'dependencies.lock.json'})
    manifest['dependencies']=deps
    manifest['code_paths']={'codec':'decoders/Python/apps/FNF_TUNNEL_BD/codec.py',
      'cli':'decoders/Python/apps/FNF_TUNNEL_BD/server_catalog_decoder.py',
      'worker':'cloud/workers/python/catalog_vpn_bridge.py','engine':'cloud/workers/python/engine.py',
      'broker':'cloud/web/lib/server-vpn-provider.mjs','public_metadata':'cloud/web/lib/server-vpn-catalog.mjs',
      'controls':'cloud/web/lib/c12-provider-controls.mjs','contract':'cloud/web/lib/c3-gateway.mjs',
      'tests':['tests/test_fnf_tunnel_bd.py','cloud/web/tests/fnf-tunnel-bd.test.mjs']}
    manifest['evidence_refs']=['ANALYSIS.md','REPRODUCE.md','RESULTS.md','DEPENDENCIES.md',
      'generated/recovery.json','generated/verification.json','generated/checks.json']
    manifest['fixture_hashes']=[{'path':str(f.relative_to(HERE)),'sha256':sha(f)} for f in sorted((HERE/'tests/fixtures').iterdir())]
    manifest['limitations']=['APKPure sample; official Play signing equivalence/latest version unverified.',
      'JADX exit3 with18/9 errors; relevant catalog sources and independent real outputs checked.',
      'Node direct transport denied here; Node/VPS real test pending. Replay uses simulated HTTP.',
      'Catalog fields plaintext; no nested XOR or file/text/export support inferred.',
      'No Android changes/builds, merge or VPS deployment.',
      'No VPN connection/account functionality tested; unauthenticated XXTEA is not an integrity guarantee.',
      'PyPI archive hashes absent; transitive licensing and Phase7 automatic approval remain NEEDS_REVIEW.']
    manifest['unresolved_questions']=['Real Node transport and operator rollout in VPS.']
    save(HERE/'MANIFEST.json',manifest)
    uses={'androguard':'Manifiesto/APK; ejecutado.','capstone':'Desensamblado ARM64 offline; ejecutado.',
      'pyelftools':'Lectura ELF offline; ejecutado.','pillow':'Dimensiones del icono; ejecutado.',
      'loguru':'Inspector desactiva logs Androguard; ejecutado.'}
    rows=['| Paquete | Versión | Uso |','| --- | --- | --- |']
    rows += [f"|{x['name']}|{x['version']}|{uses.get(x['name'].lower(),'Instalado como parte del entorno/transitivas; no validado por separado.')}|" for x in lock['python_packages']]
    depsdoc=HERE/'DEPENDENCIES.md';s=depsdoc.read_text();s=s.split('<!-- PACKAGES -->')[0]+'<!-- PACKAGES -->\n'+'\n'.join(rows)+'\n';depsdoc.write_text(s)
    print(json.dumps({'status':'VERIFIED_REAL','python_tests':11,'node_tests':count,'private_inputs_not_copied':True}))
if __name__=='__main__':main()
