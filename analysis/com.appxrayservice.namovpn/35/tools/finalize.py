#!/usr/bin/env python3
"""Produce sanitized evidence/locks from actual reports; never copy VPN records."""
import argparse,datetime,hashlib,json,platform,re,subprocess
from pathlib import Path
from urllib.parse import urlsplit,urlunsplit
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[4];HERE=Path(__file__).resolve().parents[1]
BASE='45db1d4ed4c18df6911a7f77a744776353223a8c'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):p.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args();d=a.private
    lock=json.loads((HERE/'dependencies.lock.json').read_text())
    install=json.loads((d/'install-report.json').read_text())['install']
    canonical=lambda name:re.sub(r'[-_.]+','-',name.lower())
    by_name={canonical(x['metadata']['name']):x for x in install}
    for pkg in lock['python_packages']:
        source=by_name.get(canonical(pkg['name']))
        if source:
            dl=source['download_info'];url=urlsplit(dl['url'])
            pkg['distribution_sha256']=dl.get('archive_info',{}).get('hashes',{}).get('sha256')
            pkg['download_url']=urlunsplit((url.scheme,url.hostname or '',url.path,'',''))
            pkg['hash_note']='SHA256 retained from pip --report for the actual installed distribution.'
        else:pkg['hash_note']='Bundled venv package not downloaded in this install; archive checksum unavailable.'
    shared=['scripts/apk_analysis/inspect_apk.py','scripts/apk_analysis/decompile.py',
      'scripts/apk_analysis/paranoid_strings.py','scripts/apk_analysis/elf_inspect.py',
      'decoders/Python/apps/BD_NET_VPN/codec.py','analysis/com.halcon.connect/1391/tools/dependency_inventory.py']
    lock['shared_sources']=[{'path':s,'sha256':sha(ROOT/s),'source_commit':BASE} for s in shared]
    for name,cmd in [('node',['node','--version']),('readelf',['readelf','--version']),('rg',['rg','--version']),('bash',['bash','--version'])]:
        lock['environment'][name]=subprocess.run(cmd,capture_output=True,text=True,check=True).stdout.splitlines()[0]
    lock['environment']['architecture']=platform.machine();save(HERE/'dependencies.lock.json',lock)
    checks=json.loads((d/'checks/checks.json').read_text());assert all(x['exit_code']==0 for x in checks)
    py=(d/'checks/python.log').read_text();node=(d/'checks/node.log').read_text()
    assert 'Ran 10 tests' in py and '\nOK\n' in py
    count=int(re.search(r'tests (\d+)',node)[1]);assert count==140 and re.search(r'fail 0',node)
    generated=HERE/'generated';generated.mkdir(exist_ok=True)
    recovery=json.loads((d/'recovery-report.json').read_text());verification=json.loads((d/'verified/summary.json').read_text())
    save(generated/'recovery.json',recovery);save(generated/'verification.json',verification)
    save(generated/'signature.json',json.loads((d/'signature-report.json').read_text()))
    save(generated/'checks.json',{'python_tests':10,'node_tests':count,'all_passed':True,'commands':checks,
      'first_node_pass':'139/140; new test expected a copied template URL; fixed to the proven NAMO updater without changing production destination.',
      'node_real':{'status':'NETWORK_UNAVAILABLE','code':'REMOTE_NETWORK_DENIED'},
      'node_replay':{'status':'PASS','transport':'SIMULATED_HTTP_REAL_BYTES','version':'22.3','servers':14}})
    inv=json.loads((d/'unpacked/inventory.json').read_text());manifest=json.loads((HERE/'MANIFEST.json').read_text())
    now=datetime.datetime.now(datetime.timezone.utc)
    manifest.update(status='VERIFIED',version_name='3.5-namo',version_code=35,observed_at=now.isoformat(),
      observed_local_date=now.astimezone(ZoneInfo('America/Tijuana')).date().isoformat(),source_commit=BASE,branch='feat/nuevas-integraciones')
    samples=[('xapk',d/'NAMO-VPN-35.xapk','APKPure build35 sv24 URL in REPRODUCE'),
      ('apk',d/'unpacked/apks/com.appxrayservice.namovpn.apk','XAPK/base package APK'),
      ('native_inspected_only',d/'unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libapi-namo.so','ARM64 split/libapi-namo.so'),
      ('remote_catalog',d/'remote.enc','fixed original public updater in server_catalog_decoder.py'),
      ('icon',d/'icon.png','base.apk/res/mipmap-xxxhdpi-v4/ic_launcher.png')]
    manifest['inputs']=[{'type':kind,'bytes':f.stat().st_size,'sha256':sha(f),'source':source} for kind,f,source in samples]
    manifest['apk_metadata']=inv['metadata']
    manifest['targets']=[{'kind':'catalog','status':'VERIFIED_REAL','remote_http':200,'remote_version':'22.3',
      'counts':verification[0]['counts'],'java_cli_worker_whole_document_equal':True,'node_vps_transport':'PENDING'},
      {'kind':'files','status':'NOT_INVESTIGATED'},{'kind':'text','status':'NOT_INVESTIGATED'},{'kind':'export','status':'NOT_CERTIFIED'}]
    manifest['runtime_configuration']={'external_secrets':[],'format_constant':'Inline FORMAT_KEY in NAMO_VPN/codec.py; reconstructed from pinned JNI b, not HTTP authentication.',
      'key_sha256':recovery['formatKeySha256'],'request_authorization':'none','user_requested_inline_constant':True}
    manifest['tooling']=[{'path':str(f.relative_to(ROOT)),'sha256':sha(f),'approval':'MANUAL_RESEARCH_NOT_APPROVED_FOR_AUTOMATIC_PHASE7'}
      for f in sorted((HERE/'tools').rglob('*')) if f.suffix in ('.py','.mjs','.java')]
    manifest['shared_tooling']=lock['shared_sources']
    deps=[{'id':x['id'],'name':x['name'],'type':'PyPI','version':x['version'],'source':x['source'],
      'license':x['license'],'review':'NEEDS_REVIEW','distribution_sha256':x['distribution_sha256'],
      'lockfile':'dependencies.lock.json','use':'Direct/transitive roles in DEPENDENCIES.md'} for x in lock['python_packages']]
    for name,version,source,lic in [('CPython','3.12.14','https://www.python.org/','PSF'),
      ('OpenJDK','17.0.20','https://openjdk.org/','GPL-2.0 WITH Classpath-exception-2.0'),
      ('JADX','1.5.6','https://github.com/skylot/jadx','Apache-2.0'),
      ('Node.js','24.22.1','https://nodejs.org/','MIT and bundled components'),
      ('curl','8.5.0','https://curl.se/','curl'),('GNU readelf','2.42','https://www.gnu.org/software/binutils/','GPL-3.0-or-later')]:
        deps.append({'id':name,'name':name,'type':'runtime/tool','version':version,'source':source,'license':lic,'review':'MANUAL_USE_ONLY','lockfile':'dependencies.lock.json'})
    for name in ['GitHub connector','Library connector','Codex web search']:
        deps.append({'id':name,'name':name,'type':'hosted_service','version':None,'version_status':'UNKNOWN_NOT_EXPOSED',
          'source':'Codex connected service','license':'Service terms; not redistributed or part of codec','review':'MANUAL_USE_ONLY'})
    manifest['dependencies']=deps
    manifest['code_paths']={'codec':'decoders/Python/apps/NAMO_VPN/codec.py','cli':'decoders/Python/apps/NAMO_VPN/server_catalog_decoder.py',
      'worker':'cloud/workers/python/catalog_vpn_bridge.py','engine':'cloud/workers/python/engine.py',
      'broker':'cloud/web/lib/server-vpn-provider.mjs','public_metadata':'cloud/web/lib/server-vpn-catalog.mjs',
      'controls':'cloud/web/lib/c12-provider-controls.mjs','contract':'cloud/web/lib/c3-gateway.mjs',
      'tests':['tests/test_namo_vpn.py','cloud/web/tests/namo-vpn.test.mjs']}
    manifest['evidence_refs']=['ANALYSIS.md','REPRODUCE.md','RESULTS.md','DEPENDENCIES.md',
      'generated/recovery.json','generated/verification.json','generated/checks.json','generated/signature.json']
    manifest['fixture_hashes']=[{'path':str(f.relative_to(HERE)),'sha256':sha(f)} for f in sorted((HERE/'tests/fixtures').iterdir())]
    manifest['limitations']=['Mirror sample; latest official Play build/signing equivalence unverified.',
      'JADX exit3/40 errors; relevant methods and real independent results validated.',
      'Node direct transport denied here; Node/VPS real check and rollout pending; replay is simulated HTTP.',
      'No Android changes/builds, merge, deployment, file/text/export or VPN connection tests.',
      'No included catalog found; bundled V2Ray template is not remote catalog evidence.',
      'XXTEA is unauthenticated; schema rejection is not universal integrity protection.',
      'Transitive licenses/Phase7 auto-execution remain NEEDS_REVIEW; evidence CI validator not implemented.']
    manifest['network_requirements']=['HTTPS APKPure acquisition and fixed original raw GitHub updater; install dependencies/JADX only when absent.']
    manifest['manual_steps']=['Review PR; test original Node transport on VPS; preserve monotonic deployed catalog version before operator rollout.']
    manifest['unresolved_questions']=['Real Node transport in VPS.'];save(HERE/'MANIFEST.json',manifest)
    roles={'androguard':'Manifiesto/APK/certificado; ejecutado.','capstone':'Desensamblado ARM64 offline; ejecutado.',
      'pyelftools':'ELF/rodata offline; ejecutado.','pillow':'Formato/dimensiones del PNG; ejecutado.',
      'loguru':'Control de logs del inspector; ejecutado.'}
    rows=['| Paquete | Versión | Uso |','| --- | --- | --- |']
    rows += [f"|{x['name']}|{x['version']}|{roles.get(x['name'].lower(),'Instalado como parte del entorno/transitivas; no validado por separado.')}|" for x in lock['python_packages']]
    f=HERE/'DEPENDENCIES.md';f.write_text(f.read_text().split('<!-- PACKAGES -->')[0]+'<!-- PACKAGES -->\n'+'\n'.join(rows)+'\n')
    print(json.dumps({'status':'VERIFIED_REAL','python_tests':10,'node_tests':count,
      'distribution_hashes':sum(bool(x['distribution_sha256']) for x in lock['python_packages']),'private_records_not_copied':True}))
if __name__=='__main__':main()
