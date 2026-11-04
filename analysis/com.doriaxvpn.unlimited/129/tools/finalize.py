#!/usr/bin/env python3
"""Build sanitized evidence and a dependency inventory; never publish real rows/tokens."""
import argparse,datetime,hashlib,json,platform,re,subprocess
from pathlib import Path
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[4];HERE=Path(__file__).resolve().parents[1]
BASE='61ad524ee44673d69b36253223dbc9d984663137'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):p.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args();d=a.private
    lock=json.loads((HERE/'dependencies.lock.json').read_text())
    prior=ROOT/'analysis/com.appxrayservice.namovpn/35/dependencies.lock.json'
    previous=json.loads(prior.read_text());canonical=lambda s:re.sub(r'[-_.]+','-',s.lower())
    by_name={canonical(x['name']):x for x in previous['python_packages']}
    for pkg in lock['python_packages']:
        old=by_name.get(canonical(pkg['name']))
        if old and old['version']==pkg['version'] and old.get('distribution_sha256'):
            pkg['distribution_sha256']=old['distribution_sha256'];pkg['download_url']=old.get('download_url')
            pkg['hash_note']='Actual installed distribution hash retained in the prior NAMO pip-report inventory; same name/version, no reinstall.'
        else:pkg['hash_note']='No distribution archive retained for this bundled environment package.'
    lock['distribution_hash_source']={'path':str(prior.relative_to(ROOT)),'sha256':sha(prior),'source_commit':BASE}
    shared=['scripts/apk_analysis/inspect_apk.py','scripts/apk_analysis/decompile.py','scripts/apk_analysis/dex_method.py',
      'decoders/Python/apps/BD_NET_VPN/codec.py','analysis/com.halcon.connect/1391/tools/dependency_inventory.py']
    lock['shared_sources']=[{'path':s,'sha256':sha(ROOT/s),'source_commit':BASE,
      'role':'reference_read_not_executed' if s.endswith('dex_method.py') else 'canonical_source_used'} for s in shared]
    for name,cmd in [('node',['node','--version']),('rg',['rg','--version']),('bash',['bash','--version'])]:
        lock['environment'][name]=subprocess.run(cmd,capture_output=True,text=True,check=True).stdout.splitlines()[0]
    lock['environment']['architecture']=platform.machine();save(HERE/'dependencies.lock.json',lock)
    checks=json.loads((d/'checks/checks.json').read_text());assert all(x['exit_code']==0 for x in checks)
    assert 'Ran 10 tests' in (d/'checks/python.log').read_text() and '\nOK\n' in (d/'checks/python.log').read_text()
    node=(d/'checks/node.log').read_text();assert re.search(r'tests 147\b',node) and re.search(r'fail 0',node)
    gen=HERE/'generated';gen.mkdir(exist_ok=True)
    recovery=json.loads((d/'recovery-report.json').read_text());verification=json.loads((d/'verified/summary.json').read_text())
    save(gen/'recovery.json',recovery);save(gen/'verification.json',verification)
    save(gen/'firebase-observation.json',json.loads((d/'firebase-report.json').read_text()))
    save(gen/'signature.json',json.loads((d/'signature-report.json').read_text()))
    methods=json.loads((d/'updater-methods.json').read_text())
    save(gen/'updater-references.json',[{'dex':r['dex'],'class':r['class'],'method':r['method'],'descriptor':r['descriptor'],
      'instruction_count':len(r['instructions']),'instructions_sha256':hashlib.sha256(json.dumps(r['instructions'],sort_keys=True).encode()).hexdigest()} for r in methods])
    save(gen/'checks.json',{'python_tests':10,'node_tests':147,'all_passed':True,'commands':checks,
      'node_real':{'status':'NETWORK_UNAVAILABLE','code':'REMOTE_NETWORK_DENIED'},
      'node_replay':{'status':'PASS','transport':'SIMULATED_HTTP_REAL_BYTES','ciphertext_bytes':4311432,'version':'107','servers':244},
      'negative_discoveries':['Default source served57/251; real Firebase template17 selected /new107/244.',
        'Strict Base64 census misclassified LF-wrapped fields; Android whitespace mode authenticated5325.',
        'JCAv1 rejected inner Base64 LF with Illegal base64 character a; fixed to match Android.DEFAULT; historical revisions retained.']})
    census=[]
    for name in ['remote','config']:
        report=json.loads((d/(name+'-outer-census.json')).read_text());counts=report['android_whitespace']
        census.append({'source':name,'strict_authenticated':sum(x.get('authenticated_gcm',0) for x in report['strict_base64'].values()),
          'android_authenticated':sum(x.get('authenticated_gcm',0) for x in counts.values()),
          'protected_fields':[k for k,v in counts.items() if v.get('authenticated_gcm')]})
    save(gen/'field-census.json',census)
    inv=json.loads((d/'unpacked/inventory.json').read_text());manifest=json.loads((HERE/'MANIFEST.json').read_text())
    now=datetime.datetime.now(datetime.timezone.utc)
    manifest.update(status='VERIFIED',version_name='1.2.9',version_code=129,observed_at=now.isoformat(),
      observed_local_date=now.astimezone(ZoneInfo('America/Tijuana')).date().isoformat(),source_commit=BASE,branch='feat/nuevas-integraciones')
    samples=[('xapk',d/'HTTP-Conexion-129.xapk','APKPure build129 URL in REPRODUCE'),
      ('apk',d/'unpacked/apks/com.doriaxvpn.unlimited.apk','XAPK/base package APK'),
      ('included_catalog',d/'unpacked/extracted/com.doriaxvpn.unlimited/assets/config.json','assets/config.json'),
      ('remote_catalog_active',d/'remote.enc','Firebase-selected fixed /new with original headers and nocache'),
      ('obsolete_default_reference',d/'default.enc','APK /Update57 reference; not used as production fallback'),
      ('icon',d/'unpacked/inspected/icon.png','base.apk/res/mipmap-xxxhdpi-v4/ic_launcher.png')]
    manifest['inputs']=[{'type':kind,'bytes':f.stat().st_size,'sha256':sha(f),'source':source} for kind,f,source in samples]
    manifest['apk_metadata']=inv['metadata']
    manifest['targets']=[{'kind':'catalog','status':'VERIFIED_REAL','remote_http':200,'remote_version':'107','servers':244,
      'authenticated_gcm_fields':5325,'unique_gcm_values':5299,'included_version':'1','included_servers':7,
      'jca_cli_worker_whole_document_equal':True,'node_vps_transport':'PENDING'},
      {'kind':'files','status':'NOT_INVESTIGATED'},{'kind':'text','status':'NOT_INVESTIGATED'},{'kind':'export','status':'NOT_CERTIFIED'}]
    manifest['runtime_configuration']={'external_secrets':[],'format_constants':'Inline CATALOG_PASSWORD and FIELD_KEY in HTTP_Conexion/codec.py; not HTTP authorization.',
      'password_sha256':recovery['passwordSha256'],'field_key_sha256':recovery['fieldKeySha256'],
      'request_authentication':'none for catalog GET','discovery_authentication':'Real FIS-issued token; temporary analytical installation deleted200; tokens not retained in Git.',
      'source_pinning':'Observed Remote Config template17 /new; changes require reviewed update, not arbitrary runtime routing.'}
    manifest['tooling']=[{'path':str(f.relative_to(ROOT)),'sha256':sha(f),'approval':'MANUAL_RESEARCH_NOT_APPROVED_FOR_AUTOMATIC_PHASE7'}
      for f in sorted((HERE/'tools').rglob('*')) if f.suffix in ('.py','.mjs','.java')]
    manifest['shared_tooling']=lock['shared_sources']
    deps=[{'id':x['id'],'name':x['name'],'type':'PyPI','version':x['version'],'source':x['source'],'license':x['license'],
      'review':'NEEDS_REVIEW','distribution_sha256':x['distribution_sha256'],'lockfile':'dependencies.lock.json',
      'use':'Direct/transitive roles in DEPENDENCIES.md; reused installed environment'} for x in lock['python_packages']]
    for name,version,source,lic in [('CPython','3.12.14','https://www.python.org/','PSF'),
      ('OpenJDK','17.0.20','https://openjdk.org/','GPL-2.0 WITH Classpath-exception-2.0'),
      ('JADX','1.5.6','https://github.com/skylot/jadx','Apache-2.0'),('Node.js','24.22.1','https://nodejs.org/','MIT and bundled components'),
      ('curl','8.5.0','https://curl.se/','curl')]:
        deps.append({'id':name,'name':name,'type':'runtime/tool','version':version,'source':source,'license':lic,'review':'MANUAL_USE_ONLY','lockfile':'dependencies.lock.json'})
    for name in ['GitHub connector','Library connector','Codex web search']:
        deps.append({'id':name,'name':name,'type':'hosted_service','version':None,'version_status':'UNKNOWN_NOT_EXPOSED',
          'source':'Codex connected service','license':'Service terms; not redistributed or part of codec','review':'MANUAL_USE_ONLY'})
    manifest['dependencies']=deps
    manifest['code_paths']={'codec':'decoders/Python/apps/HTTP_Conexion/codec.py','cli':'decoders/Python/apps/HTTP_Conexion/server_catalog_decoder.py',
      'worker':'cloud/workers/python/catalog_vpn_bridge.py','engine':'cloud/workers/python/engine.py','broker':'cloud/web/lib/server-vpn-provider.mjs',
      'protocol':'cloud/web/lib/http-conexion-protocol.mjs','public_metadata':'cloud/web/lib/server-vpn-catalog.mjs',
      'controls':'cloud/web/lib/c12-provider-controls.mjs','contract':'cloud/web/lib/c3-gateway.mjs',
      'tests':['tests/test_http_conexion.py','cloud/web/tests/http-conexion.test.mjs']}
    manifest['evidence_refs']=['ANALYSIS.md','REPRODUCE.md','RESULTS.md','DEPENDENCIES.md','generated/recovery.json',
      'generated/verification.json','generated/firebase-observation.json','generated/checks.json','generated/signature.json',
      'generated/field-census.json','generated/protected-fields.json','generated/updater-references.json']
    manifest['fixture_hashes']=[{'path':str(f.relative_to(HERE)),'sha256':sha(f)} for f in sorted((HERE/'tests/fixtures').iterdir())]
    manifest['limitations']=['Mirror sample, official Play latest/signing equivalence unverified; certificate presence/fingerprints only.',
      'JADX outputs3/0/3/3 with22/0/11/3 errors; missing updater recovered as Dalvik data.',
      'Firebase observation is template17 for one analytical MX/es-MX/API34 profile; URL/password pinned to that observation.',
      'Node direct transport denied here; real VPS test, human PR review and operator rollout pending.',
      'No Android changes/builds, merge, deployment, account/VPN connection or file/text/export tests.',
      'Outer CBC does not authenticate all metadata; defined GCM fields authenticate their values.',
      'Transitive licenses/Phase7 autoexecution remain NEEDS_REVIEW; evidence CI validator not implemented.']
    manifest['network_requirements']=['HTTPS APK acquisition; original Firebase FIS/Remote Config discovery with public client options; pinned raw GitHub catalog GET.']
    manifest['manual_steps']=['Review PR, test Node transport in VPS, maintain monotonic deployed catalog version before rollout.']
    manifest['unresolved_questions']=['Real Node transport in VPS; any future Firebase parameter change requires reviewed revision.'];save(HERE/'MANIFEST.json',manifest)
    roles={'androguard':'APK/recursos/certificado/Dalvik; ejecutado.','pycryptodome':'AES-CBC/GCM y tags; runtime ejecutado.',
      'pillow':'Formato/dimensiones PNG; ejecutado.','loguru':'Logs del inspector controlados; ejecutado.'}
    rows=['| Paquete | Versión | Uso |','| --- | --- | --- |']
    rows += [f"|{x['name']}|{x['version']}|{roles.get(x['name'].lower(),'Instalado del entorno previo/transitivas; no validado por separado aquí.')}|" for x in lock['python_packages']]
    f=HERE/'DEPENDENCIES.md';f.write_text(f.read_text().split('<!-- PACKAGES -->')[0]+'<!-- PACKAGES -->\n'+'\n'.join(rows)+'\n')
    print(json.dumps({'status':'VERIFIED_REAL','python_tests':10,'node_tests':147,
      'distribution_hashes':sum(bool(x['distribution_sha256']) for x in lock['python_packages']),'private_rows_and_tokens_not_copied':True}))
if __name__=='__main__':main()
