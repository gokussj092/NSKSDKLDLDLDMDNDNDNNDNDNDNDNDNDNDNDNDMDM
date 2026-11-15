#!/usr/bin/env python3
"""Publish sanitized PARTIAL/PENDING evidence, never a verified remote method."""
import argparse,hashlib,importlib.metadata,json,platform,re,subprocess
from datetime import datetime,timezone
from pathlib import Path
from cryptography.hazmat.backends.openssl.backend import backend
ROOT=Path(__file__).resolve().parents[4];HERE=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):p.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args();d=a.private
    inventory=json.loads((d/'unpacked/inventory.json').read_text());meta=inventory['metadata']
    assert meta['package']=='noob.arpro.vpn' and meta['versionCode']=='2'
    verify=json.loads((d/'verification-pending.json').read_text());assert verify['enabled'] is False and verify['remote_whole_document_verified'] is False
    log=(d/'checks.log').read_text();assert 'Ran 5 tests' in log and '\nOK\n' in log
    bootstrap=json.loads((d/'remote/probe.json').read_text());configured=json.loads((d/'configured-probe.json').read_text())
    assert bootstrap['html'] and next(x for x in configured if x['role']=='configured-catalog')['html']
    recovery=json.loads((d/'recovery.json').read_text())
    own=[{'path':str(f.relative_to(ROOT)),'sha256':sha(f),'approval':'UNREVIEWED_MANUAL_RESEARCH_ONLY'}
        for f in sorted((HERE/'tools').rglob('*')) if f.is_file() and f.suffix in ('.py','.java')]
    shared=[{'path':name,'sha256':sha(ROOT/name),'source_commit':'8ce1af86f0e3e2a9732b11eb8d68cb52ed40c76d'}
        for name in ['scripts/apk_analysis/inspect_apk.py','scripts/apk_analysis/decompile.py','scripts/apk_analysis/elf_inspect.py',
            'analysis/net.catnet.vpn/27/tools/dex_trace.py','analysis/com.halcon.connect/1391/tools/dependency_inventory.py']]
    lock=json.loads((HERE/'dependencies.lock.json').read_text());lock['shared_sources']=shared
    lock['installed_scope']='Reused analysis environment; all installed packages inventoried, no new installations and no claim all executed.'
    lock['environment']['openssl_cryptography']=backend.openssl_version_text()
    lock['environment']['architecture']=platform.machine()
    lock['environment']['readelf']=subprocess.run(['readelf','--version'],capture_output=True,text=True,check=True).stdout.splitlines()[0]
    save(HERE/'dependencies.lock.json',lock)
    dependencies=[{'id':v['id'],'name':v['name'],'type':'PyPI','version':v['version'],'source':v['source'],
        'license':v['license'],'review':v['license_review'],'distribution_sha256':None,'lockfile':'dependencies.lock.json'} for v in lock['python_packages']]
    for name,version,source,license in [('CPython','3.12.14','https://python.org','PSF'),
        ('OpenJDK','17.0.20+8','https://openjdk.org','GPLv2 with Classpath Exception'),
        ('JADX','1.5.6','https://github.com/skylot/jadx/releases/tag/v1.5.6','Apache-2.0'),
        ('curl','8.5.0','https://curl.se','curl license'),('ripgrep','15.2.0','https://github.com/BurntSushi/ripgrep','MIT/Unlicense'),
        ('readelf','2.42','https://www.gnu.org/software/binutils/','GPLv3+'),('Bash','5.2.21','https://www.gnu.org/software/bash/','GPLv3+')]:
        dependencies.append({'id':'tool:'+name,'name':name,'version':version,'source':source,'license':license,
            'review':'MANUAL_USE_NOT_AUTOMATIC_PHASE7_APPROVAL','lockfile':'dependencies.lock.json'})
    inputs=[]
    for kind,path,source in [('xapk',d/'ARPRO-latest.xapk','https://d.apkpure.com/b/XAPK/noob.arpro.vpn?version=latest; pinned by hash'),
        ('apk',d/'unpacked/apks/noob.arpro.vpn.apk','XAPK base'),
        ('native_inspected_only',d/'unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libovpn3.so','ARM64 split/libovpn3.so'),
        ('included_resource',d/'noobdev.js','base/res/raw/noobdev.js'),
        ('remote_html',d/'remote/remote.enc',bootstrap['source'])]:
        inputs.append({'type':kind,'bytes':path.stat().st_size,'sha256':sha(path),'source':source})
    inputs.extend({'type':x['role'],'bytes':x['bytes'],'sha256':x['sha256'],'source':x['source'],'http':x['http']} for x in configured)
    checks={'tests':5,'status':'PASS','scope':'Research only; does not certify complete remote catalog',
        'command':'python -m unittest discover -s analysis/noob.arpro.vpn/2/tests -v','log_sha256':sha(d/'checks.log')}
    for name,value in [('verification',verify),('bootstrap',bootstrap),('configured-sources',configured),('recovery',recovery),('checks',checks)]:
        save(HERE/'generated'/(name+'.json'),value)
    manifest={'schema_version':1,'package_name':'noob.arpro.vpn','app_name':'AR PRO VPN','version_name':'2.0','version_code':2,
        'observed_at':datetime.now(timezone.utc).isoformat(),'source_category':'user_store_link_public_mirror',
        'authorization_note':'User requested Cloud catalog investigation/integration, strictly no Android compilation or waiting for artifacts. No deployment/merge requested.',
        'status':'PARTIAL','enabled':False,'public_catalog_changed':False,
        'targets':[{'kind':'catalog','status':'PENDING','network':'Both observed catalog sources return HTTP200 HTML195bytes here',
            'whole_remote_json_verified':False,'enabled':False},
            {'kind':'included_catalog','status':'PARTIAL','outer_json_opened':True,'servers':1,'tweaks':1,
             'root_gcm_metadata_verified':True,'all_fields_decoded':False,'independent_xts_oracle':'PENDING','enabled':False},
            {'kind':'files','status':'NOT_INVESTIGATED'},{'kind':'text','status':'NOT_INVESTIGATED'},{'kind':'export','status':'NOT_CERTIFIED'}],
        'inputs':inputs,'tooling':own,'shared_tooling':shared,'dependencies':dependencies,
        'code_paths':{'production_provider':None,'research':'analysis/noob.arpro.vpn/2/tools/recover.py',
            'tests':'analysis/noob.arpro.vpn/2/tests/test_research.py'},
        'evidence_refs':['ANALYSIS.md','RESULTS.md','REPRODUCE.md','DEPENDENCIES.md','generated/verification.json',
            'generated/bootstrap.json','generated/configured-sources.json','generated/recovery.json','generated/checks.json'],
        'fixture_hashes':[{'path':'tests/fixtures/site-unavailable.html','sha256':sha(HERE/'tests/fixtures/site-unavailable.html'),
            'scope':'Observed public HTML error only; no profile/user data'}],
        'limitations':['No complete remote catalog; provider remains inactive.','Included outer JSON is not remote evidence; all fields and independent XTS oracle remain pending.',
            'JADX exit3/38 errors; primary DEX analyzed, secondary only inventoried; dynamic string arrays unresolved.',
            'Mirror sample; no latest official build/signature equivalence certified.','Response observed in this environment does not prove global provider outage.',
            'No APK/JNI/SO execution, authentication/attestation bypass, Android builds, artifacts, deployment or merge.',
            'Distribution hashes unknown in reused environment; license/automatic Phase7 approval remains pending; evidence CI validator not implemented.'],
        'network_requirements':['Original fixed catalog HTTPS URLs and original app-update metadata; inherited proxy/TLS maintained.'],
        'manual_steps':['Retry original catalog endpoints when reachable; require entire real JSON and all field layers independently verified before enabling a provider.'],
        'unresolved_questions':['Actual complete remote catalog bytes.','Independent AES-XTS reference and complete per-field mapping.',
            'Any device/network-specific reason for the HTML responses.'],
        'source_commit':'8ce1af86f0e3e2a9732b11eb8d68cb52ed40c76d','branch':'feat/nuevas-integraciones','apk_metadata':meta,
        'catalog_unchanged':{'floor':72,'apps':66,'formats':256}}
    save(HERE/'MANIFEST.json',manifest)
    print(json.dumps({'status':'PARTIAL','enabled':False,'research_tests':5,'own_tools':len(own),
        'direct_versions':{name:importlib.metadata.version(name) for name in ['cryptography','pycryptodome','androguard','capstone','pyelftools']}}))
if __name__=='__main__':main()
