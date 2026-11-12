#!/usr/bin/env python3
"""Update the existing evidence dossier without publishing runtime credentials."""
import argparse
import datetime
import hashlib
import importlib.metadata as metadata
import json
import re
from pathlib import Path

ROOT=Path(__file__).resolve().parents[5]
DOSSIER=Path(__file__).resolve().parents[2]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args();d=a.private
    generated=DOSSIER/'generated/refresh-2026-11-04';generated.mkdir(parents=True,exist_ok=True)
    reports={}
    for name in ['options-report','firebase-report','auto-verification','node-real','node-replay']:
        value=json.loads((d/(name+'.json')).read_text());reports[name]=value
        (generated/(name+'.json')).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
    results=json.loads((d/'checks/checks.json').read_text());assert all(x['exit_code']==0 for x in results)
    py=[int(re.search(r'Ran (\d+) tests',(d/'checks'/name).read_text())[1]) for name in ['python-http.log','python-genis.log']]
    node=int(re.search(r'ℹ tests (\d+)',(d/'checks/node.log').read_text())[1])
    lock=json.loads((DOSSIER/'dependencies.lock.json').read_text())
    for item in lock['python_packages']:assert metadata.version(item['name'])==item['version'],item['name']
    summary={'python_http':py[0],'python_genis_regression':py[1],'python_total':sum(py),'node_total':node,
      'all_passed':True,'commands':results,'real_firebase_download_jca_cli_worker':reports['auto-verification'],
      'dependency_versions_match_lock':True,'new_packages_installed':False,'catalog_floor':70,'cards':65,'formats':256,
      'android_changes':False,'android_build':False,'merge':False,'deploy':False}
    (generated/'checks.json').write_text(json.dumps(summary,indent=2)+'\n')
    path=DOSSIER/'MANIFEST.json';m=json.loads(path.read_text())
    m['observed_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();m['observed_local_date']='2026-11-04'
    m['latest_update_source_commit']='af4955fb87a27a3feb1b43469d9356f32afcccab'
    m['targets'][0]['firebase_auto_refresh']='VERIFIED_REAL_PYTHON_AND_SYNTHETIC_NODE_TRANSPORT'
    m['targets'][0]['config_cache_seconds']=3600;m['targets'][0]['max_forced_refresh_retry']=1
    m['runtime_configuration']={
      'external_secrets':[],'public_client_options':'Inline public build129 Android Firebase options, extracted from exact APK.',
      'format_constants':'FIELD_KEY and legacy offline password in codec.py; live outer password read from Firebase, passed per operation.',
      'field_key_sha256':m['runtime_configuration']['field_key_sha256'],
      'last_observed_outer_password_sha256':reports['auto-verification']['password_sha256'],
      'request_authentication':'No credentials for catalog GET. FIS-issued credentials restricted to fixed Google endpoints, held only in memory.',
      'config_resolution':'ockla_url and gretta_pass fetched together; 3600s per-process cache, 60s failure cooldown, one forced refresh on download/decode failure.',
      'source_policy':'Canonical HTTPS raw.githubusercontent.com only, variable repository/path; no credentials/query/fragment/redirect/client-supplied URL.',
      'worker_contract':'spdecode-http-conexion-config-v1: catalogBase64 and passwordBase64; worker remains offline; total8MiB limit.',
      'installation_lifecycle':'Temporary analytical FIS installation, best-effort DELETE; observed200; no minted tokens persisted by runtime.'}
    for item in m['inputs']:
        if item['type']=='remote_catalog_active':item['source']='Live Firebase-selected approved raw GitHub URL; original headers and nocache'
    m['code_paths'].update(firebase_python='decoders/Python/apps/HTTP_Conexion/firebase.py',
      firebase_node='cloud/web/lib/http-conexion-firebase.mjs',retry_gateway='cloud/web/lib/server-vpn-gateway.mjs')
    for name in ['tests/test_http_conexion_refresh.py','cloud/web/tests/http-conexion-firebase.test.mjs']:
        if name not in m['code_paths']['tests']:m['code_paths']['tests'].append(name)
    for name in ['REFRESH_2026_11_04.md']+[str(p.relative_to(DOSSIER)) for p in sorted(generated.glob('*.json'))]:
        if name not in m['evidence_refs']:m['evidence_refs'].append(name)
    m['limitations']=[x for x in m['limitations'] if 'URL/password pinned' not in x]
    m['limitations'] += ['Firebase parameters use the analytical MX/es-MX/API34 profile, not device attestation.',
      'Real URL/password unchanged during current validation; rotation verified with independent JCA fictional vector and real isolated worker.',
      'New domains require allowlist review. Source/GCM algorithm changes are outside parameter-only refresh.',
      'Temporary installation deletion is best effort under network failure; all observed research deletions returned200.']
    m['network_requirements']=['HTTPS FIS creation, Remote Config client fetch and temporary installation DELETE on fixed Google endpoints.',
      'HTTPS approved raw GitHub updater, no redirects, public DNS and pinned IPv4/TLS in Node broker.']
    m['unresolved_questions']=['Real Node transport in VPS and deployment remain pending; evidence CI/automatic Phase7 approval remain pending.']
    existing={x['path']:x for x in m['tooling']}
    for file in sorted((DOSSIER/'tools').rglob('*')):
        if not file.is_file() or '__pycache__' in file.parts:continue
        key=str(file.relative_to(ROOT));entry=existing.get(key,{'path':key,'approval':'MANUAL_RESEARCH_NOT_APPROVED_FOR_AUTOMATIC_PHASE7'})
        entry['sha256']=hashlib.sha256(file.read_bytes()).hexdigest()
        if key not in existing:m['tooling'].append(entry)
    path.write_text(json.dumps(m,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'python':sum(py),'node':node,'reports':len(reports),'versions_match_lock':True}))


if __name__=='__main__':main()
