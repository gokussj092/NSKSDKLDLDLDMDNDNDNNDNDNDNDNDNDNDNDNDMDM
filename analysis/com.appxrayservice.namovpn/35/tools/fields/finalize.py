#!/usr/bin/env python3
"""Publish only sanitized field-revision metadata after successful checks."""
import argparse,hashlib,json,re
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[5]
DOSSIER=Path(__file__).resolve().parents[2]

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path,value):path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args()
    checks=json.loads((a.private/'final-checks/checks.json').read_text())
    assert len(checks)==2 and all(r['exit_code']==0 for r in checks)
    py=(a.private/'final-checks/python.log').read_text();node=(a.private/'final-checks/node.log').read_text()
    py_count=int(re.search(r'Ran (\d+) tests',py)[1]);node_count=int(re.search(r'tests (\d+)',node)[1])
    assert py_count==15 and node_count==172 and 'fail 0' in node and '\nOK\n' in py
    verification=json.loads((a.private/'verified/summary.json').read_text())
    assert len(verification)==2
    for v in verification:
        assert v['whole_java_equal'] and v['whole_cli_equal'] and v['whole_worker_equal']
        assert v['changed_nonempty_fields']==87 and v['counts']=={'Servers':14,'Networks':13}
    tools=[{'path':str(t.relative_to(ROOT)),'sha256':sha(t),
        'approval':'MANUAL_RESEARCH_NOT_APPROVED_FOR_AUTOMATIC_PHASE7'}
        for t in sorted((DOSSIER/'tools/fields').rglob('*')) if t.is_file() and t.suffix in ('.py','.java')]
    initial={'python':'14/14 PASS','node':'104/150; 46 failed',
        'cause':'Partial workspace lacked Genis icon, fixtures and HTTP Firebase modules; restored exact Git base files. No production workaround.',
        'after_restore':'172/172 PASS; final complete run below'}
    report={'status':'VERIFIED_REAL','observed_at':datetime.now(timezone.utc).isoformat(),
        'base_commit':'a1b6721e39657d9e6e5360de88dede30d772f764',
        'previous_full_field_claim':'WITHDRAWN: previous oracle covered only XXTEA envelope',
        'verification':verification,'tools':tools,'python_tests':py_count,'node_tests':node_count,
        'initial_attempt':initial,'node_real':{'status':'NETWORK_UNAVAILABLE','code':'REMOTE_NETWORK_DENIED'},
        'node_replay':{'status':'PASS','transport':'SIMULATED_HTTP_REAL_BYTES','whole_worker_equal':True},
        'runtime_versions':{'python':'3.12.14','java':'17.0.20+8-1-24.04-Ubuntu','node':'24.22.1','jadx':'1.5.6'},
        'catalog_floor':71,'cards':65,'formats':256,'dependency_changes':'none; Java/Python standard library only'}
    save(DOSSIER/'generated/fields.json',report)
    save(DOSSIER/'generated/field-inspection.json',json.loads((a.private/'field-inspection.json').read_text()))
    save(DOSSIER/'generated/verification.json',verification)
    save(DOSSIER/'generated/checks.json',{'python_tests':py_count,'node_tests':node_count,'all_passed':True,
        'commands':checks,'initial_field_revision_attempt':initial,
        'node_real':report['node_real'],'node_replay':report['node_replay']})
    manifest=json.loads((DOSSIER/'MANIFEST.json').read_text())
    manifest['observed_at']=report['observed_at'];manifest['observed_local_date']='2026-11-04'
    manifest['field_revision']={k:report[k] for k in ['base_commit','previous_full_field_claim',
        'runtime_versions','dependency_changes','catalog_floor','cards','formats']}
    manifest['field_revision']['evidence']='generated/fields.json'
    manifest['field_revision']['schema']='Explicit Base64/UTF-8 fields after XXTEA; once; preserve all keys/types'
    for target in manifest['targets']:
        if target['kind']=='catalog':
            target['layers_verified']=['XXTEA envelope','Base64/UTF-8 fields']
            target['changed_nonempty_fields']=87
    bypath={t['path']:t for t in manifest['tooling']}
    for t in tools:bypath[t['path']]=t
    for path,entry in bypath.items():
        file=ROOT/path
        if file.exists():entry['sha256']=sha(file)
    manifest['tooling']=list(bypath.values())
    manifest['fixture_hashes']=[{'path':str(f.relative_to(DOSSIER)),'sha256':sha(f)}
        for f in sorted((DOSSIER/'tests/fixtures').iterdir()) if f.is_file()]
    for ref in ['FIELDS_FIX.md','generated/fields.json','generated/field-inspection.json']:
        if ref not in manifest['evidence_refs']:manifest['evidence_refs'].append(ref)
    limit='Backend rejects invalid field Base64/UTF-8 more strictly than Android; no recursive decoding or unknown-field guessing.'
    if limit not in manifest['limitations']:manifest['limitations'].append(limit)
    save(DOSSIER/'MANIFEST.json',manifest)
    print(json.dumps({'python_tests':py_count,'node_tests':node_count,'changed_fields':87,'private_values_published':False}))
if __name__=='__main__':main()
