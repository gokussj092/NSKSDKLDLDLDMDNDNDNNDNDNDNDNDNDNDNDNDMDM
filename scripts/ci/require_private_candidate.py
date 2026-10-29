"""Read-only Actions gate. Never builds an untested or superseded private candidate."""
import json,os,re,subprocess,time
repo=os.environ['GITHUB_REPOSITORY'];sha=os.environ['SOURCE_SHA']
assert repo=='gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM'
assert re.fullmatch('[a-f0-9]{40}',sha)
branch='feat/catalog-notifications-donations'
def api(path):
    return json.loads(subprocess.check_output(['gh','api','repos/'+repo+'/'+path],text=True))
head=api('branches/'+branch)['commit']['sha']
assert head==sha,'Refusing superseded source revision'
required={'cloud-c0-audit.yml','cloud-c1.yml','cloud-c2.yml','cloud-c3.yml','cloud-c4.yml','cloud-c5.yml','cloud-c6.yml','cloud-c7.yml','cloud-c8-vps-installer.yml','hardware-security.yml','cloud-v2-security.yml'}
for attempt in range(91):
    runs=api('actions/runs?event=pull_request&head_sha='+sha+'&per_page=100')['workflow_runs']
    latest={}
    for run in runs:
        name=run['path'].split('/')[-1]
        if name not in latest or run['id']>latest[name]['id']:latest[name]=run
    bad=[name for name in required if name in latest and latest[name]['status']=='completed' and latest[name]['conclusion']!='success']
    assert not bad,'Required validation failed: '+','.join(sorted(bad))
    pending=[name for name in required if name not in latest or latest[name]['status']!='completed']
    if not pending:break
    if attempt==90:raise SystemExit('Required validations did not finish within 30 minutes')
    print('Waiting for exact-source validations: '+','.join(sorted(pending)),flush=True)
    time.sleep(20)
assert api('branches/'+branch)['commit']['sha']==sha,'Source changed during validation'
# Require the exact general unit and emulator jobs, excluding the signing job
# that is part of that workflow and must not create a circular dependency.
general=next((r for r in runs if r['path'].endswith('/validate.yml')),None)
assert general,'General validation run missing'
jobs=api('actions/runs/'+str(general['id'])+'/jobs?per_page=100')['jobs']
assert any(j['name']=='validate' and j['conclusion']=='success' for j in jobs),'General unit validation must succeed'
assert any(j['name'].startswith('Android production source regression') and j['conclusion']=='success' for j in jobs),'Android regression must succeed'
print('All independent validation workflows and both general jobs passed for '+sha)
