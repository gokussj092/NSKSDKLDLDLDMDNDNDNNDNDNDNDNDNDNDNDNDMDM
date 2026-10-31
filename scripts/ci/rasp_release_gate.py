#!/usr/bin/env python3
"""Require recorded real-world evidence before marking R0/R6 production-ready.

This validator checks evidence completeness, not the truth of manually recorded
claims. Review source logs/artifacts. It never fabricates a PASS for missing data.
"""
import argparse
import json
from pathlib import Path

CHECKS={'play_hpke_decode','npvs_v5_password','npvs_v6_recipient','catalog_p256',
        'encrypted_history','no_network_recovery','foreground_recovery',
        'resigned_rejected','debugger_rejected','hook_rejected','hook_recovery',
        'adb_benign','termux_benign','shizuku_benign','vpn_benign','no_profile_logs'}
STAGING={'hpke_preserved','missing_keyring_rejected','wrong_kid_rejected',
         'recreate_e2e','rollback_e2e','key_backup_restored'}

def validate(value,commit):
    errors=[]
    if not isinstance(value,dict): return ['evidence must be an object']
    if value.get('commit')!=commit: errors.append('evidence commit differs from candidate')
    builds=value.get('devices',[])
    if not isinstance(builds,list): builds=[]
    minimumSdk=value.get('minimumDeviceSdk',33)
    if type(minimumSdk) is not int or not 24<=minimumSdk<=36:
        errors.append('minimumDeviceSdk missing/invalid');minimumSdk=33
    manufacturers=set();apis=set();channels=set()
    if len(builds)<4: errors.append('at least four device records required')
    for i,d in enumerate(builds):
        if not isinstance(d,dict):errors.append(f'device {i}: invalid record');continue
        tag=f'device {i}'
        if d.get('physical') is not True:errors.append(f'{tag}: physical device required')
        if d.get('manufacturer'):manufacturers.add(d['manufacturer'].strip().lower())
        apis.add(d.get('api'));channels.add(d.get('channel'))
        if d.get('candidateCommit')!=commit:errors.append(f'{tag}: candidate SHA mismatch')
        if not d.get('evidenceRef'):errors.append(f'{tag}: source evidence missing')
        required=CHECKS if type(d.get('api')) is int and d['api']>=minimumSdk else {'ui_no_crash','policy_denied_without_crash'}
        if not isinstance(d.get('checks'),dict) or any(d['checks'].get(c) is not True for c in required):
            errors.append(f'{tag}: functional/benign/tamper checks incomplete')
        if d.get('falsePositives')!=0:errors.append(f'{tag}: false positives not zero')
        for field in ('baselineP95Ms','candidateP95Ms','maxRegressionPercent'):
            x=d.get(field)
            if type(x) not in (int,float) or not 0<x<1e7:errors.append(f'{tag}: {field} missing/invalid')
        if not errors or all('P95' not in e and 'Regression' not in e for e in errors if e.startswith(tag)):
            base=d.get('baselineP95Ms',0);candidate=d.get('candidateP95Ms',0);budget=d.get('maxRegressionPercent',0)
            if base and (candidate/base-1)*100>budget:errors.append(f'{tag}: latency regression exceeds agreed budget')
        for field in ('cpuBudgetPass','ramBudgetPass','batteryBudgetPass','signerVerified'):
            if d.get(field) is not True:errors.append(f'{tag}: {field} not confirmed')
    if len(manufacturers)<2:errors.append('at least two manufacturers required')
    if not {24,28,33,36}.issubset(apis):errors.append('API 24/28/33/36 boundary coverage required')
    if not {'play_internal','authorized_sideload'}.issubset(channels):errors.append('Play and authorized sideload coverage required')
    staging=value.get('staging',{})
    if not isinstance(staging,dict):staging={}
    if staging.get('candidateCommit')!=commit or not staging.get('evidenceRef') or any(staging.get(c) is not True for c in STAGING):
        errors.append('real staging update/rollback evidence incomplete')
    if value.get('ci',{}).get('candidateCommit')!=commit or not value.get('ci',{}).get('runUrl') or value.get('ci',{}).get('success') is not True:
        errors.append('candidate CI evidence missing')
    return errors

def main():
    p=argparse.ArgumentParser();p.add_argument('evidence',type=Path);p.add_argument('--commit',required=True)
    args=p.parse_args()
    try:errors=validate(json.loads(args.evidence.read_text()),args.commit)
    except (OSError,ValueError,TypeError):errors=['evidence file missing or invalid']
    if errors:
        print('NOT READY: '+ '; '.join(errors));return 1
    print('Evidence matrix complete; review the linked source evidence before promotion.');return 0

if __name__=='__main__':raise SystemExit(main())
