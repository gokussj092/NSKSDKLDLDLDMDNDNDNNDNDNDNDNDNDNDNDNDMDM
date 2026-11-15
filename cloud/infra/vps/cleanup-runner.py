#!/usr/bin/env python3
"""SP-DECODE host-only cache housekeeping: never delete volumes or live jobs.

Reads the administrator-approved policy from PostgreSQL. The only destructive
operation is pruning unused *Docker build cache* older than the allowed age.
APK analysis jobs already have their own state-aware TTL sweepers.
"""
from __future__ import annotations
import argparse
import datetime as dt
import fcntl
import json
import os
import subprocess
import sys
from pathlib import Path

DB='spdecode-shop-db-1'
QUERY="SELECT value::text FROM spdecode_shop.settings WHERE id='cleanup-policy'"
MIN_AGE=168
AGES={168,336,720}
LOCK=Path('/run/lock/spdecode-safe-cleanup.lock')

def invoke(args,timeout=35):
    return subprocess.run(args,check=True,text=True,capture_output=True,timeout=timeout).stdout.strip()

def query(sql):
    return invoke(['docker','exec',DB,'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1',
      '-U','spdecode_admin','-d','spdecode_shop','-c',sql])

def policy():
    value=query(QUERY)
    if not value:raise RuntimeError('CLEANUP_POLICY_MISSING')
    parsed=json.loads(value)
    if not (isinstance(parsed,dict) and type(parsed.get('enabled')) is bool and
            type(parsed.get('requested')) is bool and parsed.get('retentionHours') in AGES):
        raise RuntimeError('CLEANUP_POLICY_INVALID')
    return parsed

def update_result(status):
    if status not in {'ok','error','skipped_shared_builder'}:
        raise RuntimeError('BAD_STATUS')
    # All values hardcoded; never compose SQL with the policy or user input.
    query("UPDATE spdecode_shop.settings SET value = value || "
          "jsonb_build_object('requested', false, "
          "'lastRunAt', to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), "
          "'lastResult', '"+status+"'), updated_at=now() WHERE id='cleanup-policy'")

def recent(value):
    if not isinstance(value,str):return False
    try:
        ts=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
        if ts.tzinfo is None:return False
        return (dt.datetime.now(dt.timezone.utc)-ts).total_seconds()<86400
    except ValueError:return False

def other_running_containers():
    names=invoke(['docker','ps','--format','{{.Names}}'])
    return [name for name in names.splitlines() if name and not name.startswith('spdecode-')]

def execute():
    if os.geteuid()!=0:raise RuntimeError('ROOT_REQUIRED')
    LOCK.parent.mkdir(parents=True,exist_ok=True)
    with LOCK.open('a') as handle:
        try:fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return 'CLEANUP_ALREADY_RUNNING'
        p=policy()
        if not p['enabled'] and not p['requested']:return 'CLEANUP_DISABLED'
        if not p['requested'] and recent(p.get('lastRunAt')):return 'NOT_DUE'
        if other_running_containers():
            update_result('skipped_shared_builder')
            return 'SKIPPED: non-SP-DECODE containers also use this Docker host'
        hours=p['retentionHours']
        if type(hours) is not int or hours<MIN_AGE:raise RuntimeError('INVALID_RETENTION')
        try:
            invoke(['docker','builder','prune','--force','--filter',f'until={hours}h'],timeout=600)
        except (subprocess.SubprocessError,OSError):
            update_result('error')
            return 'CLEANUP_FAILED'
        update_result('ok')
        return 'CLEANUP_OK (unused build cache only; no Docker volumes, images, or active jobs)'

def main():
    parser=argparse.ArgumentParser(description='Safe, host-only SP-DECODE cache cleanup')
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--once',action='store_true')
    mode.add_argument('--status',action='store_true')
    opts=parser.parse_args()
    if os.geteuid()!=0:raise RuntimeError('ROOT_REQUIRED')
    if opts.status:
        value=policy()
        print(json.dumps({key:value.get(key)for key in
            ('enabled','retentionHours','requested','lastRunAt','lastResult')},ensure_ascii=False))
    else:print(execute())
if __name__=='__main__':
    try:main()
    except (RuntimeError,subprocess.SubprocessError,ValueError,OSError) as exc:
        print('SPDECODE_CLEANUP_ERROR: '+str(exc)[:150],file=sys.stderr);sys.exit(1)
