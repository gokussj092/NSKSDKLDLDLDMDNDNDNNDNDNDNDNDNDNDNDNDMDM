#!/usr/bin/env python3
"""Compare a whole private Netcol catalog with independent JCA and the worker."""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoders.Python.apps.Netcol_VPN import codec

def request(mode, value):
    return 'dec\t' + mode + '\t' + base64.b64encode(value.encode()).decode()

def java(lines):
    result = subprocess.run(['java', str(ROOT / 'tests/golden/netcol_oracle.java')],
        input='\n'.join(lines) + '\n', text=True, capture_output=True, timeout=60)
    if result.returncode:
        raise ValueError('Independent Netcol JCA verification failed')
    return [base64.b64decode(v, validate=True).decode('utf-8') for v in result.stdout.splitlines()]

def verify(path, worker=False):
    with Path(path).open('rb') as source:
        data = source.read(codec.MAX_BYTES + 1)
    if not data or len(data) > codec.MAX_BYTES:
        raise ValueError('Catalog size limit')
    obj = json.loads(java([request('catalog', data.decode('utf-8-sig').strip())])[0])
    independent = copy.deepcopy(obj)
    jobs, destinations = [], []
    # Exact call sites in NetColMainActivity: six field-key calls and one user-key call.
    for item in independent['Servers']:
        for name in ('ServerIP', 'ProxyIP', 'Payload', 'SNI', 'Slowchave', 'Nameserver', 'ServerUser'):
            value = item.get(name)
            if isinstance(value, str) and value:
                jobs.append(request('user' if name == 'ServerUser' else 'field', value))
                destinations.append((item, name))
    replies = java(jobs) if jobs else []
    if len(replies) != len(destinations):
        raise ValueError('Incomplete JCA result')
    for (parent, name), value in zip(destinations, replies):
        parent[name] = value
    actual = codec.decode_catalog(data)
    if actual != independent:
        raise ValueError('Complete Netcol JSON mismatch')
    report = {'sha256': hashlib.sha256(data).hexdigest(), 'inputBytes': len(data),
              'version': actual['Version'], 'servers': len(actual['Servers']),
              'encryptedFields': len(jobs), 'completeJcaParity': True}
    if worker:
        from cloud.workers.python.engine import decode_provider_catalog
        result = decode_provider_catalog('netcol-vpn', data)
        if (result['structuredJson'] != independent or json.loads(result['rawText']) != independent
                or result['isPartial'] is not False):
            raise ValueError('Complete worker mismatch')
        report['workerRawBytes'] = len(result['rawText'].encode())
        report['workerResponseBytes'] = len(json.dumps(result, ensure_ascii=False, separators=(',', ':')).encode())
        report['completeWorkerParity'] = True
    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('catalog', type=Path)
    parser.add_argument('--worker', action='store_true')
    args = parser.parse_args()
    print(json.dumps(verify(args.catalog, args.worker)))
