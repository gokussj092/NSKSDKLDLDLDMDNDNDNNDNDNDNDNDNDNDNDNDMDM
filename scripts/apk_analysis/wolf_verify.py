#!/usr/bin/env python3
"""Compare a complete private Wolf catalog with independent JCA and the worker.

No vendor input or decrypted output is printed or stored. Run from the checkout
with PyCryptodome/JDK; the original APK is not needed once constants are known.
"""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from Crypto.Cipher import AES

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoders.Python.apps.Wolf_Custom_VPN import codec

def java(lines):
    result = subprocess.run(['java', str(ROOT / 'tests/golden/wolf_oracle.java')],
        input='\n'.join(lines) + '\n', text=True, capture_output=True, timeout=60)
    if result.returncode:
        raise ValueError('Independent JCA verification failed')
    return [base64.b64decode(v, validate=True) for v in result.stdout.splitlines()]

def request(key, value):
    return 'dec\t' + base64.b64encode(key).decode() + '\t' + value.replace('\r', '').replace('\n', '')

def verify(path, worker=False):
    with Path(path).open('rb') as source:
        data = source.read(codec.MAX_BYTES + 1)
    if not data or len(data) > codec.MAX_BYTES:
        raise ValueError('Catalog size limit')
    text = data.decode('utf-8-sig').strip()
    outer = json.loads(java([request(codec.KEY, text)])[0])
    independent = copy.deepcopy(outer)
    jobs, destinations = [], []
    def walk(value):
        if isinstance(value, dict):
            for name, item in value.items():
                if not isinstance(item, str):
                    walk(item)
                    continue
                for key in (codec.KEY, codec.INJECTOR_KEY):
                    try:
                        packed = base64.b64decode(item.replace('\r', '').replace('\n', ''), validate=True)
                        if len(packed) < 28:
                            continue
                        AES.new(key, AES.MODE_GCM, nonce=packed[:12]).decrypt_and_verify(packed[12:-16], packed[-16:])
                    except ValueError:
                        continue
                    jobs.append(request(key, item))
                    destinations.append((value, name))
                    break
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk(independent)
    replies = java(jobs) if jobs else []
    if len(replies) != len(destinations):
        raise ValueError('Incomplete independent result')
    for (parent, name), value in zip(destinations, replies):
        parent[name] = value.decode('utf-8')
    actual = codec.decode_catalog(data)
    if actual != independent:
        raise ValueError('Complete JSON mismatch')
    report = {'sha256': hashlib.sha256(data).hexdigest(), 'inputBytes': len(data),
              'version': actual['Version'], 'servers': len(actual['Servers']),
              'networks': len(actual['Networks']), 'encryptedFields': len(jobs), 'completeJcaParity': True}
    if worker:
        from cloud.workers.python.engine import decode_provider_catalog
        result = decode_provider_catalog('wolf-custom-vpn', data)
        if result['structuredJson'] != independent or json.loads(result['rawText']) != independent or result['isPartial'] is not False:
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
