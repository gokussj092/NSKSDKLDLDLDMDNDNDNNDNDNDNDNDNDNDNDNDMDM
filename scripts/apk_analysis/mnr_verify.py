#!/usr/bin/env python3
"""Full MNR catalog/profile comparison with independent JDK and worker, offline."""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoders.Python.apps.MNR_TUNNEL_PLUS import codec

# Literal source consumers; keep reference field schema independent of codec.
FIELDS = {'Servers': {'ServerIP','ServerUser','ServerPass','v2rayurl','UdpIP','Obfs_Str','Auth_Str','chaveKey','serverNameKey'},
          'Networks': {'Payload','SNI','dnsKey','ProxyIP','v2Address','v2Host','v2SNI','udpIP','udpObfs','udpAuth','PREFIX','DNS_RESOLVER_MANUAL'}}


def oracle(pairs):
    incoming = ''.join(mode + '\t' + base64.b64encode(value).decode() + '\n' for mode, value in pairs)
    result = subprocess.run(['java', str(ROOT/'tests/golden/mnr_oracle.java')], input=incoming,
        text=True, capture_output=True, timeout=40)
    if result.returncode or len(result.stdout.splitlines()) != len(pairs):
        raise ValueError('JDK failed')
    return [base64.b64decode(line, validate=True) for line in result.stdout.splitlines()]


def reference(data, profile=False):
    obj = json.loads(oracle([('profile' if profile else 'catalog', data.strip())])[0])
    slots = []
    if not profile:
        for group, fields in FIELDS.items():
            for row in obj[group]:
                for key in sorted(fields & row.keys()):
                    if row[key] != '': slots.append((row, key))
        values = oracle([('field', row[key].encode()) for row, key in slots]) if slots else []
        for (row, key), value in zip(slots, values): row[key] = value.decode('utf-8')
    return obj, len(slots)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('files', nargs='+', type=Path)
    parser.add_argument('--profile', action='store_true')
    parser.add_argument('--worker', action='store_true')
    args = parser.parse_args()
    try:
        for path in args.files:
            with path.open('rb') as stream: data = stream.read(codec.MAX_BYTES + 1)
            actual = codec.decode_profile(data) if args.profile else codec.decode_catalog(data)
            expected, fields = reference(data, args.profile)
            if actual != expected: raise ValueError('Whole document mismatch')
            if args.worker:
                from cloud.workers.python.engine import decode_file, decode_provider_catalog, decode_text
                worker = decode_file('stp', data) if args.profile else decode_provider_catalog('mnr-tunnel-plus', data)
                if worker['structuredJson'] != expected or json.loads(worker['rawText']) != expected or worker['isPartial']:
                    raise ValueError('Whole worker mismatch')
                if args.profile and decode_text(data.decode())['structuredJson'] != expected:
                    raise ValueError('Whole text mismatch')
            print(json.dumps({'jdkCompleteMatch': True, 'workerCompleteMatch': args.worker, 'encryptedFields': fields,
                **({'kind':'profile'} if args.profile else {'version':actual['Version'], 'servers':len(actual['Servers']), 'networks':len(actual['Networks'])})}))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print('No se pudo verificar MNR completo; no se muestran datos privados.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__': raise SystemExit(main())
