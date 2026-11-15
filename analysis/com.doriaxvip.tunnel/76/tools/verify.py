#!/usr/bin/env python3
"""Compare whole documents against independent Java/JCA, CLI and isolated worker."""
import argparse
import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from decoders.Python.apps.Genis_VPN.codec import decode_catalog
from decoders.Python.apps.Genis_VPN.server_catalog_decoder import download, run
from cloud.workers.python.engine import decode_provider_catalog


def oracle(lines):
    result = subprocess.run(['java', str(Path(__file__).with_name('CatalogOracle.java'))],
                            input=''.join(lines), text=True, capture_output=True, check=True, timeout=60)
    return [base64.b64decode(line) for line in result.stdout.splitlines()]


def line(mode, password, data):
    return mode+'\t'+base64.b64encode(password).decode()+'\t'+base64.b64encode(data).decode()+'\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('private', type=Path)
    parser.add_argument('--download', action='store_true')
    parser.add_argument('--worker', action='store_true')
    args = parser.parse_args()
    root = args.private
    constants = json.loads((root/'constants.json').read_text())
    if args.download:
        path = root/'remote.enc'
        path.write_bytes(download())
        path.chmod(0o600)
    inputs = {'included':root/'unpacked/extracted/com.doriaxvip.tunnel/assets/flags/config.png',
              'included-users':root/'unpacked/extracted/com.doriaxvip.tunnel/assets/flags/usr.png',
              'remote':root/'remote.enc'}
    report = {}
    for name, path in inputs.items():
        data = path.read_bytes()
        clear, = oracle([line('O', constants['outerPassword'].encode(), data)])
        expected = json.loads(clear)
        fields = []
        for section in ('Servers', 'Usuarios'):
            for row in expected.get(section, []):
                fields.extend((row, key, value) for key, value in row.items() if isinstance(value, str))
        results = oracle([line('F', constants['innerPassword'].encode(), value.encode()) for _, _, value in fields])
        assert len(results)==len(fields)
        for (row,key,_), value in zip(fields, results):
            row[key] = value.decode()
        actual = decode_catalog(data)
        assert actual == expected
        cli = subprocess.run([sys.executable, str(ROOT/'decoders/Python/apps/Genis_VPN/server_catalog_decoder.py'), str(path.resolve())],
                             capture_output=True, text=True, check=True, timeout=30)
        assert json.loads(cli.stdout)==expected
        output = run(data)
        assert json.loads(output)==expected
        worker_equal = None
        if args.worker:
            worker = decode_provider_catalog('genis-vpn', data)
            assert worker['structuredJson']==expected and json.loads(worker['rawText'])==expected
            assert worker['isPartial'] is False
            worker_equal = True
            if name=='remote':
                worker_path=root/'worker.json'
                worker_path.write_text(json.dumps(worker,ensure_ascii=False)+'\n')
                worker_path.chmod(0o600)
        target = root/(name+'.decoded.json')
        target.write_text(output+'\n')
        target.chmod(0o600)
        report[name] = {'inputBytes':len(data),'inputSha256':hashlib.sha256(data).hexdigest(),
                        'version':expected['Version'],'sections':{k:len(v) for k,v in expected.items() if isinstance(v,list)},
                        'nonemptyFields':sum(bool(v) for _,_,v in fields),'emptyFields':sum(not v for _,_,v in fields),
                        'jcaFullDocumentEqual':True,'cliFullDocumentEqual':True,'workerFullDocumentEqual':worker_equal,
                        'outputBytes':len((output+'\n').encode()),'outputSha256':hashlib.sha256((output+'\n').encode()).hexdigest()}
    (root/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__ == '__main__':
    main()
