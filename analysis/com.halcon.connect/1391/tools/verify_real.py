#!/usr/bin/env python3
"""Compare the entire private real catalog with JCA, production CLI and worker.

No network unless --download is explicitly provided (authorized updater only).
Never prints credentials, records, URLs, signatures or plaintext configuration.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('response', type=Path)
    p.add_argument('recipe', type=Path)
    p.add_argument('private_output', type=Path)
    p.add_argument('--download', action='store_true')
    a = p.parse_args()
    a.private_output.mkdir(parents=True, exist_ok=True, mode=0o700)
    recipe = json.loads(a.recipe.read_text())
    env = dict(os.environ, HALCON_CATALOG_PASSWORD=recipe['catalog_password'],
        SPDECODE_HALCON_CATALOG_PASSWORD=recipe['catalog_password'],
        SPDECODE_HALCON_REQUEST_SECRET=recipe['request_secret'])
    oracle = Path(__file__).with_name('EnvelopeOracle.java')
    reference = a.private_output / 'reference.json'
    reference.touch(mode=0o600, exist_ok=True)
    reference.chmod(0o600)
    subprocess.run(['java', str(oracle), 'decode', str(a.response.resolve()), str(reference.resolve())],
                   env=env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45)
    expected = json.loads(reference.read_text())
    script = ROOT / 'decoders/Python/apps/Halcon_R_Net/server_catalog_decoder.py'
    result = subprocess.run([sys.executable, str(script), str(a.response.resolve())],
                            env=env, capture_output=True, timeout=40)
    if result.returncode or json.loads(result.stdout) != expected:
        raise ValueError('Complete production CLI differs from JCA')
    cli = a.private_output / 'cli.json'
    cli.touch(mode=0o600, exist_ok=True)
    cli.chmod(0o600)
    cli.write_bytes(result.stdout)
    os.environ['SPDECODE_HALCON_CATALOG_PASSWORD'] = recipe['catalog_password']
    from cloud.workers.python.engine import decode_provider_catalog
    worker = decode_provider_catalog('halcon-r-net', a.response.read_bytes())
    if worker['structuredJson'] != expected or json.loads(worker['rawText']) != expected or worker['isPartial']:
        raise ValueError('Complete isolated worker differs from JCA')
    worker_file = a.private_output / 'worker-result.json'
    worker_file.touch(mode=0o600, exist_ok=True)
    worker_file.chmod(0o600)
    worker_file.write_text(json.dumps(worker, ensure_ascii=False) + '\n')
    report = {'scope': 'VERIFIED_REAL', 'version': expected['version'],
        'servers': len(expected['servers']), 'encrypted_bytes': a.response.stat().st_size,
        'encrypted_sha256': hashlib.sha256(a.response.read_bytes()).hexdigest(),
        'reference_bytes': reference.stat().st_size,
        'reference_sha256': hashlib.sha256(reference.read_bytes()).hexdigest(),
        'jca_cli_worker_full_document_equal': True, 'cli_real_download_full_document_equal': None}
    if a.download:
        fresh = subprocess.run([sys.executable, str(script)], env=env, capture_output=True, timeout=50)
        if fresh.returncode or json.loads(fresh.stdout) != expected:
            raise ValueError('Real CLI download failed or catalog changed; inspect privately')
        out = a.private_output / 'cli-downloaded.json'
        out.touch(mode=0o600, exist_ok=True)
        out.chmod(0o600)
        out.write_bytes(fresh.stdout)
        report['cli_real_download_full_document_equal'] = True
    (a.private_output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))

if __name__ == '__main__': main()
