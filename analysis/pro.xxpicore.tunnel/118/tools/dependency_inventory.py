#!/usr/bin/env python3
"""Snapshot the actual isolated analysis environment; never inspect credentials."""
import argparse
import hashlib
import importlib.metadata as metadata
import json
from pathlib import Path
import platform
import subprocess
import sys

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('output', type=Path)
    p.add_argument('--repo-root', type=Path, required=True)
    a = p.parse_args()
    packages = []
    for d in sorted(metadata.distributions(), key=lambda d: d.metadata['Name'].lower()):
        lic = d.metadata.get('License-Expression') or d.metadata.get('License') or 'UNKNOWN'
        if len(lic) > 240: lic = lic.splitlines()[0][:240]
        source = d.metadata.get_all('Project-URL') or [d.metadata.get('Home-page', 'UNKNOWN')]
        packages.append({'id': 'pypi:' + d.metadata['Name'], 'name': d.metadata['Name'],
                         'version': d.version, 'source': source, 'license': lic,
                         'license_review': 'NEEDS_REVIEW', 'requires_dist': d.requires or [],
                         'distribution_sha256': None,
                         'hash_note': 'Distribution archive hash was not retained during pip installation.'})
    scripts = []
    shared = a.repo_root / 'scripts/apk_analysis'
    for name in ['inspect_apk.py', 'decompile.py', 'elf_inspect.py', 'arm64_function.py', 'paranoid_strings.py', 'requirements.txt']:
        path = shared / name
        scripts.append({'path': path.relative_to(a.repo_root).as_posix(),
                        'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    runtimes = {'python': sys.version, 'platform': platform.platform(),
                'java': subprocess.run(['java', '-version'], capture_output=True, text=True).stderr.strip(),
                'node': subprocess.run(['node','--version'],capture_output=True,text=True).stdout.strip(),
                'curl': subprocess.run(['curl', '--version'], capture_output=True, text=True).stdout.strip()}
    out = {'schema_version': 1, 'environment': runtimes, 'python_packages': packages,
           'shared_scripts': scripts, 'approval': 'UNREVIEWED_FOR_AUTOMATIC_PHASE_7',
           'jadx': {'version': '1.5.6', 'source': 'https://github.com/skylot/jadx/releases/tag/v1.5.6',
                    'license': 'Apache-2.0',
                    'zip_sha256': '545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974',
                    'jar_sha256': 'fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b'}}
    a.output.write_text(json.dumps(out, ensure_ascii=False, indent=2) + '\n')
    a.output.with_name('requirements.lock.txt').write_text('\n'.join(
        d['name'] + '==' + d['version'] for d in packages) + '\n')
    print(json.dumps({'python_packages': len(packages), 'shared_scripts': len(scripts)}))

if __name__ == '__main__': main()
