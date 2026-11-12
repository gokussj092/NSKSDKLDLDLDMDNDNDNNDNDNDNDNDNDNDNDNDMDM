"""Inventory owner supplied APKS and authenticated envelopes, omitting secrets."""
import argparse, hashlib, io, json, runpy, sys, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from decoders.Python.apps.HTTP_Custom.codec import open_envelope
identity = runpy.run_path(str(ROOT / 'analysis/xyz.easypro.httpcustom/564/tools/inspect_apkm.py'))['manifest_identity']

def sample_report(data):
    env = open_envelope(data)
    scalar = {k: env[k] for k in ('a','b','e','h','n','k','l','m') if k in env}
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                outer_authenticated=True, metadata=scalar,
                section_count=len(env.get('j', [])), hwid_slot_count=len(env.get('o', [])),
                extra_protection_shape=sorted(env.get('p', {})),
                access_wrapper=isinstance(env.get('c'), str) and env.get('b') == 9)

def main():
    p=argparse.ArgumentParser(); p.add_argument('inputs',type=Path); p.add_argument('--output',type=Path)
    args=p.parse_args(); report={'samples':[], 'archives':[]}
    for path in sorted(args.inputs.iterdir()):
        if not path.is_file():continue
        data=path.read_bytes()
        if path.suffix == '.hc':
            report['samples'].append({'name':path.name, **sample_report(data)})
        elif path.suffix == '.apks':
            item={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'apks':[]}
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for name in z.namelist():
                    blob=z.read(name)
                    with zipfile.ZipFile(io.BytesIO(blob)) as apk:
                        item['apks'].append({'name':name,'bytes':len(blob),
                          'sha256':hashlib.sha256(blob).hexdigest(),
                          'identity':identity(apk.read('AndroidManifest.xml')),
                          'libraries':[{'path':n,'bytes':len(apk.read(n)),
                          'sha256':hashlib.sha256(apk.read(n)).hexdigest()}
                          for n in apk.namelist() if n.endswith('.so')]})
            report['archives'].append(item)
    text=json.dumps(report,ensure_ascii=False,indent=2)+'\n'
    if args.output: args.output.write_text(text)
    else: print(text,end='')

if __name__=='__main__': main()
