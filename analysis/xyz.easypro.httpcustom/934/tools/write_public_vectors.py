"""Freeze public n15 vectors using the owner's revised independent SHA routine."""
import argparse,hashlib,importlib.util,json
from pathlib import Path
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('reader',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    s=importlib.util.spec_from_file_location('reader',a.reader);r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
    aad=b'HCCFG|12|synthetic-public-vector|n15|934';seed=bytes(range(32))
    data={'source_script_sha256':hashlib.sha256(a.reader.read_bytes()).hexdigest(),
      'description':'Public synthetic KDF vectors; never use as service keys.',
      'seed_hex':seed.hex(),'aad_ascii':aad.decode(),'cases':[{'password_key_hex':pw.hex(),
      'expected_key_hex':r._derive_n15(seed,aad,pw).hex()} for pw in (b'',bytes(range(32)))]}
    a.output.write_text(json.dumps(data,indent=2)+'\n')
if __name__=='__main__':main()
