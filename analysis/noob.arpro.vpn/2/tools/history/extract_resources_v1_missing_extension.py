"""Initial inline probe, retained as failed history; do not use as final recipe."""
import argparse,zipfile
from pathlib import Path
def main():
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args()
    with zipfile.ZipFile(a.private/'unpacked/apks/noob.arpro.vpn.apk') as z:
        # Observed KeyError: the actual resource name is res/raw/noobdev.js.
        (a.private/'noobdev.raw').write_bytes(z.read('res/raw/noobdev'))
if __name__=='__main__':main()
