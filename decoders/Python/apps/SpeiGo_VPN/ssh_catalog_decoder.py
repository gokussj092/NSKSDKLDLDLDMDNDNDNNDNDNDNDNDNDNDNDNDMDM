#!/usr/bin/env python3
"""Independent fixed SpeiGo SSH/users catalog reader."""
import sys
from pathlib import Path
if not __package__:sys.path.insert(0,str(Path(__file__).resolve().parents[4]))
from decoders.Python.apps.SpeiGo_VPN.server_catalog_decoder import main
from decoders.Python.apps.SpeiGo_VPN.codec import decode_catalog,render
def run(data):return render(decode_catalog(data,2))
if __name__=='__main__':raise SystemExit(main(2))
