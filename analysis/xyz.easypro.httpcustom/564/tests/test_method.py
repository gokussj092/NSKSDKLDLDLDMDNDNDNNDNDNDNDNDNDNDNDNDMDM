"""Canonical synthetic method suite, with optional native reference CLI."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[4]))
from tests.test_hc_legacy57 import Legacy57Tests,native_parity

if __name__=='__main__':
    if len(sys.argv)==2:native_parity(sys.argv[1])
    else:unittest.main()
