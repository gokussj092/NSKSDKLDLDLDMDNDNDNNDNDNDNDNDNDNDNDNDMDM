"""Canonical Offline consumer validation, no copied fixtures or private data."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[4]))
from tests.test_offline_hc_native_parity import main as hc
from tests.test_offline_npv_native_parity import main as npv
if __name__=="__main__":
    hc(sys.argv[1])
    npv(sys.argv[2])
