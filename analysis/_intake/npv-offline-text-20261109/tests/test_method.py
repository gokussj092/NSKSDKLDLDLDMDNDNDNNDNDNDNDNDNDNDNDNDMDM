"""Canonical regression entry point, including negative explicit-field cases."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[4]))
from tests.test_offline_npv_native_parity import main
if __name__=="__main__":
    main(sys.argv[1])
