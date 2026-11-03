"""One canonical provider suite, exposed from the mandatory per-build dossier."""
import importlib.util
from pathlib import Path

def load_tests(loader,tests,pattern):
    source=Path(__file__).resolve().parents[4]/'tests/test_alsaher_vip.py'
    spec=importlib.util.spec_from_file_location('alsaher_canonical_tests',source)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return loader.loadTestsFromModule(module)
