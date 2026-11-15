"""Expose the canonical provider suite in this build dossier."""
import importlib.util
from pathlib import Path
def load_tests(loader,tests,pattern):
    p=Path(__file__).resolve().parents[4]/'tests/test_catnet_vpn.py'
    spec=importlib.util.spec_from_file_location('catnet_tests',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return loader.loadTestsFromModule(m)
