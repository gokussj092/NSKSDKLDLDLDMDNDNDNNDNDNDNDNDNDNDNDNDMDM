"""Canonical FNF provider suite, exposed from its build dossier."""
import importlib.util
from pathlib import Path
def load_tests(loader,tests,pattern):
    path=Path(__file__).resolve().parents[4]/'tests/test_fnf_tunnel_bd.py'
    spec=importlib.util.spec_from_file_location('fnf_canonical_tests',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return loader.loadTestsFromModule(module)
