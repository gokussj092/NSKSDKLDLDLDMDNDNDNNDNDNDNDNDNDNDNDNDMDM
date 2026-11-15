"""Expose the canonical HTTP Conexión provider suite from its dossier."""
import importlib.util
from pathlib import Path
def load_tests(loader,tests,pattern):
    path=Path(__file__).resolve().parents[4]/'tests/test_http_conexion.py'
    spec=importlib.util.spec_from_file_location('http_conexion_canonical_tests',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return loader.loadTestsFromModule(module)
