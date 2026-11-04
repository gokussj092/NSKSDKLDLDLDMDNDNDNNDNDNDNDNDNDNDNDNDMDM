import importlib.util
from pathlib import Path
def load_tests(loader,tests,pattern):
    path=Path(__file__).resolve().parents[4]/'tests/test_speicers_turbo_vpn.py';spec=importlib.util.spec_from_file_location('speicers_turbo_tests',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return loader.loadTestsFromModule(module)
