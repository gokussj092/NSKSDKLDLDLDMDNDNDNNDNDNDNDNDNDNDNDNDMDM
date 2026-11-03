"""Independent batch: nine Python engines, 13 bot-only suffixes, two text schemes."""
from __future__ import annotations

import importlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from decoders.Python.config_independent_registry import (
    INDEPENDENT_DECODERS, independent_file_decoder_specs,
)
from spdecode.registry import (
    DECODER_REGISTRY, get_supported_extension, validate_decoder_files,
)

ROOT = Path(__file__).resolve().parents[1]


class IndependentFamilyRegistryTests(unittest.TestCase):
    def test_nine_engines_thirteen_extensions(self):
        self.assertEqual(len(INDEPENDENT_DECODERS), 9)
        self.assertEqual(len(independent_file_decoder_specs()), 13)
        self.assertEqual(len(set(DECODER_REGISTRY) - {'solid','1ftnl','awg','creeb','kyz','stp','hexcm'}), 239)
        self.assertEqual(validate_decoder_files(), [])
        original = json.loads((ROOT / "decoders.json").read_text(encoding="utf-8"))
        self.assertEqual(len(original["decoders"]), 61)
        for suffix, (name, script) in independent_file_decoder_specs().items():
            with self.subTest(extension=suffix):
                self.assertEqual(get_supported_extension("CONFIG" + suffix.upper()), suffix[1:])
                spec = DECODER_REGISTRY[suffix[1:]]
                # .crev is explicitly overlaid for the newer CREEB VPN Cloud
                # handler; its historical Phase F module remains intact.
                if suffix == ".crev":
                    self.assertEqual(spec.script, "decoders/Python/apps/CREEB_VPN/file_decoder.py")
                    self.assertEqual(spec.name, "CREEB VPN 50.0")
                else:
                    self.assertEqual(spec.script, script)
                    self.assertEqual(spec.name, name)
                self.assertEqual(spec.runtime, "python")
                module = importlib.import_module("decoders.Python." + Path(script).stem)
                self.assertTrue(callable(module.run))
                self.assertIn(suffix, module.EXTENSIONS)

    def test_previous_families_stay_unchanged(self):
        for suffix, script in {
            "ultra": "decoders/Python/ultra.py",
            "ost": "decoders/Python/ost.py",
            "7net": "decoders/Python/renz.py",
            "flex": "decoders/Python/flex.py",
            "npvs": "decoders/Python/npvs.py",
            "lnk": "decoders/Python/linklayer.py",
            "st": "decoders/Python/sentinel.py",
        }.items():
            with self.subTest(suffix=suffix):
                self.assertEqual(DECODER_REGISTRY[suffix].script, script)

    def test_malformed_files_fail_closed(self):
        for name, (script, aliases) in INDEPENDENT_DECODERS.items():
            module = importlib.import_module("decoders.Python." + Path(script).stem)
            with self.subTest(engine=name):
                self.assertIsNone(module.run(b""))
                self.assertIsNone(module.run(b"invalid ciphertext"))
                self.assertIsNone(module.run(b"x" * (2 * 1024 * 1024 + 1)))

    def test_cli_failure_status_and_no_false_stdout(self):
        for name, (script, aliases) in INDEPENDENT_DECODERS.items():
            with self.subTest(engine=name), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / ("test" + aliases[0])
                path.write_bytes(b"invalid ciphertext")
                proc = subprocess.run(
                    [sys.executable, str(ROOT / script), str(path)],
                    cwd=ROOT, text=True, capture_output=True, timeout=30)
                self.assertEqual(proc.returncode, 1, proc.stderr)
                self.assertFalse(proc.stdout.strip())

    def test_izph_text_route_registration(self):
        source = (ROOT / "spdecode/handlers/config_batch_texts.py").read_text(encoding="utf-8")
        self.assertIn('"izph://"', source)
        self.assertIn('"izphvpnpro://"', source)


if __name__ == "__main__":
    unittest.main()
