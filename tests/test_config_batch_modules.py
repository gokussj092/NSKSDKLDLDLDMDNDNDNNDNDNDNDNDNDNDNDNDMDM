"""Bot file-decoder batch: isolation, extension registration and fail-closed smoke tests."""
from __future__ import annotations
import importlib
import unittest

from decoders.Python.config_batch_registry import FILE_DECODER_FAMILIES, file_decoder_specs
from spdecode.registry import DECODER_REGISTRY, get_supported_extension, validate_decoder_files


class BatchModuleTests(unittest.TestCase):
    def test_all_twelve_independent_modules_and_eighteen_suffixes(self):
        self.assertEqual(len(FILE_DECODER_FAMILIES), 13)
        self.assertEqual(len(file_decoder_specs()), 27)
        self.assertEqual(len(set(DECODER_REGISTRY) - {'solid','1ftnl','awg','creeb','kyz','stp'}), 239)
        self.assertEqual(validate_decoder_files(), [])
        for suffix, (name, script) in file_decoder_specs().items():
            with self.subTest(suffix=suffix):
                self.assertEqual(get_supported_extension("myconfig" + suffix.upper()), suffix[1:])
                self.assertEqual(DECODER_REGISTRY[suffix[1:]].script, script)
                module = importlib.import_module("decoders.Python." + script.rsplit("/", 1)[-1][:-3])
                self.assertTrue(callable(module.run))

    def test_malformed_input_rejected_without_fake_success(self):
        for name, (_, script, _) in FILE_DECODER_FAMILIES.items():
            with self.subTest(name=name):
                module = importlib.import_module("decoders.Python." + script.rsplit("/", 1)[-1][:-3])
                self.assertIsNone(module.run(b""))
                self.assertIsNone(module.run(b"invalid configuration"))

    def test_old_family_registrations_not_modified(self):
        self.assertEqual(DECODER_REGISTRY["ost"].script, "decoders/Python/ost.py")
        self.assertEqual(DECODER_REGISTRY["ultra"].script, "decoders/Python/ultra.py")
        self.assertEqual(DECODER_REGISTRY["7net"].script, "decoders/Python/renz.py")
        self.assertEqual(DECODER_REGISTRY["npvs"].script, "decoders/Python/npvs.py")
        self.assertEqual(DECODER_REGISTRY["lnk"].script, "decoders/Python/linklayer.py")


if __name__ == "__main__":
    unittest.main()
