"""Generic AES-GCM/PBKDF2 and DES-ECB bot profile registration contracts."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from decoders.Python.generic_profiles import (
    VPN_PASSWORDS, DES_PASSWORDS, MULTI_PASSWORDS, AES_PROFILES,
    DES_PROFILES, generic_specs,
)
from spdecode.registry import (
    DECODER_REGISTRY, get_supported_extension, validate_decoder_files,
)

ROOT = Path(__file__).resolve().parents[1]
AES_SCRIPT = "decoders/Python/generic_aes.py"
DES_SCRIPT = "decoders/Python/generic_des.py"
SHARED_NEW = frozenset({".acm", ".htp", ".pin", ".tut", ".vmx", ".xsks"})


class GenericFamilyRegistryTests(unittest.TestCase):
    def test_exact_81_new_suffixes_74_aes_13_des(self):
        self.assertEqual(len(set(DECODER_REGISTRY) - {'solid','1ftnl','awg','creeb'}), 239)
        self.assertEqual(validate_decoder_files(), [])
        self.assertEqual(len(AES_PROFILES), 94)  # .vpnlite has no key
        self.assertEqual(len(DES_PROFILES), 21)
        generated = {
            "." + suffix: spec for suffix, spec in DECODER_REGISTRY.items()
            if spec.script in (AES_SCRIPT, DES_SCRIPT)
        }
        self.assertEqual(len(generated), 81)
        aes_new = {
            name for name in generated
            if name in AES_PROFILES
        }
        des_new = {
            name for name in generated
            if name in DES_PROFILES
        }
        self.assertEqual(len(aes_new), 74)
        self.assertEqual(len(des_new), 13)
        self.assertEqual(aes_new & des_new, SHARED_NEW)
        self.assertEqual(len(des_new - aes_new), 7)
        self.assertEqual(len(aes_new - des_new), 68)
        self.assertEqual(len(DECODER_REGISTRY) - len(generated) - 4, 158)
        for suffix, spec in generated.items():
            with self.subTest(suffix=suffix):
                self.assertEqual(get_supported_extension("FILE" + suffix.upper()),
                                 suffix[1:])
                self.assertEqual(spec.runtime, "python")
                selected = DES_SCRIPT if suffix in des_new else AES_SCRIPT
                self.assertEqual(spec.script, selected)

    def test_original_static_android_catalog_unchanged(self):
        registry = json.loads((ROOT / "decoders.json").read_text(encoding="utf-8"))
        self.assertEqual(len(registry["decoders"]), 61)
        self.assertNotIn("ace", registry["decoders"])
        self.assertNotIn("clay", registry["decoders"])

    def test_source_duplicate_resolution_and_multikey_priority(self):
        self.assertEqual(AES_PROFILES[".tsd"], (b"Ed\x01",))
        self.assertEqual(AES_PROFILES[".ignix_vpn"], (b"3k8DiZh55Iss",))
        self.assertEqual(AES_PROFILES[".cks"], tuple(MULTI_PASSWORDS[".cks"]))
        self.assertEqual(AES_PROFILES[".pb"], tuple(MULTI_PASSWORDS[".pb"]))
        self.assertNotIn(".vpnlite", AES_PROFILES)
        self.assertIn(".fɴ", DES_PROFILES)

    def test_existing_specific_engines_are_not_overwritten(self):
        expected = {
            ".ost": "decoders/Python/ost.py",
            ".ultra": "decoders/Python/ultra.py",
            ".7net": "decoders/Python/renz.py",
            ".itv": "decoders/Python/itv.py",
            ".fthp": "decoders/Python/fthp.py",
            ".ftp": "decoders/Python/fthp.py",
            ".cly": "decoders/Python/multides.py",
            ".jvc": "decoders/Python/multides.py",
            ".jvi": "decoders/Python/multides.py",
            ".v2i": "decoders/Python/multides.py",
            ".npvs": "decoders/Python/npvs.py",
            ".lnk": "decoders/Python/linklayer.py",
            ".izph": "decoders/Python/izph.py",
        }
        for suffix, script in expected.items():
            with self.subTest(suffix=suffix):
                self.assertEqual(DECODER_REGISTRY[suffix[1:]].script, script)
        proposals = generic_specs(DECODER_REGISTRY)
        self.assertEqual(proposals, {})

    def test_generic_excludes_externally_claimed_suffixes(self):
        claimed = set(AES_PROFILES) | set(DES_PROFILES)
        self.assertEqual(generic_specs(claimed), {})
        self.assertNotIn(".vpnlite", generic_specs(set()))
        self.assertNotIn(".hat", generic_specs(set()))
        specs = generic_specs(set())
        self.assertEqual(specs[".acm"][1], DES_SCRIPT)
        self.assertEqual(specs[".ace"][1], AES_SCRIPT)


if __name__ == "__main__":
    unittest.main()
