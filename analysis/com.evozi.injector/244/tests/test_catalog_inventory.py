"""Synthetic parser/redaction boundaries; these do not verify a live catalog."""
import importlib.util
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
TOOLS = ROOT / "analysis/_intake/http-injector-catalog-2026-11-09/tools"
sys.path.insert(0, str(TOOLS))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


inventory = load("catalog_inventory_test", TOOLS / "inventory.py")
frame = load("frame_inventory_test", TOOLS / "frame_inventory.py")
metadata = load("metadata_inventory_test", TOOLS / "metadata_inventory.py")


class CatalogInventoryTests(unittest.TestCase):
    def test_url_report_removes_userinfo_query_values_and_opaque_segment(self):
        secret = "fictional_authentication_material_123456789"
        raw = (f"https://user:fictional-pass@www.ehi.tools/{secret}?token={secret} "
               "https://unrelated.example/catalog").encode()
        result = inventory.urls(raw, "synthetic")
        encoded = json.dumps(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["path"], "/[opaque-segment]")
        self.assertEqual(result[0]["queryNames"], ["token"])
        self.assertTrue(result[0]["hadUserInfo"])
        for value in (secret, "fictional-pass", "unrelated.example"):
            self.assertNotIn(value, encoded)

    def test_frame_rejects_another_build_before_loading_zstd(self):
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory)
            (private / "inputs").mkdir()
            (private / "inputs/libdatajar.so").write_bytes(b"wrong build")
            with self.assertRaisesRegex(ValueError, "BUILD_HASH_MISMATCH"):
                frame.unpack(private)
            self.assertFalse((private / "code-frame.bin").exists())

    def test_metadata_retains_only_selected_type_descriptors(self):
        data = bytearray(2048)
        struct.pack_into("<I", data, 64, 10)
        entries = [(2, 0, 2, 400), (0x2002, 0, 3, 600)]
        entries += [(0xF000 + i, 0, 0, 1000) for i in range(8)]
        for index, entry in enumerate(entries):
            struct.pack_into("<HHII", data, 68 + index * 12, *entry)
        struct.pack_into("<II", data, 400, 0, 1)
        cursor = 600
        for value in (b"fictional-secret", b"Lcom/evozi/injector/views/ServersActivity;", b"unrelated"):
            encoded = bytes([len(value)]) + value + b"\0"
            data[cursor:cursor + len(encoded)] = encoded
            cursor += len(encoded)
        report = metadata.inventory_types(data, 0, 64)
        self.assertEqual(report["selectedTypeIdentifiers"],
                         ["Lcom/evozi/injector/views/ServersActivity;"])
        self.assertNotIn("fictional-secret", json.dumps(report))
        self.assertFalse(report["completeDexReconstructed"])

    def test_invalid_uleb_does_not_become_a_valid_offset(self):
        with self.assertRaisesRegex(ValueError, "INVALID_ULEB128"):
            metadata.uleb128(b"\xff\xff\xff\xff\xff", 0)
        with self.assertRaises(IndexError):
            metadata.uleb128(b"\x80", 0)

    def test_reviewed_report_keeps_catalog_and_authentication_pending(self):
        dossier = Path(__file__).resolve().parents[1]
        report = json.loads((dossier / "generated/catalog-research-summary.json").read_text())
        self.assertEqual(report["catalogStatus"], "PENDING")
        self.assertIsNone(report["catalogRequest"])
        self.assertIsNone(report["serverRecordCount"])
        self.assertEqual(report["downloadAuthentication"], "UNCONFIRMED")
        self.assertFalse(report["catalogVerified"])
        self.assertFalse(report["apkCodeExecuted"])


if __name__ == "__main__":
    unittest.main()
