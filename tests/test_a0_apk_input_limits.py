"""P05 adversarial APK/APKS ZIP fixtures. Synthetic packaging, not real APK parsing."""
from __future__ import annotations
import io
from pathlib import Path
import stat
import tempfile
from unittest import mock
import unittest
import zipfile

from cloud.apk_analysis import input_gate as gate


AXML = b"\x03\x00\x08\x00\x08\x00\x00\x00"  # synthetic AXML header only
DEX = b"dex\n035\x00" + b"fixture" * 4


def zipped(items, *, compression=zipfile.ZIP_DEFLATED) -> bytes:
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", compression=compression, allowZip64=False) as z:
        for name, payload in items:
            z.writestr(name, payload)
    return data.getvalue()


class ApkBoundaryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.apk_bytes = zipped([
            ("AndroidManifest.xml", AXML), ("classes.dex", DEX),
            ("assets/data.bin", b"small synthetic content")
        ])

    def file(self, name="sample.apk", data=None):
        p = self.dir / name
        p.write_bytes(self.apk_bytes if data is None else data)
        return p

    def reject(self, path, code):
        with self.assertRaises(gate.GateError) as caught:
            gate.inspect_input(path)
        self.assertEqual(str(caught.exception), code)

    def test_owned_fixture_shape_apk_accepts(self):
        result = gate.inspect_input(self.file())
        self.assertEqual(result["format"], "APK")
        self.assertEqual(result["apk_count"], 1)
        self.assertEqual(result["dex_count"], 1)
        self.assertEqual(len(result["input_sha256"]), 64)

    def test_structural_apks_nested_base_accepts(self):
        packed = zipped([("base.apk", self.apk_bytes),
                         ("toc.pb", b"synthetic bundle")], compression=zipfile.ZIP_STORED)
        result = gate.inspect_input(self.file("set.apks", packed))
        self.assertEqual(result["format"], "APKS")
        self.assertEqual(result["apk_count"], 1)
        self.assertEqual(result["dex_count"], 1)

    def test_multiple_apks_with_base_accept(self):
        packed=zipped([("base.apk",self.apk_bytes),
                       ("split_config.apk",self.apk_bytes)],compression=zipfile.ZIP_STORED)
        result=gate.inspect_input(self.file("set.apks",packed))
        self.assertEqual(result["apk_count"],2)

    def test_apks_without_base_rejected(self):
        packed=zipped([("one.apk",self.apk_bytes),("two.apk",self.apk_bytes)],
                      compression=zipfile.ZIP_STORED)
        self.reject(self.file("set.apks",packed),"APKS_NO_BASE")

    def test_nested_apk_must_be_structurally_valid(self):
        packed=zipped([("base.apk",b"not an APK")],compression=zipfile.ZIP_STORED)
        self.reject(self.file("set.apks",packed),"APKS_NESTED_INVALID")

    def test_apks_unknown_subdirectory_layout_denied(self):
        packed=zipped([("splits/base.apk",self.apk_bytes)],compression=zipfile.ZIP_STORED)
        self.reject(self.file("set.apks",packed),"APKS_UNSUPPORTED_LAYOUT")

    def test_zip_slip_rejected(self):
        for name in ("../escape", "/absolute", "a/../bad", "C:/temp", "a\\b"):
            with self.subTest(name=name):
                self.reject(self.file(data=zipped([
                    ("AndroidManifest.xml",AXML),(name,b"secret")
                ])),"ZIP_ENTRY_UNSAFE")

    def test_duplicate_zip_member_rejected(self):
        with mock.patch("warnings.warn"):
            data = zipped([("AndroidManifest.xml",AXML),
                           ("AndroidManifest.xml",AXML)])
        self.reject(self.file(data=data),"ZIP_DUPLICATE")

    def test_symbolic_link_entry_rejected(self):
        info=zipfile.ZipInfo("assets/link")
        info.create_system=3
        info.external_attr=(stat.S_IFLNK|0o777)<<16
        self.reject(self.file(data=zipped([
            ("AndroidManifest.xml",AXML),(info,b"../private")
        ])),"ZIP_UNSAFE_TYPE")

    def test_zip_bomb_ratio_denied(self):
        data=zipped([("AndroidManifest.xml",AXML),
                     ("assets/zeros",b"\x00"*1024*1024)])
        self.reject(self.file(data=data),"ZIP_RATIO")

    def test_entry_size_guard(self):
        with mock.patch.object(gate,"MAX_ENTRY",16):
            self.reject(self.file(),"ZIP_ENTRY_SIZE")

    def test_expansion_guard(self):
        with mock.patch.object(gate,"MAX_EXPANDED",16):
            self.reject(self.file(),"ZIP_EXPANDED_SIZE")

    def test_max_members_guard(self):
        with mock.patch.object(gate,"MAX_ENTRIES",1):
            self.reject(self.file(),"ZIP_ENTRY_COUNT")

    def test_input_byte_limit(self):
        with mock.patch.object(gate,"MAX_INPUT",32):
            self.reject(self.file(),"INPUT_SIZE")

    def test_plain_xml_not_a_compiled_manifest(self):
        self.reject(self.file(data=zipped([
            ("AndroidManifest.xml",b"<manifest xmlns:android='x' />")
        ])),"APK_MANIFEST")

    def test_missing_manifest_denied(self):
        self.reject(self.file(data=zipped([
            ("classes.dex",DEX)
        ])),"APK_MANIFEST")

    def test_extension_and_corrupt_zip_rejected(self):
        self.reject(self.file("data.txt"),"INPUT_EXTENSION")
        self.reject(self.file(data=b"PKnotzip"),"ZIP_INVALID")

    def test_zip_and_future_xapk_are_not_current_input_formats(self):
        for suffix in (".zip", ".xapk", ".ZIP", ".XAPK"):
            with self.subTest(suffix=suffix):
                self.reject(self.file("disallowed" + suffix), "INPUT_EXTENSION")

    def test_input_symlink_denied(self):
        target=self.file()
        link=self.dir/"linked.apk"
        link.symlink_to(target)
        self.reject(link,"INPUT_NOT_REGULAR")

    def test_empty_apks_rejected(self):
        self.reject(self.file("empty.apks",zipped([("toc.pb",b"metadata")])),
                    "APKS_COUNT")

    def test_nested_entry_limit(self):
        packed=zipped([("base.apk",self.apk_bytes)],compression=zipfile.ZIP_STORED)
        with mock.patch.object(gate,"MAX_ENTRIES",3):
            self.reject(self.file("set.apks",packed),"APKS_NESTED_LIMIT")

    def test_no_disk_writes_by_plain_apk_gate(self):
        p=self.file()
        before={x.name for x in self.dir.iterdir()}
        gate.inspect_input(p)
        self.assertEqual(before,{x.name for x in self.dir.iterdir()})


if __name__=="__main__":
    unittest.main()
