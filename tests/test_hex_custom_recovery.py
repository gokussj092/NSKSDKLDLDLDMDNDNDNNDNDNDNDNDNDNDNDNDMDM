"""Analysis recovery only. These tests do not claim a Hex file decoder."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts/apk_analysis'))
spec=importlib.util.spec_from_file_location('hex_recovery',ROOT/'scripts/apk_analysis/hex_custom_recover.py')
recovery=importlib.util.module_from_spec(spec);spec.loader.exec_module(recovery)


def container(entries=None,manifest=None):
    body=b'opaque\x00first'+b'\xffsecond'
    if entries is None:entries=[(4,0,12),(9,12,7)]
    if manifest is None:manifest=b'{"format":1,"files":[],"build_id":"synthetic"}'
    table=b''.join(struct.pack('<IIQ',*v) for v in entries)
    return struct.pack('<4s4I',b'KVS1',1,len(manifest),len(table),len(body))+manifest+table+body+bytes(range(64))


class HexRecoveryTests(unittest.TestCase):
    def test_preserves_entire_opaque_packages_and_signature_without_claiming_decryption(self):
        manifest,packages,signature=recovery.parse_container(container())
        self.assertEqual(manifest['build_id'],'synthetic')
        self.assertEqual([v['data'] for v in packages],[b'opaque\x00first',b'\xffsecond'])
        self.assertEqual([v['id'] for v in packages],[4,9]);self.assertEqual(signature,bytes(range(64)))

    def test_bad_magic_version_table_alignment_and_truncation_rejected(self):
        valid=container()
        for field,value in ((0,b'WRNG'),(4,struct.pack('<I',2)),(8,struct.pack('<I',999999)),
                            (12,struct.pack('<I',17)),(16,struct.pack('<I',0))):
            bad=bytearray(valid);bad[field:field+4]=value
            with self.assertRaises(ValueError):recovery.parse_container(bytes(bad))
        for bad in (valid[:-1],valid+b'x',b'',None,bytearray(valid)):
            with self.assertRaises(ValueError):recovery.parse_container(bad)

    def test_duplicate_overlapping_missing_and_out_of_bounds_ranges_rejected(self):
        for entries in ([(4,0,12),(4,12,7)],[(4,0,12),(9,11,8)],[(4,0,10),(9,12,7)],
                        [(4,0,12),(9,12,8)],[(4,0,0),(9,0,19)]):
            with self.assertRaises(ValueError):recovery.parse_container(container(entries))

    def test_bad_json_duplicate_manifest_fields_and_invalid_utf8_rejected(self):
        for raw in (b'[]',b'null',b'{',b'\xff',b'{"format":1,"format":1,"files":[]}',
                    b'{"format":2,"files":[]}',b'{"format":1,"files":{}}'):
            with self.assertRaises(ValueError):recovery.parse_container(container(manifest=raw))

    def test_unknown_native_build_rejected_before_reading_layout(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'other.so';p.write_bytes(b'not the supported build')
            with self.assertRaisesRegex(ValueError,'Unknown native build'):recovery.recover_methods(p)

    def test_private_outputs_never_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'private.bin';recovery.write_private(p,b'first')
            self.assertEqual(p.stat().st_mode&0o777,0o600)
            with self.assertRaises(FileExistsError):recovery.write_private(p,b'second')
            self.assertEqual(p.read_bytes(),b'first')


if __name__=='__main__':unittest.main()
