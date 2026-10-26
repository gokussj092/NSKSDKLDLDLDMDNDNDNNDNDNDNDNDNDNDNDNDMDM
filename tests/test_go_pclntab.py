"""Reject ambiguous merged Go tables; preserve named-section behavior."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts/apk_analysis'))
from go_inspect import find_pclntab

SIG=bytes.fromhex('f1ffffff00000408')
class Section(dict):
    def __init__(self,data):super().__init__(sh_addr=0x1000);self.raw=data
    def data(self):return self.raw
class Elf:
    def __init__(self,sections):self.sections=sections
    def get_section_by_name(self,name):return self.sections.get(name)

class GoTableTests(unittest.TestCase):
    def test_named_table_is_preserved(self):
        data=SIG+bytes(64)
        self.assertEqual(find_pclntab(Elf({'.gopclntab':Section(data)})),(data,0x1000))
    def test_merged_table_uses_real_virtual_address(self):
        data=SIG+bytes(64)
        self.assertEqual(find_pclntab(Elf({'.data.rel.ro':Section(b'prefix'+data)})),(data,0x1006))
    def test_missing_ambiguous_and_unsupported_fail(self):
        for sections in ({},{'.gopclntab':Section(b'bad')},{'.data.rel.ro':Section(b'bad')},
                         {'.data.rel.ro':Section(SIG+bytes(72)+SIG)}):
            with self.assertRaises(ValueError):find_pclntab(Elf(sections))

if __name__=='__main__':unittest.main()
