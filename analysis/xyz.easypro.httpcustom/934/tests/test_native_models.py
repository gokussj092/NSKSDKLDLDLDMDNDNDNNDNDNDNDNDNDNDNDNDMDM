"""Independent native-model checks; no Android binary is loaded by these tests."""
import ctypes,importlib.util,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]/'tools'))
from native_memory_fs import MemoryFS

class Boundaries(unittest.TestCase):
    @unittest.skipUnless(importlib.util.find_spec('unicorn'),'Optional isolated native-analysis dependencies unavailable')
    def test_fp_and_lr_use_unicorn_named_registers(self):
        from jni_format_probe import Probe
        from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM
        from unicorn.arm64_const import UC_ARM64_REG_X29,UC_ARM64_REG_X30
        instance=Probe.__new__(Probe);instance.uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        instance.uc.reg_write(UC_ARM64_REG_X29,0x102000)
        instance.uc.reg_write(UC_ARM64_REG_X30,0x304000)
        self.assertEqual(instance.reg(29),0x102000)
        self.assertEqual(instance.reg(30),0x304000)

    @unittest.skipUnless(importlib.util.find_spec('unicorn'),'Optional isolated native-analysis dependencies unavailable')
    def test_argument_register_reads_are_preserved(self):
        from jni_format_probe import Probe
        from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM
        from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X7
        instance=Probe.__new__(Probe);instance.uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        instance.uc.reg_write(UC_ARM64_REG_X0,0x1122)
        instance.uc.reg_write(UC_ARM64_REG_X7,0x3344)
        self.assertEqual(instance.reg(0),0x1122)
        self.assertEqual(instance.reg(7),0x3344)

    def test_virtual_paths_cannot_escape_to_host_or_other_apps(self):
        class Engine:
            def alloc(self,value):return 123
            def cstr(self,value):return value
        fs=MemoryFS(Engine())
        self.assertEqual(fs.path('/data/user/0/xyz.easypro.httpcustom/no_backup'),'/data/user/0/xyz.easypro.httpcustom/no_backup')
        for path in ('/etc/passwd','/data/user/0/other.app/no_backup','/data/user/0/xyz.easypro.httpcustom/../../other'):
            with self.assertRaises(ValueError):fs.path(path)

    @unittest.skipUnless(importlib.util.find_spec('unicorn'),'Optional isolated native-analysis dependencies unavailable')
    def test_lrand48_matches_independent_system_libc(self):
        from jni_format_probe import Probe
        libc=ctypes.CDLL(None);libc.srand48.argtypes=[ctypes.c_long];libc.lrand48.restype=ctypes.c_long
        libc.srand48(0x1234abcd)
        expected=[libc.lrand48() for _ in range(6)]
        instance=Probe.__new__(Probe);instance.reg=lambda i:0;instance.finish=lambda value:value
        self.assertEqual([instance.imported('lrand48') for _ in range(6)],expected)

if __name__=='__main__':unittest.main()
