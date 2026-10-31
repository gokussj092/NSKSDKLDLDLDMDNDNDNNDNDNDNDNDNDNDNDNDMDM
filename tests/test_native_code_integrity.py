"""Real ELF mapping comparison: ASLR, changed RX bytes, W+X, recovery, unlink.

The disposable DSO exports a laboratory target; no app or third-party process
is modified. This is host evidence, not Android/ART runtime validation.
"""
import ctypes
import mmap
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
CPP=ROOT/'android/app/src/main/cpp'

class OwnCodeIntegrity(unittest.TestCase):
    def test_real_mapped_code_tamper_and_recovery(self):
        self.assertIsNotNone(shutil.which('g++'))
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'fixture.cpp'
            source.write_text('''#include "spdecode_code_integrity.h"
extern "C" __attribute__((visibility("default"),noinline)) int lab_target(){return 41;}
extern "C" __attribute__((visibility("default"))) int lab_verify(){
    return static_cast<int>(spdecode::verifyOwnExecutable());}
''')
            so=Path(d)/'fixture.so'
            subprocess.run(['g++','-std=c++17','-O2','-Wall','-Wextra','-Werror','-fPIC','-shared',
                '-Wl,-z,relro,-z,now,-z,noexecstack','-I',str(CPP),str(source),
                str(CPP/'spdecode_code_integrity.cpp'),'-ldl','-o',str(so)],check=True)
            lib=ctypes.CDLL(str(so));lib.lab_verify.restype=ctypes.c_int
            self.assertEqual(lib.lab_verify(),1,'genuine relocated RX code must match file')
            addr=ctypes.cast(lib.lab_target,ctypes.c_void_p).value
            page=addr & ~(mmap.PAGESIZE-1)
            libc=ctypes.CDLL(None,use_errno=True)
            libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]
            original=ctypes.c_ubyte.from_address(addr).value
            try:
                self.assertEqual(libc.mprotect(page,mmap.PAGESIZE,7),0)
                self.assertEqual(lib.lab_verify(),2,'own writable executable page is a change')
                ctypes.c_ubyte.from_address(addr).value=original^1
                self.assertEqual(libc.mprotect(page,mmap.PAGESIZE,5),0)
                self.assertEqual(lib.lab_verify(),2,'changed RX bytes must be detected')
            finally:
                libc.mprotect(page,mmap.PAGESIZE,7)
                ctypes.c_ubyte.from_address(addr).value=original
                libc.mprotect(page,mmap.PAGESIZE,5)
            self.assertEqual(lib.lab_verify(),1,'restoring exact bytes permits recovery')
            so.unlink()
            self.assertEqual(lib.lab_verify(),0,'unreadable reference must be UNKNOWN')

if __name__=='__main__': unittest.main()
