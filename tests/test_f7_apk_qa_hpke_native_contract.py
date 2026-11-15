"""F7 native HPKE upload-boundary regression.

Reproduce the original 0 / 36 MiB CLOUD_HPKE_ENCRYPT_FAILED bug:
operation 22 must accept a raw 2 MiB chunk. Other operations must not
accidentally accept binary payloads. Compile the *actual* C++ header with
the host C++17 compiler and reject drift from the native encryption caller.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
CPP=ROOT/"android/app/src/main/cpp"
SOURCE=(CPP/"spdecode_hpke.cpp").read_text(encoding="utf-8")
ANDROID=(ROOT/"android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudApkQaClient.kt").read_text(encoding="utf-8")
SERVER=(ROOT/"cloud/web/lib/v2-hpke.mjs").read_text(encoding="utf-8")


class F7NativeHpkeAttachmentContract(unittest.TestCase):
    def test_real_native_preparation_uses_allowlist_size_rule(self):
        self.assertIn("!hpkeAttachmentAllowed(operation,attachment.size())",SOURCE)
        self.assertIn("qaPost(CloudOperation.APK_QA_CHUNK,payload,piece)",ANDROID)
        self.assertIn("if(op===5 || op===22)",SERVER)

    def test_cxx17_compiled_limits_prevent_first_chunk_failure(self):
        source=r"""
#include "spdecode_hpke.h"
using namespace spdecode;
static_assert(hpkeAttachmentAllowed(22, 1));
static_assert(hpkeAttachmentAllowed(22, 2U*1024U*1024U));
static_assert(!hpkeAttachmentAllowed(22, 0));
static_assert(!hpkeAttachmentAllowed(22, 2U*1024U*1024U+1));
static_assert(hpkeAttachmentAllowed(5, 8U*1024U*1024U));
static_assert(!hpkeAttachmentAllowed(5, 8U*1024U*1024U+1));
static_assert(!hpkeAttachmentAllowed(5, 0));
static_assert(hpkeAttachmentAllowed(21, 0));
static_assert(hpkeAttachmentAllowed(23, 0));
static_assert(hpkeAttachmentAllowed(24, 0));
static_assert(!hpkeAttachmentAllowed(21, 1));
static_assert(!hpkeAttachmentAllowed(23, 1));
static_assert(!hpkeAttachmentAllowed(24, 1));
static_assert(!hpkeAttachmentAllowed(16, 1));
static_assert(!hpkeAttachmentAllowed(1, 1));
int main() { return hpkeAttachmentLimit(22)==2U*1024U*1024U ? 0 : 1; }
"""
        with tempfile.TemporaryDirectory() as tmp:
            src=Path(tmp)/"f7_hpke_contract.cpp"
            out=Path(tmp)/"f7_hpke_contract"
            src.write_text(source,encoding="utf-8")
            subprocess.run(["c++","-std=c++17","-Wall","-Wextra","-Werror",
                "-I",str(CPP),str(src),"-o",str(out)],check=True,
                capture_output=True,text=True,timeout=45)
            subprocess.run([str(out)],check=True,timeout=10)


if __name__=="__main__":
    unittest.main()
