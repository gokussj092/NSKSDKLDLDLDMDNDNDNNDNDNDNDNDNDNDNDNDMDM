"""Deep APK/APKS/DEX/ELF regression fixtures; never execute uploaded binaries."""
from io import BytesIO
import struct
import tempfile
from pathlib import Path
import unittest
import zipfile

from cloud.apk_analysis.qa_static import inspect_static


def dex_fixture():
    buf=bytearray(512)
    buf[:8]=b"dex\n035\0"
    struct.pack_into("<I",buf,0x20,len(buf))
    strings=[b"Lcom/example/Crypto;",b"decryptConfiguration",b"AES/GCM/NoPadding",b"Ljava/lang/Object;"]
    struct.pack_into("<II",buf,0x38,len(strings),0x70)
    struct.pack_into("<II",buf,0x40,1,0x90)
    struct.pack_into("<II",buf,0x58,1,0x94)
    struct.pack_into("<II",buf,0x60,1,0x9c)
    struct.pack_into("<I",buf,0x90,0)
    struct.pack_into("<HHI",buf,0x94,0,0,1)
    struct.pack_into("<I",buf,0x9c,0)
    at=0xc0
    for i,s in enumerate(strings):
        struct.pack_into("<I",buf,0x70+i*4,at)
        buf[at]=len(s);at+=1
        buf[at:at+len(s)]=s
        at+=len(s)+1
    return bytes(buf)


def elf_fixture():
    buf=bytearray(1024)
    buf[:7]=b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H",buf,18,183)
    struct.pack_into("<Q",buf,40,0x300)
    struct.pack_into("<HH",buf,58,64,4)
    strings=b"\0libcrypto.so\0EVP_EncryptInit_ex\0"
    buf[0x100:0x100+len(strings)]=strings
    def sec(idx,kind,offset,size,link=0,step=0):
        at=0x300+idx*64
        struct.pack_into("<I",buf,at+4,kind)
        struct.pack_into("<QQ",buf,at+24,offset,size)
        struct.pack_into("<I",buf,at+40,link)
        struct.pack_into("<Q",buf,at+56,step)
    sec(1,3,0x100,len(strings))
    sec(2,11,0x160,48,1,24)
    sec(3,6,0x200,32,1,16)
    struct.pack_into("<I",buf,0x160+24,strings.index(b"EVP_"))
    struct.pack_into("<Q",buf,0x200,1)
    struct.pack_into("<Q",buf,0x208,1)
    return bytes(buf)


def apk_fixture(*, dex=None, elf=None):
    out=BytesIO()
    with zipfile.ZipFile(out,"w",compression=zipfile.ZIP_STORED) as z:
        z.writestr("AndroidManifest.xml",b"\x03\x00\x08\x00\x08\x00\x00\x00")
        if dex is not None:z.writestr("classes.dex",dex)
        if elf is not None:z.writestr("lib/arm64-v8a/libexample.so",elf)
    return out.getvalue()


class F7DeepReports(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def inspect(self, raw, suffix):
        path=Path(self.tmp.name)/("sample"+suffix)
        path.write_bytes(raw)
        return inspect_static(path)

    def test_dex_string_method_and_cipher_references_are_not_claimed_as_verified(self):
        report=self.inspect(apk_fixture(dex=dex_fixture()),".apk")
        entry=report["inventory"]["dexHeaders"][0]
        self.assertEqual(entry["tableStatus"],"PARSED")
        self.assertEqual(entry["methods"],1)
        self.assertEqual(entry["sampledClasses"],["Lcom/example/Crypto;"])
        self.assertEqual(entry["candidateMethods"][0]["name"],"decryptConfiguration")
        self.assertIn("AES/GCM/NoPadding",entry["cryptoReferences"])
        self.assertFalse(report["analysis"]["vendorMethodValidated"])
        self.assertFalse(report["analysis"]["jadxExecuted"])
        self.assertEqual(report["status"],"COMPLETED_PARTIAL")

    def test_elf_sections_imports_and_dependencies(self):
        report=self.inspect(apk_fixture(dex=dex_fixture(),elf=elf_fixture()),".apk")
        entry=report["inventory"]["nativeLibraries"][0]
        self.assertEqual(entry["sectionStatus"],"PARSED")
        self.assertEqual(entry["architecture"],"AARCH64")
        self.assertIn("libcrypto.so",entry["neededLibraries"])
        self.assertIn("EVP_EncryptInit_ex",entry["importedSymbols"])
        self.assertIn("EVP_EncryptInit",entry["cryptoReferences"])

    def test_nested_base_and_split_are_inspected(self):
        outer=BytesIO()
        with zipfile.ZipFile(outer,"w") as z:
            z.writestr("base.apk",apk_fixture(dex=dex_fixture()))
            z.writestr("split_config.arm64_v8a.apk",apk_fixture(elf=elf_fixture()))
            z.writestr("split_config.es.apk",apk_fixture())
        report=self.inspect(outer.getvalue(),".apks")
        inv=report["inventory"]
        self.assertEqual(report["input"]["apkCount"],3)
        self.assertEqual(inv["dexCount"],1)
        self.assertEqual(inv["dexHeaders"][0]["apk"],"base.apk")
        self.assertEqual(inv["nativeLibraries"][0]["apk"],"split_config.arm64_v8a.apk")
        self.assertGreater(inv["uncompressedBytesSeen"],0)
        self.assertEqual(inv["dexParsed"],1)
        self.assertEqual(inv["elfParsed"],1)

    def test_invalid_elf_is_not_reported_as_valid(self):
        report=self.inspect(apk_fixture(elf=b"\x7fELF"+b"\0"*128),".apk")
        self.assertEqual(report["inventory"]["nativeLibraries"][0]["status"],"ELF_HEADER_INVALID")
        self.assertEqual(report["inventory"]["elfParsed"],0)


if __name__=="__main__":
    unittest.main()
