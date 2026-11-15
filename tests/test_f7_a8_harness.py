"""Synthetic cross-reference tests: never execute APK code or research scripts."""
from __future__ import annotations
import unittest
import struct
from cloud.apk_analysis.qa_identity import _parse, _resolve_label
from cloud.apk_analysis.qa_tool_harness import inspect_harness


class HarnessTests(unittest.TestCase):
    def test_correlates_dex_and_jadx_without_claiming_decryption(self):
        dex = {"dexHeaders": [{"tableStatus": "PARSED",
            "candidateMethods": [{"class": "Lcom/owned/Cripto;", "name": "decrypt"}],
            "methodCodeEvidence": [{"class": "Lcom/owned/Cripto;",
                "status": "CODE_ITEM_HASHED", "bytecodeSha256": "0"*64}]}],
            "nativeLibraries": [{"sectionStatus": "PARSED"}]}
        tools = {"jadxAttempted": True, "jadx": {"candidateCallSites": [
            {"class": "com.owned.Cripto", "method": "m948", "indicator": "JCA_CIPHER"},
            {"class": "org.conscrypt.OpenSSLCipher", "method": "a", "indicator": "JCA_CIPHER"}]}}
        report = inspect_harness(dex, tools)
        self.assertEqual(report["catalogue"]["registeredResearchScripts"], 63)
        self.assertEqual(report["catalogue"]["researchScriptsAutoExecuted"], 0)
        self.assertEqual(report["candidateClasses"][0]["class"], "com.owned.Cripto")
        self.assertIn("JADX_REFERENCE", report["candidateClasses"][0]["evidence"])
        self.assertIn("DEX_CODE_ITEM_SHA256", report["candidateClasses"][0]["evidence"])
        self.assertFalse(report["methodValidated"])
        self.assertFalse(report["codeExecuted"])
        self.assertNotIn("org.conscrypt", str(report))

    def test_bounded_even_for_many_candidates(self):
        dex={"dexHeaders": [{"candidateMethods": [
            {"class": f"Lcom/owned/C{i};", "name": "decrypt"} for i in range(80)
        ]}]}
        report=inspect_harness(dex, {"jadx": {}})
        self.assertLessEqual(len(report["candidateClasses"]), 24)
        self.assertTrue(report["candidateClassesTruncated"])


class IdentityTests(unittest.TestCase):
    @staticmethod
    def pool(items):
        data=bytearray()
        offsets=[]
        for word in items:
            encoded=word.encode("utf-8")
            assert len(encoded)<128
            offsets.append(len(data))
            data.extend((len(word),len(encoded)))
            data.extend(encoded)
            data.append(0)
        header=bytearray(28)
        struct.pack_into("<HHI",header,0,1,28,28+4*len(items)+len(data))
        struct.pack_into("<I",header,8,len(items))
        struct.pack_into("<I",header,16,0x100)
        struct.pack_into("<I",header,20,28+4*len(items))
        return bytes(header)+b"".join(struct.pack("<I",offset) for offset in offsets)+data

    @staticmethod
    def tag(name_idx, attr_name, raw_value, typ, data):
        chunk=bytearray(56)
        struct.pack_into("<HHI",chunk,0,0x0102,16,56)
        struct.pack_into("<I",chunk,12,0xffffffff)
        struct.pack_into("<I",chunk,16,0xffffffff)
        struct.pack_into("<I",chunk,20,name_idx)
        struct.pack_into("<HHH",chunk,24,20,20,1)
        struct.pack_into("<I",chunk,36,0xffffffff)
        struct.pack_into("<I",chunk,40,attr_name)
        struct.pack_into("<I",chunk,44,raw_value)
        struct.pack_into("<HBBI",chunk,48,8,0,typ,data)
        return chunk

    def test_manifest_package_and_resource_referenced_label(self):
        pool=self.pool(["manifest","package","com.owned.sample","application","label"])
        first=self.tag(0,1,2,3,2)
        label_id=0x7f120000
        second=self.tag(3,4,0xffffffff,1,label_id)
        body=pool+first+second
        axml=struct.pack("<HHI",3,8,8+len(body))+body
        parsed=_parse(axml)
        self.assertEqual(parsed["packageName"],"com.owned.sample")
        self.assertIsNone(parsed["appName"])
        self.assertEqual(parsed["_labelResourceId"],label_id)

    def test_literal_resource_string_lookup(self):
        pool=self.pool(["Owned Demo App"])
        entry=struct.pack("<HHI",8,0,0)+struct.pack("<HBBI",8,0,3,0)
        chunk=bytearray(24)+entry
        struct.pack_into("<HHI",chunk,0,0x0201,20,len(chunk))
        chunk[8]=0x12
        struct.pack_into("<I",chunk,12,1)
        struct.pack_into("<I",chunk,16,24)
        struct.pack_into("<I",chunk,20,0)
        package=struct.pack("<HHII",0x0200,12,12+len(chunk),0x7f)+chunk
        table=struct.pack("<HHII",2,12,12+len(pool)+len(package),1)+pool+package
        self.assertEqual(_resolve_label(table,0x7f120000),"Owned Demo App")
        self.assertIsNone(_resolve_label(table,0x7f120001))


if __name__=="__main__":
    unittest.main()
