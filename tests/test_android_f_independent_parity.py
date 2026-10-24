"""Phase F source parity: all 13 suffixes, all nine original engines and alternatives."""
from __future__ import annotations
import base64
import json
import unittest
from pathlib import Path

from decoders.Python import flex,izph,n4,crev,ktr,zoba,dev,ltm,vn7
from scripts.android_a24_catalog import generate as catalog_generate,ROOT
from scripts.android_f_independent_fixtures import fixtures, SOURCES
from spdecode.registry import DECODER_REGISTRY

class AndroidPhaseFParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc=catalog_generate()
        cls.entries={row["suffix"]:row for row in cls.doc["entries"]}
        cls.corpus=fixtures()
    def test_all_13_suffixes_and_nine_sources_are_exactly_registered(self):
        doc=self.doc
        self.assertEqual(doc["botRegisteredSuffixes"],239)
        self.assertEqual(doc["androidIndependentNativeSuffixes"],13)
        self.assertEqual(doc["androidNativePortSuffixes"],239)
        self.assertEqual(doc["androidPendingNativeSuffixes"],0)
        self.assertEqual(doc["androidCertifiedSuffixes"],0)
        self.assertEqual(doc["syntheticLinuxCoveredSuffixes"],238)
        self.assertEqual(self.corpus["suffixCount"],13)
        self.assertEqual(self.corpus["moduleCount"],9)
        self.assertEqual(self.corpus["caseCount"],25)
        self.assertEqual(set(self.corpus["modules"]),set(SOURCES))
        expected={"flexnet","flex","izph","ltm","lt","vn7","crev","cer","cerv",
                  "zoba","ktr","n4","dev"}
        self.assertEqual({s for s,r in self.entries.items() if r["migrationPhase"]=="F"},expected)
        for s in expected:
            row=self.entries[s]
            self.assertEqual(row["androidPortStatus"],
                "experimental_independent_9_engines_synthetic")
            self.assertEqual(row["script"],
                "decoders/Python/crev.py" if s=="crev" else DECODER_REGISTRY[s].script)
            self.assertTrue(row["linuxGoldenSynthetic"])
            self.assertFalse(row["androidVerified"])
        self.assertTrue(all(r["androidPortStatus"]!="registered_not_implemented"
            for r in self.entries.values()))
    def test_flex_materials_exactly_match_all_30_original_profiles(self):
        path=ROOT/"android/app/src/main/assets/flex_f_profiles.json"
        data=json.loads(path.read_text("utf-8"))
        self.assertEqual(data["schemaVersion"],1)
        self.assertEqual(data["materialCount"],30)
        self.assertEqual(data["materials"],flex.FLEX_MATERIALS)
        self.assertTrue(all(len(bytes.fromhex(x))>0 for x in data["materials"].values()))
    def test_all_25_vectors_are_decodable_with_exact_python_output(self):
        cases=self.corpus["vectors"]
        self.assertEqual(len(cases),25)
        self.assertEqual({c["suffix"] for c in cases if c["mode"]=="outer"},
            {s for s,row in self.entries.items() if row["migrationPhase"]=="F"})
        for item in cases:
            with self.subTest(extension=item["suffix"],mode=item["mode"]):
                content=base64.b64decode(item["encodedInput"],validate=True)
                self.assertEqual(SOURCES[item["module"]].run(content),item["expected"])
                self.assertIsNotNone(item["expected"])
                try:
                    self.assertIsInstance(json.loads(item["expected"]),(dict,list))
                except ValueError:
                    self.assertTrue(item["expected"].strip())
    def test_two_batches_have_no_collision_with_A_to_E(self):
        F1={"flexnet","flex","izph","ltm","lt","vn7"}
        F2={"crev","cer","cerv","ktr","zoba","dev","n4"}
        self.assertEqual(len(F1),6)
        self.assertEqual(len(F2),7)
        self.assertFalse(F1 & F2)
        self.assertEqual(F1|F2,{r["suffix"] for r in self.entries.values()
            if r["migrationPhase"]=="F"})
        self.assertEqual(self.entries["ost"]["migrationPhase"],"legacy")
        self.assertEqual(self.entries["vlx"]["migrationPhase"],"C")
        self.assertEqual(self.entries["7net"]["migrationPhase"],"D")
        self.assertEqual(self.entries["itv"]["migrationPhase"],"E")

if __name__=="__main__":
    unittest.main()
