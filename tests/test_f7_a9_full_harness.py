"""Full server tools: real parsing, bounded resources and no false validation."""
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from cloud.apk_analysis.qa_full_profile import GIB, full_profile, remaining_seconds
from cloud.apk_analysis.qa_method_recipes import (
    inspect_source, scan_method_recipes, merge_recipe_reports, MAX_FILE_BYTES,
)
from cloud.apk_analysis.qa_tooling import inspect_tooling, _base_and_libs
from cloud.apk_analysis.qa_tool_harness import inspect_harness

OWNED = """
package com.spdecode.owned;
public class Owned {
    public static byte[] decryptOwned(byte[] input) throws Exception {
        String privateValue = "PRIVATE_SENTINEL_do_not_export";
        String privateUrl = "https://private.invalid/no-export";
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(privateValue.getBytes(), "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(input);
    }
    public static byte[] caller(byte[] input) throws Exception {
        return decryptOwned(input);
    }
}
"""

class FullBudgets(unittest.TestCase):
    def test_profiles_depend_on_enforced_container_memory(self):
        for amount in (0, -1, True, 2*GIB):
            with self.assertRaises(ValueError):
                full_profile(amount)
        small = full_profile(4*GIB)
        large = full_profile(8*GIB)
        self.assertEqual(small["name"], "FULL_STANDARD")
        self.assertEqual(large["name"], "FULL_12GB_HOST")
        self.assertEqual(large["heap"], "4096m")
        self.assertEqual(large["threads"], 3)
        self.assertEqual(large["jadxMode"], "auto")
        large["heap"] = "bad"
        self.assertEqual(full_profile(8*GIB)["heap"], "4096m")

    def test_deadline_never_extends_a_job(self):
        self.assertEqual(remaining_seconds(200, 100, 60), 60)
        self.assertEqual(remaining_seconds(200, 199.9, 60), 0)
        self.assertEqual(remaining_seconds(10, 100, 60), 0)
        with self.assertRaises(ValueError):
            remaining_seconds(200, 100, 0)

class MethodRecipes(unittest.TestCase):
    def test_actual_method_body_hash_roles_lines_and_caller(self):
        methods, calls = inspect_source(OWNED, "com.spdecode.owned.Owned")
        by_name = {m["method"]: m for m in methods}
        self.assertEqual(set(by_name), {"decryptOwned", "caller"})
        method = by_name["decryptOwned"]
        self.assertEqual(method["algorithms"], ["AES/GCM/NoPadding"])
        self.assertEqual(method["parameters"], {"gcmTagBits": 128})
        self.assertEqual(method["directionObserved"], "DECRYPT")
        self.assertEqual(method["firstLine"], 4)
        self.assertEqual(len(method["sourceMethodSha256"]), 64)
        self.assertIn("CIPHER_FINAL", {o["role"] for o in method["observations"]})
        for observation in method["observations"]:
            self.assertGreaterEqual(observation["line"], method["firstLine"])
            self.assertLessEqual(observation["line"], method["lastLine"])
        self.assertTrue(any(e["caller"] == by_name["caller"]["id"]
                            and e["callee"] == method["id"] for e in calls))
        exported = json.dumps([methods, calls])
        self.assertNotIn("PRIVATE_SENTINEL", exported)
        self.assertNotIn("private.invalid", exported)
        self.assertTrue(all(m["methodValidated"] is False for m in methods))

    def test_comments_strings_and_generic_init_are_not_crypto(self):
        decoy = """
public class Decoy {
    public void harmless() {
        // Cipher.getInstance("AES/GCM/NoPadding");
        String s = "SecretKeySpec(value, AES)";
        object.init(value);
        object.doFinal(value);
    }
}
"""
        self.assertEqual(inspect_source(decoy, "com.spdecode.Decoy"), ([], []))

    def test_pbkdf_simple_numeric_parameters_only(self):
        source = """
public class Kdf {
    public byte[] derive(char[] password, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 120000, 256);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }
}
"""
        methods, _ = inspect_source(source, "com.spdecode.Kdf")
        self.assertEqual(len(methods), 1)
        self.assertEqual(methods[0]["parameters"],
                         {"pbkdfIterations": 120000, "derivedKeyBits": 256})
        self.assertIn("PBKDF2WithHmacSHA256", methods[0]["algorithms"])

    def test_framework_symlink_size_bounds_and_stable_merge(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)/"sources"
            target = root/"com/spdecode/owned/Owned.java"
            target.parent.mkdir(parents=True)
            target.write_text(OWNED)
            framework = root/"android/Decoy.java"
            framework.parent.mkdir()
            framework.write_text(OWNED)
            (target.parent/"Large.java").write_text(" "*(MAX_FILE_BYTES+1))
            outside = Path(td)/"Outside.java"
            outside.write_text(OWNED)
            (target.parent/"Linked.java").symlink_to(outside)
            report = scan_method_recipes(root)
            self.assertEqual(len(report["methods"]), 2)
            self.assertEqual(report["skippedLargeOrUnsafe"], 2)
            self.assertFalse(report["rawSourceExported"])
            merged = merge_recipe_reports([report, report])
            self.assertEqual(len(merged["methods"]), 2)
            self.assertEqual(len(merged["sameClassCalls"]), 1)
            self.assertTrue(merged["observationsMayOverlapRetries"])

class FullTooling(unittest.TestCase):
    def test_full_rpc_worker_command_uses_auto_and_large_heap(self):
        commands = []
        def decompile(command, **kwargs):
            commands.append(command)
            output = Path(command[command.index("-d")+1])
            target = output/"sources/com/spdecode/owned/Owned.java"
            target.parent.mkdir(parents=True)
            target.write_text(OWNED)
            return "EXIT_ZERO"
        env = {
            "SPDECODE_APK_QA_TOOL_MODE": "enabled",
            "SPDECODE_APK_QA_TOOLS_REVIEWED": "true",
            "SPDECODE_APK_QA_LITE": "false",
            "SPDECODE_APK_QA_GHIDRA": "disabled",
        }
        with tempfile.TemporaryDirectory() as td:
            source = Path(td)/"owned.apk"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("classes.dex", b"owned-fixture")
            with patch.dict("os.environ", env, clear=True), \
                 patch("cloud.apk_analysis.qa_tooling._memory_limit", return_value=8*GIB), \
                 patch("cloud.apk_analysis.qa_tooling._verified_jadx", return_value=True), \
                 patch("cloud.apk_analysis.qa_tooling._run_jadx", side_effect=decompile):
                result = inspect_tooling(source, {})
        self.assertEqual(result["toolDistribution"], "JADX_FULL")
        self.assertEqual(result["resourceProfile"], "FULL_12GB_HOST")
        self.assertEqual(result["jadx"]["decompilationMode"], "auto")
        self.assertTrue(result["jadx"]["completed"])
        self.assertIn("-Xmx4096m", commands[0])
        self.assertEqual(commands[0][commands[0].index("-j")+1], "3")
        self.assertFalse(result["uploadedCodeExecuted"])
        methods = result["jadx"]["methodRecipes"]["methods"]
        self.assertEqual(len(methods), 2)
        harness = inspect_harness({}, result)
        self.assertEqual(harness["methodRecipeSummary"]["methodsExported"], 2)
        self.assertFalse(harness["methodValidated"])
        self.assertEqual(harness["catalogue"]["researchScriptsAutoExecuted"], 0)

    def test_full_native_selection_exceeds_legacy_three_explicitly(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td)/"owned.apk"
            dest = Path(td)/"work"
            dest.mkdir()
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("classes.dex", b"fixture")
                for i in range(10):
                    archive.writestr("lib/arm64-v8a/libowned"+str(i)+".so", b"\x7fELF"+b"\x00"*60)
            _, libs, discovered, oversized = _base_and_libs(
                source, dest, profile=full_profile(8*GIB))
            self.assertEqual(discovered, 10)
            self.assertEqual(oversized, 0)
            self.assertEqual(len(libs), 10)

if __name__ == "__main__":
    unittest.main()
