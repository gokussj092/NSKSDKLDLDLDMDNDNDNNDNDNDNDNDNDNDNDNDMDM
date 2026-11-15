"""Admin workflow gates. Synthetic subprocess responses, no real signing keys."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github/workflows/android-admin-release.yml").read_text()


def step(name):
    return WORKFLOW.split("      - name: " + name + "\n", 1)[1].split("\n      - ", 1)[0]


def script(name):
    return textwrap.dedent(step(name).split("        run: |\n", 1)[1])


class AdminWorkflowTests(unittest.TestCase):
    def test_any_branch_and_manual_target_do_not_need_a_branch_allowlist(self):
        self.assertIn('branches: ["**"]', WORKFLOW)
        self.assertIn("ref: ${{ inputs.ref || github.ref }}", WORKFLOW)
        self.assertIn("type: string", WORKFLOW.split("  push:", 1)[0])
        self.assertNotIn("pull_request_target:", WORKFLOW)

    def test_each_missing_permanent_secret_fails_before_key_material_is_written(self):
        guard = script("Restore permanent signing key").split("umask 077", 1)[0]
        names = ("STORE_BASE64", "STORE_PASSWORD", "KEY_ALIAS", "KEY_PASSWORD")
        for absent in names:
            with self.subTest(absent=absent):
                env = {**os.environ, **dict.fromkeys(names, "synthetic-only")}
                env[absent] = ""
                result = subprocess.run(["bash", "-c", guard], env=env,
                                        text=True, capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(absent, result.stdout)
                self.assertNotIn("synthetic-only", result.stdout + result.stderr)
        result = subprocess.run(["bash", "-c", guard],
                                env={**os.environ, **dict.fromkeys(names, "synthetic-only")},
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)

    def test_every_gradle_apk_invocation_uses_the_permanent_policy(self):
        for name in ("Compile signed release with R8, lint and tests",
                     "Run reference flows on accelerated Android"):
            with self.subTest(step=name):
                body = step(name)
                self.assertIn('gradle --init-script "$RUNNER_TEMP/admin-permanent-signing.init.gradle"', body)
                for key in ("STORE_PASSWORD", "KEY_ALIAS", "KEY_PASSWORD"):
                    self.assertIn("SPDECODE_RELEASE_" + key, body)
        restore = script("Restore permanent signing key")
        self.assertIn("finalizeDsl", restore)
        self.assertIn("buildType.signingConfig = signing", restore)
        self.assertNotRegex(WORKFLOW, r"(?:-genkeypair|-genkey|debug\.keystore)")

    def verify_signatures(self, mode):
        body = script("Verify permanent signer and APK contents").split("mkdir -p", 1)[0]
        with tempfile.TemporaryDirectory(prefix="admin workflow ") as directory:
            root = Path(directory)
            runner = root / "runner"
            runner.mkdir()
            (runner / "admin-signer-sha256").write_text("a" * 64 + "\n")
            tools = root / "android/build-tools/35.0.0"
            tools.mkdir(parents=True)
            binary = tools / "apksigner"
            binary.write_text("""#!/usr/bin/env python3
import os,sys
from pathlib import Path
apk=sys.argv[-1]
with Path(os.environ['CAPTURE']).open('a') as stream:stream.write(apk+'\\n')
mode=os.environ['FAKE_MODE']
if mode=='unsigned':sys.exit(1)
print('Number of signers: '+('2' if mode=='extra-signer' else '1'))
digest=('b' if mode=='wrong-debug' and '/debug/' in apk else 'a')*64
print('Signer #1 certificate SHA-256 digest: '+digest)
""")
            binary.chmod(0o755)
            apks = ["release/app-release.apk", "debug/app-debug.apk",
                    "androidTest/debug/app-debug-androidTest.apk"]
            for name in apks:
                path = root / "android-admin/app/build/outputs/apk" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"synthetic test placeholder, not an APK")
            capture = root / "checked.txt"
            result = subprocess.run(["bash", "-c", body], cwd=root,
                                    env={**os.environ, "RUNNER_TEMP": str(runner),
                                         "ANDROID_HOME": str(root / "android"),
                                         "FAKE_MODE": mode, "CAPTURE": str(capture)},
                                    capture_output=True, timeout=10)
            checked = capture.read_text().splitlines() if capture.exists() else []
            return result.returncode, checked

    def test_release_debug_and_instrumentation_all_require_the_same_certificate(self):
        code, checked = self.verify_signatures("matching")
        self.assertEqual(code, 0)
        self.assertEqual(len(checked), 3)
        self.assertTrue(checked[-1].endswith("app-debug-androidTest.apk"))

    def test_wrong_debug_signer_unsigned_or_extra_signer_is_rejected(self):
        for mode in ("wrong-debug", "unsigned", "extra-signer"):
            with self.subTest(mode=mode):
                code, _ = self.verify_signatures(mode)
                self.assertNotEqual(code, 0)

    def test_signature_gate_precedes_install_and_failed_jobs_upload_no_apk(self):
        self.assertLess(WORKFLOW.index("name: Verify permanent signer and APK contents"),
                        WORKFLOW.index("name: Run reference flows on accelerated Android"))
        release = step("Upload verified signed release")
        self.assertIn("if: success()", release)
        self.assertIn("outputs/apk/release/*.apk", release)
        diagnostics = step("Upload test diagnostics")
        self.assertIn("if: always()", diagnostics)
        self.assertNotIn("*.apk", diagnostics)
        self.assertIn("if: always()", step("Erase signing material"))

    def test_shell_blocks_have_valid_syntax(self):
        names = re.findall(r"^      - name: (.+)$", WORKFLOW, re.M)
        for name in names:
            if "        run: |\n" in step(name):
                with self.subTest(step=name):
                    result = subprocess.run(["bash", "-n"], input=script(name),
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
