"""Contracts for F7-A5 isolated toolchain and no Android release workflow."""
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]

def source(p):
    return (ROOT/p).read_text(encoding="utf-8")

class F7ToolingIsolationPolicy(unittest.TestCase):
    def test_no_public_tool_worker_port_or_host_secrets(self):
        compose=source("cloud/compose.yaml")
        block=compose.split("  apk-tools:\n",1)[1].split("  key-attestation:",1)[0]
        self.assertNotIn("\n    ports:",block)
        self.assertIn("networks: [apk-tools-private]",block)
        self.assertIn('read_only: true',block)
        self.assertIn('no-new-privileges:true',block)
        self.assertIn('cap_drop: ["ALL"]',block)
        self.assertNotIn("CLOUD_APK_QA_INTERNAL_TOKEN",block)
        self.assertNotIn("/var/run/docker.sock",block)
        self.assertIn("internal: true",compose.split("  apk-tools-private:",1)[1])

    def test_image_loads_reviewed_jdk21_and_pinned_toolchain_once(self):
        docker=source("cloud/apk_analysis/Dockerfile.qa-tools")
        self.assertIn("eclipse-temurin:21-jdk-jammy",docker)
        self.assertIn("fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b",
                      source("cloud/apk_analysis/qa_tooling.py"))
        self.assertIn("ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db",docker)
        self.assertIn("sha256sum -c -",docker)
        self.assertIn("ghidra-headless.sha256",docker)
        self.assertIn("USER 65532:65532",docker)

    def test_tool_process_environment_sanitized(self):
        tool=source("cloud/apk_analysis/qa_tooling.py")
        self.assertIn('"JAVA_HOME":"/opt/java/openjdk"',tool)
        self.assertIn("start_new_session=True",tool)
        self.assertIn("os.killpg(child.pid,signal.SIGKILL)",tool)
        self.assertNotIn("env={**os.environ",tool)
        self.assertIn('SPDECODE_APK_QA_TOOLS_REVIEWED',tool)

    def test_ci_runs_only_own_fixture_java_and_elf_not_app_release(self):
        ci=source(".github/workflows/f7-apk-tools-image.yml")
        self.assertIn("OwnedFixture.java",ci)
        self.assertIn("libowned.so",ci)
        self.assertIn("--network none",ci)
        self.assertIn("SpDecodeGhidraReport",source("cloud/apk_analysis/qa_tooling.py"))
        self.assertNotIn(":app:assembleRelease",ci)
        self.assertNotIn(":app:bundleRelease",ci)

if __name__=="__main__":unittest.main()
