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

    def test_apk_tool_images_have_all_inputs_in_root_docker_context(self):
        # The VPS builds with context: .. (repository root). A broad '**'
        # ignore rule must not hide the pinned JADX installer or QA modules.
        ignored=source(".dockerignore").splitlines()
        self.assertIn("**",ignored)
        allow={line[1:] for line in ignored if line.startswith("!")}
        requested={
            "scripts/apk_analysis/decompile.py",
            "cloud/apk_analysis/__init__.py",
            "cloud/apk_analysis/input_gate.py",
            "cloud/apk_analysis/qa_dex_bytecode.py",
            "cloud/apk_analysis/qa_deep.py",
            "cloud/apk_analysis/qa_jadx_refs.py",
            "cloud/apk_analysis/qa_tool_rpc.py",
            "cloud/apk_analysis/qa_full_profile.py",
            "cloud/apk_analysis/qa_method_recipes.py",
            "cloud/apk_analysis/qa_tooling.py",
            "cloud/apk_analysis/qa_tool_worker.py",
            "cloud/apk_analysis/qa_static.py",
            "cloud/apk_analysis/qa_service.py",
            "cloud/apk_analysis/SpDecodeGhidraReport.java",
        }
        self.assertTrue(requested.issubset(allow), requested-allow)
        self.assertIn("scripts/",allow)
        self.assertIn("scripts/apk_analysis/",allow)
        self.assertIn("cloud/apk_analysis/",allow)
        for name in requested:
            self.assertTrue((ROOT/name).is_file(),name)
        lite=source("cloud/apk_analysis/Dockerfile.qa-lite")
        heavy=source("cloud/apk_analysis/Dockerfile.qa-tools")
        for name in requested:
            self.assertIn(name,lite)
            self.assertIn(name,heavy)
        for secret in ("**/.env","**/.env.*","**/config.json",
                       "**/keyFile.json","**/.git/**"):
            self.assertIn(secret,ignored)
        self.assertNotIn("cloud/apk_analysis/**",allow)
        self.assertNotIn("scripts/**",allow)

    def test_image_loads_reviewed_jdk21_and_pinned_toolchain_once(self):
        docker=source("cloud/apk_analysis/Dockerfile.qa-tools")
        self.assertIn("eclipse-temurin:21-jdk-jammy",docker)
        self.assertIn("fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b",
                      source("cloud/apk_analysis/qa_tooling.py"))
        self.assertIn("ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db",docker)
        self.assertIn("sha256sum -c -",docker)
        self.assertIn("ghidra-headless.sha256",docker)
        self.assertIn("USER 65532:65532",docker)

    def test_qa_python_modules_compile_and_all_images_enforce_syntax_gate(self):
        # This catches syntax errors even when dependencies are unavailable.
        files=sorted((ROOT/"cloud/apk_analysis").glob("*.py"))
        self.assertGreater(len(files),5)
        for path in files:
            with self.subTest(path=path.name):
                compile(path.read_text(encoding="utf-8"),str(path),"exec")
        for name in ("Dockerfile.qa","Dockerfile.qa-lite","Dockerfile.qa-tools"):
            with self.subTest(dockerfile=name):
                self.assertIn("RUN python3 -m compileall -q cloud/apk_analysis",
                    source("cloud/apk_analysis/"+name))

    def test_tool_process_environment_sanitized(self):
        tool=source("cloud/apk_analysis/qa_tooling.py")
        self.assertIn('"JAVA_HOME":"/opt/java/openjdk"',tool)
        self.assertIn("start_new_session=True",tool)
        self.assertIn("os.killpg(child.pid,signal.SIGKILL)",tool)
        self.assertNotIn("env={**os.environ",tool)
        self.assertIn('SPDECODE_APK_QA_TOOLS_REVIEWED',tool)

    def test_lite_toolchain_is_private_resource_limited_and_never_includes_ghidra(self):
        compose=source("cloud/compose.yaml")
        block=compose.split("  apk-tools:\n",1)[1].split("  key-attestation:",1)[0]
        self.assertIn("SPDECODE_APK_TOOLS_MEM_LIMIT:-4096m",block)
        self.assertIn("SPDECODE_APK_TOOLS_CPUS:-1.8",block)
        self.assertIn("SPDECODE_APK_QA_LITE",block)
        self.assertIn("apk-tools-scratch:/analysis:rw",block)
        self.assertNotIn("\n    ports:",block)
        docker=source("cloud/apk_analysis/Dockerfile.qa-lite")
        self.assertIn("eclipse-temurin:21-jre-jammy",docker)
        self.assertIn("scripts/apk_analysis/decompile.py --install",docker)
        self.assertNotIn("ghidra/releases",docker)
        self.assertIn("USER 65532:65532",docker)
        tooling=source("cloud/apk_analysis/qa_tooling.py")
        self.assertIn('"SPDECODE_APK_QA_LITE"',tooling)
        self.assertIn('"-Xmx512m"',tooling)
        self.assertIn('"DISABLED_IN_LITE_PROFILE"',tooling)
        self.assertIn("base,libs,total_native,oversized_native=_base_and_libs(source,scratch,lite=lite,profile=profile)",tooling)
        self.assertIn("not lite and bool(",tooling)
        cli=source("cloud/infra/vps/spdecodectl")
        self.assertIn("apk_qa_enable_lite(){",cli)
        self.assertIn("enable-lite) apk_qa_enable_lite;;",cli)
        self.assertIn("MemAvailable",cli)
        self.assertIn("1100000",cli)

    def test_ci_runs_only_own_fixture_java_and_elf_not_app_release(self):
        ci=source(".github/workflows/f7-apk-tools-image.yml")
        self.assertIn("OwnedFixture.java",ci)
        self.assertIn("libowned.so",ci)
        self.assertIn("--network none",ci)
        self.assertIn("SpDecodeGhidraReport",source("cloud/apk_analysis/qa_tooling.py"))
        self.assertNotIn(":app:assembleRelease",ci)
        self.assertNotIn(":app:bundleRelease",ci)

if __name__=="__main__":unittest.main()
