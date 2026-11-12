"""F7 QA CLI provisioner regression: tests auto-secret setup without Docker/VPS.

Executes the narrow embedded Python config update against temporary files,
never uses production secrets or mutates /etc/spdecode.
"""
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=(ROOT/"cloud/infra/vps/spdecodectl").read_text(encoding="utf-8")
MARKER='if ! python3 - "$ENVFILE" <<\'PY\'\n'


class F7QAActivationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pos=SCRIPT.find(MARKER)
        if pos<0:raise AssertionError("APK QA provisioning block missing")
        begin=pos+len(MARKER)
        end=SCRIPT.find("\nPY\n  then",begin)
        if end<0:raise AssertionError("APK QA provisioning terminator missing")
        cls.py=SCRIPT[begin:end]

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env=Path(self.tmp.name)/"cloud.env"

    def run_setup(self):
        return subprocess.run([sys.executable,"-c",self.py,str(self.env)],
                              capture_output=True,text=True,check=False)

    def test_provisions_private_secret_without_operator_or_device_input(self):
        self.env.write_text("CLOUD_API_ENABLED=true\nCLOUD_V2_HPKE_ENABLED=true\n"
                            "CLOUD_APK_QA_ALLOWED_KEY_SHA256="+"f"*64+"\n",
                            encoding="utf-8")
        result=self.run_setup()
        self.assertEqual(result.returncode,0,result.stderr)
        rows=self.env.read_text().splitlines()
        token=[x.partition("=")[2] for x in rows
               if x.startswith("CLOUD_APK_QA_INTERNAL_TOKEN=")]
        self.assertEqual(len(token),1)
        self.assertRegex(token[0],r"^[A-Za-z0-9_-]{32,128}$")
        self.assertNotIn(token[0],result.stdout+result.stderr)
        self.assertIn("CLOUD_APK_QA_ENABLED=true",rows)
        self.assertNotIn("CLOUD_APK_QA_ALLOWED_KEY_SHA256=","\n".join(rows))
        self.assertEqual(stat.S_IMODE(self.env.stat().st_mode),0o600)

    def test_repeated_setup_preserves_existing_secret(self):
        self.env.write_text("CLOUD_API_ENABLED=true\n",encoding="utf-8")
        self.assertEqual(self.run_setup().returncode,0)
        first=self.env.read_text()
        self.assertEqual(self.run_setup().returncode,0)
        self.assertEqual(first,self.env.read_text())

    def test_bad_existing_secret_fails_without_rotating(self):
        self.env.write_text("CLOUD_APK_QA_INTERNAL_TOKEN=short\n",encoding="utf-8")
        result=self.run_setup()
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.env.read_text(),"CLOUD_APK_QA_INTERNAL_TOKEN=short\n")

    def test_advanced_worker_command_provisions_its_secret_idempotently(self):
        begin=SCRIPT.index("apk_qa_enable_tools(){")
        end=SCRIPT.index("apk_qa_status(){",begin)
        tool_block=SCRIPT[begin:end]
        marker='if ! python3 - "$ENVFILE" "$tool_mem" "$tool_cpus" <<' + "'PY'\n"
        self.assertIn(marker,tool_block)
        body=tool_block.split(marker,1)[1].split("\nPY\n  then",1)[0]
        self.env.write_text("CLOUD_APK_QA_ENABLED=true\nSPDECODE_APK_QA_LITE=true\n",encoding="utf-8")
        def provision():
            return subprocess.run([sys.executable,"-c",body,str(self.env),"8192m","3.0"],
                                  capture_output=True,text=True,check=False)
        first=provision()
        self.assertEqual(first.returncode,0,first.stderr)
        raw=self.env.read_text(encoding="utf-8")
        self.assertIn("CLOUD_APK_QA_TOOLS_REMOTE=enabled",raw)
        self.assertIn("CLOUD_APK_QA_TOOLS_REVIEWED=true",raw)
        self.assertIn("SPDECODE_APK_QA_LITE=false",raw)
        self.assertNotIn("SPDECODE_APK_QA_LITE=true",raw)
        self.assertIn("SPDECODE_APK_QA_GHIDRA=enabled",raw)
        self.assertIn("SPDECODE_APK_TOOLS_MEM_LIMIT=8192m",raw)
        self.assertIn("SPDECODE_APK_TOOLS_CPUS=3.0",raw)
        self.assertIn("SPDECODE_APK_TOOLS_DOCKERFILE=cloud/apk_analysis/Dockerfile.qa-tools",raw)
        credential=[row.partition("=")[2] for row in raw.splitlines()
                    if row.startswith("CLOUD_APK_QA_TOOLS_TOKEN=")]
        self.assertEqual(len(credential),1)
        self.assertRegex(credential[0],r"^[A-Za-z0-9_-]{32,128}$")
        self.assertNotIn(credential[0],first.stdout+first.stderr)
        self.assertEqual(stat.S_IMODE(self.env.stat().st_mode),0o600)
        again=provision()
        self.assertEqual(again.returncode,0,again.stderr)
        self.assertEqual(raw,self.env.read_text(encoding="utf-8"))

    def test_private_readiness_retries_slow_boot_without_failing(self):
        helper="apk_qa_wait_ready(){"+SCRIPT.split("apk_qa_wait_ready(){",1)[1].split(
            "\napk_qa_enable_lite(){",1)[0]
        self.assertIn("for attempt in $(seq 1 45)",helper)
        self.assertIn("sleep 2",helper)
        self.assertIn(">/dev/null 2>&1",helper)
        lite=SCRIPT.split("apk_qa_enable_lite(){",1)[1].split(
            "apk_qa_enable_tools(){",1)[0]
        self.assertIn("apk_qa_wait_ready apk-tools 8793",lite)
        self.assertIn("apk_qa_wait_ready apk-qa 8792",lite)
        # Simulate an asynchronous Docker boot: first two internal health
        # requests fail and the third succeeds, without waiting in the test.
        script=helper+"""
counter=0
compose() {
  if [[ "$*" == *" exec -T apk-tools python3 -c "* ]]; then
    counter=$((counter+1))
    [[ "$counter" -ge 3 ]]
  else
    return 1
  fi
}
sleep() { :; }
log() { :; }
die() { return 1; }
apk_qa_wait_ready apk-tools 8793 || exit 61
printf 'attempts=%s\\n' "$counter"
"""
        result=subprocess.run(["bash","-c",script],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn("attempts=3",result.stdout)

    def test_private_readiness_has_bounded_timeout_and_keeps_rollback(self):
        helper="apk_qa_wait_ready(){"+SCRIPT.split("apk_qa_wait_ready(){",1)[1].split(
            "\napk_qa_enable_lite(){",1)[0]
        script=helper+"""
counter=0
compose() {
  if [[ "$*" == *" exec -T apk-tools python3 -c "* ]]; then
    counter=$((counter+1))
  fi
  return 1
}
sleep() { :; }
log() { :; }
die() { return 1; }
if apk_qa_wait_ready apk-tools 8793; then exit 62; fi
printf 'attempts=%s\\n' "$counter"
"""
        result=subprocess.run(["bash","-c",script],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn("attempts=45",result.stdout)
        lite=SCRIPT.split("apk_qa_enable_lite(){",1)[1].split(
            "apk_qa_enable_tools(){",1)[0]
        self.assertIn("JADX Lite activation failed; restoring prior configuration",lite)
        self.assertIn('cp -p "$previous" "$ENVFILE"',lite)
        self.assertIn("stop apk-tools",lite)

    def test_lite_installer_provisions_existing_secret_idempotently(self):
        segment=SCRIPT.split("apk_qa_enable_lite(){",1)[1].split(
            "apk_qa_enable_tools(){",1)[0]
        self.assertIn("MemAvailable",segment)
        self.assertIn("3400000",segment)
        self.assertIn("1100000",segment)
        self.assertIn("6000000",segment)
        self.assertIn("1152m",segment)
        self.assertIn("Dockerfile.qa-lite",segment)
        self.assertIn("compose --profile apk-qa --profile apk-qa-tools",segment)
        marker='if ! python3 - "$ENVFILE" <<' + "'PY'\n"
        body=segment.split(marker,1)[1].split("\nPY\n  then",1)[0]
        token="z"*48
        self.env.write_text("CLOUD_APK_QA_ENABLED=true\n"
                            "CLOUD_APK_QA_TOOLS_TOKEN="+token+"\n",
                            encoding="utf-8")
        def provision():
            return subprocess.run([sys.executable,"-c",body,str(self.env)],
                                  capture_output=True,text=True,check=False)
        first=provision()
        self.assertEqual(first.returncode,0,first.stderr)
        raw=self.env.read_text(encoding="utf-8")
        self.assertIn("SPDECODE_APK_QA_LITE=true",raw)
        self.assertIn("SPDECODE_APK_TOOLS_DOCKERFILE=cloud/apk_analysis/Dockerfile.qa-lite",raw)
        self.assertIn("SPDECODE_APK_TOOLS_MEM_LIMIT=1152m",raw)
        self.assertIn("CLOUD_APK_QA_TOOLS_TOKEN="+token,raw)
        self.assertNotIn(token,first.stdout+first.stderr)
        self.assertEqual(stat.S_IMODE(self.env.stat().st_mode),0o600)
        again=provision()
        self.assertEqual(again.returncode,0,again.stderr)
        self.assertEqual(raw,self.env.read_text(encoding="utf-8"))

    def test_advanced_worker_fails_closed_on_small_vps(self):
        segment=SCRIPT.split("apk_qa_enable_tools(){",1)[1].split(
            "apk_qa_status(){",1)[0]
        self.assertIn("MemTotal",segment)
        self.assertIn("7800000",segment)
        self.assertIn("8000000",segment)
        self.assertIn('CLOUD_APK_QA_TOOLS_REMOTE=enabled',segment)
        self.assertIn("compose --profile apk-qa --profile apk-qa-tools",segment)
        self.assertIn('return 1',segment)

    def test_shell_has_one_command_without_manual_device_or_user_token(self):
        self.assertIn("apk-qa)","\n"+SCRIPT)
        self.assertIn("apk_qa_enable()",SCRIPT)
        self.assertIn("compose --profile apk-qa build web apk-qa",SCRIPT)
        self.assertNotIn("read -r -p",SCRIPT[SCRIPT.find("apk_qa_enable(){"):
                                               SCRIPT.find("apk_qa_status(){")])

if __name__=="__main__":
    unittest.main()
