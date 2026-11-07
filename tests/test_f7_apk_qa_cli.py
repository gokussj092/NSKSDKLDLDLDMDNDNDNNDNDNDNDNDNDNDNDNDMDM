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

    def test_shell_has_one_command_without_manual_device_or_user_token(self):
        self.assertIn("apk-qa)","\n"+SCRIPT)
        self.assertIn("apk_qa_enable()",SCRIPT)
        self.assertIn("compose --profile apk-qa build web apk-qa",SCRIPT)
        self.assertNotIn("read -r -p",SCRIPT[SCRIPT.find("apk_qa_enable(){"):
                                               SCRIPT.find("apk_qa_status(){")])

if __name__=="__main__":
    unittest.main()
