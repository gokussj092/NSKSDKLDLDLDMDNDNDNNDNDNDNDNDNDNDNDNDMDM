"""Controller I/O and cleanup checks with fake SDK binaries, not Android tests."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/apk_analysis/flexnet_emulator_probe.py"


class EmulatorControllerTests(unittest.TestCase):
    def test_children_cannot_consume_following_json_requests(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            for name, code in (("emulator/emulator", "import time\ntime.sleep(60)\n"),
                               ("platform-tools/adb", "import sys,json\nprint(json.dumps({'stdinBytes':len(sys.stdin.read())}))\n")):
                p = base / "sdk" / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("#!/usr/bin/env python3\n" + code)
                p.chmod(0o700)
            requests = [{"adb": ["shell", "first"]}, {"adb": ["shell", "second"]}, {"exit": True}]
            r = subprocess.run([sys.executable, str(SCRIPT), "--work", str(base), "--seconds", "60"],
                               input="".join(json.dumps(q) + "\n" for q in requests), text=True,
                               capture_output=True, timeout=10)
            self.assertEqual(r.returncode, 0, r.stderr)
            replies = [json.loads(line) for line in r.stdout.splitlines()]
            self.assertTrue(replies[0]["controllerReady"])
            self.assertEqual(len(replies), 3)
            for reply in replies[1:]:
                self.assertEqual(reply["exitCode"], 0)
                self.assertEqual(json.loads(reply["stdout"]), {"stdinBytes": 0})
            self.assertEqual((base / "controller.jsonl").stat().st_mode & 0o777, 0o600)

    def test_invalid_runtime_does_not_launch_an_emulator(self):
        with tempfile.TemporaryDirectory() as temporary:
            for seconds in (0, 1801):
                r = subprocess.run([sys.executable, str(SCRIPT), "--work", temporary, "--seconds", str(seconds)],
                                   text=True, capture_output=True, timeout=10)
                self.assertEqual(r.returncode, 2)
                self.assertNotIn("controllerReady", r.stdout)


if __name__ == "__main__": unittest.main()
