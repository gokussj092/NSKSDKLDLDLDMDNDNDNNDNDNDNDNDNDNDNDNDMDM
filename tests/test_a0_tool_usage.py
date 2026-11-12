"""F7-A0-P02 isolated fixtures: no network, APKs or tool execution."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from scripts.ci.map_apk_tool_usage import audit, python_signals, UsageMapError


class ToolUsageInventoryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.write("scripts/apk_analysis/example.py",
                   "raise RuntimeError('DO NOT RUN')\n"
                   "from urllib.request import urlopen\nimport subprocess\nimport argparse\n"
                   "def main():\n"
                   "    p = argparse.ArgumentParser()\n"
                   "    p.add_argument('--abi')\n"
                   "    p.add_argument('input')\n"
                   "    subprocess.run(['echo', 'fixture'])\n"
                   "    urlopen('https://invalid.example')\n")
        self.write("scripts/apk_analysis/capture.js", "Java.use('example.Demo');\n")
        self.write("analysis/com.example.vpn/42/REPRODUCE.md",
                   "Run python scripts/apk_analysis/example.py --abi arm64-v8a\n")
        self.write("tests/test_consumers.py",
                   "import example\n# capture.js is an observer, not an approved runner\n")
        records = []
        for path in sorted((self.root / "scripts/apk_analysis").iterdir()):
            raw = path.read_bytes()
            sha = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            records.append({"path": path.relative_to(self.root).as_posix(),
                            "size": len(raw), "git_blob_sha1": sha,
                            "approval": "UNREVIEWED"})
        self.write("analysis/platform/apk-tooling/tool_sources.v1.json",
                   json.dumps({"schema_version": 1, "source_commit": "fixture", "sources": records}))

    def write(self, path, data):
        f = self.root / path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(data, encoding="utf-8")

    def test_reference_mapping_and_api_signals(self):
        report = audit(self.root)
        self.assertEqual(report["summary"]["tool_count"], 2)
        src = next(t for t in report["tools"] if t["path"].endswith("example.py"))
        self.assertIn("com.example.vpn/42", src["documented_app_build_references"])
        self.assertIn("tests/test_consumers.py", src["test_source_references"])
        self.assertIn("NETWORK_API", src["source_assessment"]["static_signals"])
        self.assertIn("PROCESS_LAUNCH", src["source_assessment"]["static_signals"])
        self.assertIn("--abi", src["source_assessment"]["cli_flags"])
        self.assertEqual(report["summary"]["approved_for_unattended_execution"], 0)

    def test_js_is_only_inspected(self):
        result = audit(self.root)
        tool = next(t for t in result["tools"] if t["path"].endswith(".js"))
        self.assertIn("RUNTIME_INSTRUMENTATION", tool["source_assessment"]["static_signals"])
        self.assertEqual(tool["source_assessment"]["parse_status"], "TEXT_INSPECTED_NOT_EXECUTED")

    def test_source_change_is_rejected(self):
        file = self.root / "scripts/apk_analysis/example.py"
        file.write_text(file.read_text() + "\n# unexpected change\n")
        with self.assertRaises(UsageMapError):
            audit(self.root)

    def test_new_uninventoried_tool_is_rejected(self):
        self.write("scripts/apk_analysis/new.py", "print('extra')\n")
        with self.assertRaises(UsageMapError):
            audit(self.root)

    def test_general_doc_reference_does_not_claim_extra_app(self):
        self.write("docs/guide.md", "example.py documented in the shared guide\n")
        item = next(t for t in audit(self.root)["tools"] if t["path"].endswith("example.py"))
        self.assertEqual(item["documented_app_build_references"], ["com.example.vpn/42"])

    def test_inventory_file_alone_is_not_a_consumer(self):
        # A registered tool with no evidence outside the baseline remains unmapped.
        self.write("tests/test_consumers.py", "import example\n")
        report = audit(self.root)
        capture = next(t for t in report["tools"] if t["path"].endswith("capture.js"))
        self.assertEqual(capture["reference_count"], 0)

    def test_invalid_python_recorded_without_exec(self):
        out = python_signals("def broken(:\n  pass\n", set())
        self.assertEqual(out["parse_status"], "SYNTAX_ERROR_NOT_EXECUTED")


if __name__ == "__main__":
    unittest.main()
