"""F7-A0-P04 JSON Schema consistency checks (offline, stdlib only)."""
from pathlib import Path
import json
import unittest
from cloud.apk_analysis.checkpoint_journal import REC_FIELDS, STAGES, STATUSES, EVIDENCE, PRIVACY

BASE = Path(__file__).resolve().parents[1] / "analysis/platform/apk-tooling/schemas"


class ContractSchemaTests(unittest.TestCase):
    def schema(self, name):
        return json.loads((BASE / name).read_text("utf-8"))

    def test_checkpoint_record_schema_mirrors_current_runtime_contract(self):
        doc = self.schema("checkpoint-event.v1.json")
        record = doc["properties"]["record"]
        self.assertEqual(set(record["required"]), REC_FIELDS)
        self.assertEqual(set(record["properties"]), REC_FIELDS)
        self.assertEqual(set(record["properties"]["stage"]["enum"]), set(STAGES))
        self.assertEqual(set(record["properties"]["status"]["enum"]), STATUSES)
        self.assertEqual(set(record["properties"]["evidence"]["enum"]), EVIDENCE)
        self.assertEqual(set(record["properties"]["privacy"]["enum"]), PRIVACY)
        self.assertFalse(doc["additionalProperties"])
        self.assertFalse(record["additionalProperties"])

    def test_result_receipt_schema_tracks_verified_object_and_hash(self):
        doc = self.schema("result-event.v1.json")
        self.assertEqual(doc["properties"]["event_type"], {"const":"RESULT_COMMITTED"})
        fields = doc["properties"]["record"]
        self.assertEqual(set(fields["required"]),
                         {"result_ref", "result_sha256", "result_bytes",
                          "report_checkpoint_sha256"})
        self.assertFalse(fields["additionalProperties"])

    def test_user_progress_does_not_expose_secret_metadata(self):
        doc = self.schema("user-progress.v1.json")
        fields = doc["properties"]["steps"]["items"]["properties"]
        self.assertEqual(set(fields),
                         {"stage", "status", "evidence", "error_code", "output_available"})
        self.assertFalse(doc["additionalProperties"])
        self.assertFalse(doc["properties"]["steps"]["items"]["additionalProperties"])

    def test_schema_major_version_not_tied_to_android_version(self):
        for name in ("checkpoint-event.v1.json", "result-event.v1.json", "user-progress.v1.json"):
            doc = self.schema(name)
            self.assertEqual(doc["properties"]["schema_version"]["const"], 1)
            self.assertNotIn("versionName", json.dumps(doc))
            self.assertNotIn("versionCode", json.dumps(doc))


if __name__ == "__main__":
    unittest.main()
