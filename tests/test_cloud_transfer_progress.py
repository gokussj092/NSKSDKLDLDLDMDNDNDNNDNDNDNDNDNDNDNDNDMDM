"""Cloud-only progress labels: real request/response milestones, all supported locales."""
from __future__ import annotations

import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/ghostdeveloper/spdecode"
RES = ROOT / "android/app/src/main/res"


class CloudTransferProgressContract(unittest.TestCase):
    def test_complete_translation_for_all_four_progress_messages(self):
        required = {
            "decode_progress_wait",
            "decode_progress_sending",
            "decode_progress_processing",
            "decode_progress_downloading_results",
        }
        locales = sorted(RES.glob("values*/strings.xml"))
        self.assertGreaterEqual(len(locales), 14)
        for file in locales:
            with self.subTest(locale=file.parent.name):
                strings = {
                    node.attrib["name"]: node.text
                    for node in ET.parse(file).getroot().findall("string")
                }
                self.assertTrue(required.issubset(strings), required - strings.keys())
                for key in required:
                    self.assertTrue(strings[key] and strings[key].strip(), key)

    def test_every_cloud_decode_route_delivers_live_phase_callbacks(self):
        client = (JAVA / "cloud/CloudDecodeClient.kt").read_text(encoding="utf-8")
        self.assertIn(
            "enum class TransferPhase { SENDING, PROCESSING, DOWNLOADING_RESULTS }",
            client,
        )
        for phase in ("SENDING", "PROCESSING", "DOWNLOADING_RESULTS"):
            self.assertIn("onPhase(TransferPhase." + phase + ")", client)
        for method in (
            "decodeFile", "decodeText", "decodeOnlineReference",
            "decodeNurCatalog", "decodeServerVpnProvider",
        ):
            self.assertIn("suspend fun " + method, client)
        self.assertIn("decodeHttpCustomReference(reference,onPhase)", client)
        self.assertIn("decodeHttpInjectorCloud(reference,onPhase)", client)
        self.assertIn("decode(CloudOperation.FILE,body,bytes,onPhase)", client)
        self.assertIn(
            "decode(CloudOperation.IMPORT_CATALOG,JSONObject().put(\"consent\",true),onPhase=onPhase)",
            client,
        )

    def test_ui_is_bound_to_active_request_and_never_sees_network_secrets(self):
        activity = (JAVA / "MainActivity.kt").read_text(encoding="utf-8")
        screen = (JAVA / "SpDecodeApp.kt").read_text(encoding="utf-8")
        self.assertIn("if(generation==importGeneration && busy) cloudProgressPhase=phase.ordinal", activity)
        self.assertIn("withContext(Dispatchers.Main.immediate)", activity)
        self.assertGreaterEqual(
            activity.count("onPhase={phase->markCloudProgress(generation,phase)}"), 6
        )
        self.assertIn("cloudProgressPhase=cloudProgressPhase", activity)
        self.assertIn("cloudProgressPhase=null", activity)
        self.assertIn("if(BuildConfig.SPDECODE_CLOUD_ENABLED && cloudProgressPhase!=null)", screen)
        for key in (
            "decode_progress_wait", "decode_progress_sending",
            "decode_progress_processing", "decode_progress_downloading_results",
        ):
            self.assertIn("R.string." + key, screen)
        self.assertNotIn("api.spdecode.xyz", screen)
        self.assertNotIn("api.spdecode.xyz", activity)


if __name__ == "__main__":
    unittest.main()
