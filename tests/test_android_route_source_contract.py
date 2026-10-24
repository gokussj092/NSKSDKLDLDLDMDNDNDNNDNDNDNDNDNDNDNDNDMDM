"""Static integration contract: every registered decoder has exactly one Android route.

This checks completeness of wiring, NOT cryptographic compatibility. A successful
Android golden built from old/synthetic data does not certify current exports.
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PARITY = ROOT / "android/app/src/main/java/com/ghostdeveloper/spdecode/parity"
ROUTER = PARITY / "AndroidOfflineDecoderRouter.kt"
TEXT = ROOT / "android/app/src/main/java/com/ghostdeveloper/spdecode/TextProtocolDecoder.kt"
PRESENTATION = ROOT / "android/app/src/main/java/com/ghostdeveloper/spdecode/ResultPresentation.kt"


class AndroidSourceWiringContract(unittest.TestCase):
    def test_every_registered_script_exists_and_has_an_android_dispatch(self):
        registry = json.loads((ROOT / "decoders.json").read_text("utf-8"))["decoders"]
        content = ROUTER.read_text("utf-8")
        route_lines = re.findall(r'^\s*"([^"]+)"\s*->\s*([A-Za-z_]\w*)\.decode\(', content, re.M)
        # Exactly one explicitly audited extra Phase F route, besides the
        # original 61 legacy switch entries; no unrelated fallback accepted.
        self.assertEqual(len(route_lines), len(registry)+1)
        self.assertEqual({suffix for suffix, _ in route_lines}, set(registry)|{"izph"})
        self.assertIn(("izph","IzphNativePort"),route_lines)
        self.assertEqual(len({suffix for suffix, _ in route_lines}), len(route_lines))
        for suffix, spec in registry.items():
            self.assertIn(spec["runtime"], ("python", "node", "php"))
            self.assertTrue((ROOT / spec["script"]).is_file(), suffix)
        for suffix, klass in route_lines:
            self.assertTrue((PARITY / f"{klass}.kt").is_file(),
                f"{suffix}: Android source {klass}.kt is missing")

    def test_text_specific_engines_are_not_replaced_by_file_decoders(self):
        kotlin = TEXT.read_text("utf-8")
        self.assertIn('"netmod"->netmod(input.content)', kotlin)
        self.assertIn('"_netsyna_netmod_"', kotlin)
        self.assertIn('scheme.startsWith("nm-")', kotlin)
        self.assertIn('"dark","ssc"', kotlin)
        self.assertIn('"tls","dark","ssc"', kotlin)
        self.assertIn("AndroidOfflineDecoderRouter.decode", kotlin)
        router = ROUTER.read_text("utf-8")
        self.assertIn('"dark" -> DarkPort.decode(context,input)', router)
        self.assertIn('"nm" -> NmPort.decode(input)', router)

    def test_android_structured_copy_credits_ghost_developer_only(self):
        source = PRESENTATION.read_text("utf-8")
        clipboard = (ROOT / "android/app/src/main/java/com/ghostdeveloper/spdecode/TelegramResultCopy.kt").read_text("utf-8")
        self.assertIn("Desarrollado por: Ghost Developer", source)
        self.assertIn("// Credits: Ghost Developer", clipboard)
        self.assertNotIn("AES224", source + clipboard)
        self.assertNotIn("https://t.me/CodeBreakersHub", source)
        self.assertNotIn("https://t.me/GhostDeve", source)
        self.assertNotIn("│ Telegram:", source)


if __name__ == "__main__":
    unittest.main()
