"""Build-contract checks; compilation/device tests are separate and mandatory."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class TestPlayUpdateDistribution(unittest.TestCase):
    def test_gradle_variant_boundary(self):
        gradle = (ROOT / "android/app/build.gradle.kts").read_text()
        self.assertIn('val enablePlayAab=providers.gradleProperty("spdecodePlayAab")', gradle)
        self.assertIn('if (enablePlayAab) from("src/playUpdate/java")', gradle)
        self.assertIn('if (enablePlayAab) {\n        implementation("com.google.android.play:app-update:2.1.0")', gradle)
        self.assertIn('if (enablePlayAab) from("src/playUpdate/assets/', gradle)

    def test_play_only_workflow(self):
        w = (ROOT / ".github/workflows/play-beta-artifacts.yml").read_text()
        self.assertIn("run: gradle --no-daemon :app:assembleRelease", w)
        self.assertIn("run: gradle --no-daemon -PspdecodePlayAab=true :app:bundleRelease", w)
        self.assertIn("verify_play_update_artifacts.py", w)
        self.assertNotIn("assembleRelease :app:bundleRelease", w)

    def test_native_play_flows_and_legacy_suppression(self):
        host = (ROOT / "android/app/src/playUpdate/java/com/ghostdeveloper/spdecode/cloud/PlayInAppUpdateHost.kt").read_text()
        for required in ("AppUpdateType.IMMEDIATE","AppUpdateType.FLEXIBLE",
                         "InstallStatus.DOWNLOADED","completeUpdate()",
                         "DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS",
                         "updatePriority()", "availableVersionCode()",
                         "registerListener(", "unregisterListener("):
            self.assertIn(required, host)
        g = (ROOT / "android/app/build.gradle.kts").read_text()
        self.assertIn('activity=replaceOnce(activity,\n                "                availableAppUpdate=availableAppUpdate,"', g)
        self.assertNotIn("CLOUD_GOOGLE_SERVICE_ACCOUNT_JSON", host)

if __name__ == "__main__":
    unittest.main()
