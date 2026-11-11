import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


class AndroidUnityReleaseContract(unittest.TestCase):
    def test_production_apk_qa_only_coming_soon(self):
        app = read("android/app/src/main/java/com/ghostdeveloper/spdecode/SpDecodeApp.kt")
        gradle = read("android/app/build.gradle.kts")
        stub = read("android/app/src/comingSoon/java/com/ghostdeveloper/spdecode/cloud/CloudApkQaDisabled.kt")
        self.assertIn("else if(BuildConfig.SPDECODE_APK_QA_ENABLED)", app)
        self.assertIn('exclude("com/ghostdeveloper/spdecode/cloud/CloudApkQaClient.kt")', gradle)
        self.assertIn('exclude("com/ghostdeveloper/spdecode/cloud/ApkQaWorker.kt")', gradle)
        self.assertIn('if(!enableQaBuild) from("src/comingSoon/java")', gradle)
        self.assertIn("APK_ANALYSIS_COMING_SOON", stub)
        self.assertNotIn("apkQaRequest(", stub)
        self.assertNotIn("/api/v1", stub)

    def test_ad_network_only_in_online_with_cmp(self):
        gradle = read("android/app/build.gradle.kts")
        host = read("android/app/src/unityAds/java/com/ghostdeveloper/spdecode/ads/UnityInterstitialHost.kt")
        activity = read("android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt")
        self.assertIn("Unity Ads is Online-only", gradle)
        self.assertIn("SPDECODE_UNITY_UMP_APP_ID", gradle)
        self.assertIn("UserMessagingPlatform.loadAndShowConsentFormIfRequired", host)
        self.assertIn("consentInformation.canRequestAds()", host)
        self.assertEqual(activity.count("onlineAds?.onSavedResult("), 5)
        self.assertIn("ads_privacy_options", read("android/app/src/main/java/com/ghostdeveloper/spdecode/FunctionalSettingsPanel.kt"))

    def test_ads_retry_and_frequency_are_qa_safe(self):
        host = read("android/app/src/unityAds/java/com/ghostdeveloper/spdecode/ads/UnityInterstitialHost.kt")
        self.assertIn("MAX_DAILY_ADS=12", host)
        self.assertIn("MIN_INTERVAL_MS=240_000L", host)
        self.assertIn("LOAD_RETRY_MS=45_000L", host)
        self.assertIn("retryAfterElapsed=SystemClock.elapsedRealtime()+LOAD_RETRY_MS", host)
        self.assertIn("ad_load_failed_retry_later", host)
        self.assertIn("requestLoadWhenReady()", host)
        self.assertIn("SPDECODE_ADS", host)
        self.assertIn("!consentInformation.canRequestAds()", host)
        self.assertIn("!success||partial", host)
        self.assertIn("onContinue={}", host)
        self.assertNotIn("count>=3", host)
        self.assertNotIn("putString(", host) # No decoded payloads stored in ad telemetry.

    def test_every_file_ads_qa_excludes_catalogs_and_keeps_production_caps(self):
        gradle = read("android/app/build.gradle.kts")
        activity = read("android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt")
        host = read("android/app/src/unityAds/java/com/ghostdeveloper/spdecode/ads/UnityInterstitialHost.kt")
        self.assertIn('spdecodeAdsEveryFileQa', gradle)
        self.assertIn('SPDECODE_ADS_EVERY_FILE_QA', gradle)
        self.assertIn('(!previewDeferred || BuildConfig.SPDECODE_ADS_EVERY_FILE_QA)', gradle)
        self.assertEqual(activity.count("&& !BuildConfig.SPDECODE_ADS_EVERY_FILE_QA"), 4)
        self.assertEqual(activity.count("onlineAds?.onSavedResult("), 5)
        self.assertIn("val qaEveryFile=BuildConfig.SPDECODE_ADS_EVERY_FILE_QA", host)
        self.assertIn("val blockedByPacing=!qaEveryFile", host)
        self.assertIn("val blockedByDailyCap=!qaEveryFile", host)
        self.assertIn("showQaFeedback(activity,feedback)", host)
        self.assertIn("LevelPlay no inicializado", host)
        self.assertIn("UMP no permite anuncios", host)
        self.assertIn("success=(saved||qaEveryFile)", host)
        self.assertNotIn('putString(', host)

    def test_vps_online_fails_closed_for_missing_ads(self):
        build = read("cloud/infra/vps/android-public-build.sh")
        self.assertIn('UNITY_CONFIG="$CFG/unity-ads.env"', build)
        self.assertIn("Incomplete Unity/CMP identifiers", build)
        self.assertIn('UNITY_ARGS+=("-PspdecodeUnityAds=true")', build)

    def test_commercial_v1_independent_of_legacy_v1(self):
        route = read("cloud/web/app/api/commercial/v1/decode/route.js")
        backend = read("cloud/web/lib/commerce/api.mjs")
        legacy = read("cloud/web/lib/v1-gate.mjs")
        self.assertIn("POST=commercialDecode", route)
        self.assertIn("SPDECODE_COMMERCIAL_API_ENABLED", backend)
        self.assertIn("checkApiKey", backend)
        self.assertIn("useApiKey", backend)
        self.assertIn("V1_API_DISABLED", legacy)


if __name__ == "__main__":
    unittest.main()
