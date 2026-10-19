"""C4 migration guard: actual source routes, no UI changes or bot edits."""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "android/app/src/main"
NATIVE = APP / "cpp/spdecode_transport.cpp"
CLIENT = APP / "java/com/ghostdeveloper/spdecode/cloud/CloudDecodeClient.kt"
JNI = APP / "java/com/ghostdeveloper/spdecode/cloud/CloudNativeTransport.kt"
ACTIVITY = APP / "java/com/ghostdeveloper/spdecode/MainActivity.kt"
GRADLE = ROOT / "android/app/build.gradle.kts"


class CloudC4Tests(unittest.TestCase):
    def test_build_loads_exact_native_library_name(self):
        source = JNI.read_text("utf-8")
        self.assertIn('System.loadLibrary("spdecode")', source)
        self.assertIn('add_library(spdecode SHARED', (APP/"cpp/CMakeLists.txt").read_text("utf-8"))
        self.assertNotIn("libspdecode_cloud.so", source + NATIVE.read_text("utf-8"))

    def test_four_user_flows_have_no_offline_fallback_in_cloud_branch(self):
        source = ACTIVITY.read_text("utf-8")
        for route in (
            "cloudClient.decodeText(userText)",
            "cloudClient.decodeHttpInjectorCloud(parsed)",
            "cloudClient.decodeNurCatalog()",
            "cloudClient.decodeFile(supported.suffix,input",
        ):
            self.assertIn(route, source)
        self.assertIn("if(BuildConfig.SPDECODE_CLOUD_ENABLED)", source)
        self.assertIn("else AndroidOfflineDecoderRouter.decode(this@MainActivity,name,input)",source)
        self.assertIn("if(BuildConfig.SPDECODE_CLOUD_ENABLED) {\n                            // Never fall back",source)
        self.assertEqual(source.count("cloudClient.decodeFile(supported.suffix,input"), 2)

    def test_native_https_policy_and_json_contract(self):
        source=NATIVE.read_text("utf-8")
        for marker in (
            'https://', 'javax/net/ssl/HttpsURLConnection',
            'setInstanceFollowRedirects', 'JNI_FALSE',
            'setConnectTimeout', 'setReadTimeout', 'setChunkedStreamingMode',
            'setRequestProperty', '"Authorization"', '"Accept-Encoding"',
            'CLOUD_NATIVE_RESPONSE_TOO_LARGE', 'postNative',
            '"/api/v1/decode/file"', '"/api/v1/decode/text"',
            '"/api/v1/decode/import/cloud"',
            '"/api/v1/decode/import/catalog/remote"',
        ):
            self.assertIn(marker,source)
        self.assertNotIn('setHostnameVerifier',source)
        self.assertNotIn('setSSLSocketFactory',source)
        self.assertNotIn('http://',source)
        self.assertNotIn("curl ",source)
        self.assertNotIn("openssl",source)

    def test_play_integrity_is_official_classic_nonce_flow(self):
        source=CLIENT.read_text("utf-8")
        for marker in ("IntegrityManagerFactory.create","IntegrityTokenRequest.builder().setNonce(nonce)",
                       "response.token()", "/api/v1/session/challenge",
                       "/api/v1/session", "accessToken", "CLOUD_PARTIAL_RESULT_REJECTED"):
            self.assertIn(marker, source)
        self.assertNotIn("CLOUD_WORKER_TOKEN",source)
        self.assertNotIn("CLOUD_SESSION_SIGNING_KEY",source)
        self.assertNotIn("CLOUD_EHI_SIGN_KEY",source)

    def test_cloud_build_is_explicit_and_https_only(self):
        source=GRADLE.read_text("utf-8")
        self.assertIn("SPDECODE_CLOUD_API_BASE_URL",source)
        self.assertIn("SPDECODE_CLOUD_ORIGIN",source)
        self.assertNotIn("SPDECODE_CLOUD_API_BASE_URL",JNI.read_text("utf-8"))
        self.assertIn("SPDECODE_CLOUD_ORIGIN",NATIVE.read_text("utf-8"))
        self.assertIn("SPDECODE_CLOUD_RELEASE",source)
        self.assertIn('parsed.scheme=="https"',source)
        self.assertIn('buildConfigField("boolean", "SPDECODE_CLOUD_ENABLED"',source)
        self.assertIn('com.google.android.play:integrity:1.6.0',source)
        self.assertNotIn("CLOUD_WORKER_TOKEN",source)
        self.assertNotIn("CLOUD_SESSION_SIGNING_KEY",source)

    def test_original_ui_sources_exactly_match_c0(self):
        frozen=json.loads((ROOT/"docs/cloud/C0_UI_BASELINE.json").read_text("utf-8"))
        import hashlib
        for path,expected in frozen["uiGitBlobSha1"].items():
            raw=(ROOT/path).read_bytes()
            actual=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
            self.assertEqual(actual,expected,path)

    def test_no_bot_files_affected_by_c4_contract(self):
        # This test guards the design intent; the PR diff must still be reviewed.
        source=CLIENT.read_text("utf-8")+JNI.read_text("utf-8")
        self.assertNotIn("Telegram",source)
        self.assertNotIn("Baileys",source)
        self.assertNotIn("spdecode.registry",source)


if __name__=="__main__":
    unittest.main()
