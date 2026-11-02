"""Phase 8: keep Cloud API topology, trust anchors and billing authority out of Kotlin.

The APK's interface necessarily handles display text and the official Play
SDK needs Android bindings, but no private server endpoint, shared secret,
payment credit authority or purchase-verification policy may live in Kotlin.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "android/app"
MAIN = APP / "src/main/java/com/ghostdeveloper/spdecode"
CPP = APP / "src/main/cpp"
GRADLE = (APP / "build.gradle.kts").read_text(encoding="utf-8")


class NativeTrustBoundaryTests(unittest.TestCase):
    def test_network_endpoint_is_in_native_compilation_only(self):
        native = (CPP / "spdecode_transport.cpp").read_text(encoding="utf-8")
        cmake = (CPP / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn("cloudOrigin()", native)
        self.assertIn("cloudTransportPath()", native)
        self.assertIn("SPDECODE_CLOUD_ORIGIN", cmake)
        self.assertIn("SPDECODE_CLOUD_ORIGIN=$cloudOrigin", GRADLE)
        self.assertNotIn('buildConfigField("String", "SPDECODE_CLOUD_API_BASE_URL"', GRADLE)
        self.assertNotIn('buildConfigField("String", "SPDECODE_CLOUD_ORIGIN"', GRADLE)

    def test_no_embedded_api_routes_or_backend_secrets_in_android_kotlin(self):
        # This includes the original sources; legacy decoders are excluded from
        # Cloud production by Gradle, and are not exempted from API route checks.
        urls = re.compile(r'https?://(?:api|panel)\\.spdecode\\.xyz|(?:[\'"])/api/(?:v1|v2)/')
        secret_values = re.compile(
            r'(?:CLOUD_WORKER_TOKEN|CLOUD_SESSION_SIGNING_KEY|'
            r'CLOUD_EHI_SIGN_KEY|SPDECODE_VIP_SNIPHER_AUTHORIZATION|'
            r'SPDECODE_ALFAISAL_API_KEY)\\s*[=:]\\s*[\'"]')
        for path in MAIN.rglob("*.kt"):
            with self.subTest(file=str(path.relative_to(MAIN))):
                source = path.read_text(encoding="utf-8")
                self.assertIsNone(urls.search(source))
                self.assertIsNone(secret_values.search(source))

    def test_native_security_verification_uses_jni_boundary(self):
        bridge = (MAIN / "cloud/CloudNativeTransport.kt").read_text(encoding="utf-8")
        cpp = (CPP / "spdecode_transport.cpp").read_text(encoding="utf-8")
        for method in ("nativeSignRequestProof", "nativeVerifyReleaseSigner",
                       "nativePrepareHpke", "nativeOpenHpke", "nativeRuntimeReport"):
            self.assertIn("external fun " + method, bridge)
            self.assertIn('const_cast<char*>("' + method + '")', cpp)
        self.assertIn("RegisterNatives(bridge,methods,static_cast<jint>(sizeof(methods)/sizeof(methods[0])))", cpp)
        self.assertNotIn("Cipher.getInstance", bridge)
        self.assertNotIn("SecretKeySpec", bridge)

    def test_paid_features_remain_disabled_without_native_and_backend_entitlements(self):
        # Do not introduce a client-side credit balance or trust a Kotlin-only
        # purchase callback. Play Billing is documented, not operational.
        for name in ("ApkAnalysisComingSoonScreen.kt", "FeedbackScreen.kt"):
            src = (MAIN / name).read_text(encoding="utf-8")
            self.assertNotIn("BillingClient", src)
            self.assertNotIn("purchaseToken", src)
            self.assertNotIn("creditBalance", src)
        preview = (MAIN / "ApkAnalysisComingSoonScreen.kt").read_text(encoding="utf-8")
        self.assertIn("enabled=false", preview.replace(" ", ""))


if __name__ == "__main__":
    unittest.main()
