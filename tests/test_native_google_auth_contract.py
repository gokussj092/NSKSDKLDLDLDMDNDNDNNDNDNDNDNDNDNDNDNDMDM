"""Regression checks for native Google sign-in and its production probe."""
import unittest
from pathlib import Path

from scripts.ci.probe_native_google_auth import validate_config, validate_account

ROOT = Path(__file__).resolve().parents[1]


class NativeGoogleAuthTests(unittest.TestCase):
    def test_config_validation(self):
        valid = {"enabled": True,
                 "googleWebClientId": "123456789012-abcd123456789.apps.googleusercontent.com"}
        validate_config(200, valid)
        for bad in [
            {"enabled": False, "googleWebClientId": valid["googleWebClientId"]},
            {"enabled": True, "googleWebClientId": None},
            {"enabled": True, "googleWebClientId": "https://example.invalid"},
        ]:
            with self.assertRaises(ValueError):
                validate_config(200, bad)
        with self.assertRaises(ValueError):
            validate_config(503, valid)

    def test_anonymous_account_validation(self):
        validate_account(200, {"authEnabled": True, "user": None})
        for status, data in [
            (503, {"authEnabled": False, "user": None}),
            (200, {"authEnabled": False, "user": None}),
            (200, {"authEnabled": True, "user": {"id": "leak"}}),
        ]:
            with self.assertRaises(ValueError):
                validate_account(status, data)

    def test_google_failure_not_silenced(self):
        ui = (ROOT / "android/app/src/main/java/com/ghostdeveloper/spdecode/NativeCommerceScreens.kt").read_text()
        self.assertNotIn('if(code!="GOOGLE_SIGN_IN_CANCELLED")', ui)
        self.assertIn('val code=NativeCommerceAuth.diagnostic(e)', ui)
        self.assertIn('notice=local("No se pudo iniciar sesión.', ui)

    def test_token_exchange_and_strict_confirmation(self):
        client = (ROOT / "android/app/src/main/java/com/ghostdeveloper/spdecode/NativeCommerceAuth.kt").read_text()
        server = (ROOT / "cloud/web/app/api/auth/[...all]/route.js").read_text()
        for marker in (
            "GetSignInWithGoogleOption.Builder(clientId)",
            '"X-SPDECODE-Mobile-Auth","android-v1"',
            '"/api/auth/sign-in/social"',
            "account(strict=true)",
            'parsed.optJSONObject("error") ?: parsed',
        ):
            self.assertIn(marker, client)
        for marker in (
            "/api/auth/native-config", "googleWebClientId",
            "request.headers.get('x-spdecode-mobile-auth')", "body.idToken.token",
        ):
            self.assertIn(marker, server)
        self.assertNotIn("GOOGLE_CLIENT_SECRET", client)

if __name__ == "__main__":
    unittest.main()
