"""Production provider switches must survive QA expiry without exposing secrets."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


FILE = Path(__file__).resolve().parents[1] / "provider-services.py"
spec = importlib.util.spec_from_file_location("spdecode_provider_services", FILE)
providers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(providers)


class ProviderServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root / "etc"
        self.config.mkdir()
        self.source = self.root / "repo"
        self.source.mkdir()
        (self.source / "cloud").mkdir()
        (self.source / "cloud" / "compose.yaml").write_text("services: {}\n")
        asset = self.source / "android/app/src/main/assets"
        asset.mkdir(parents=True)
        (asset / "nur_tunnel_server_endpoint.json").write_text(
            json.dumps({"catalogUrl": "https://strongteam.co/private/path"})
        )
        self.env = self.config / "cloud.env"
        self.write([
            "CLOUD_API_ENABLED=true",
            "CLOUD_EHI_IMPORT_ENABLED=false",
            "CLOUD_NUR_FETCH_ENABLED=false",
            "CLOUD_SERVER_VPN_ENABLED=false",
            "CLOUD_SERVER_VPN_CATALOG_VERSION=11",
            "CLOUD_EHI_SIGN_KEY=" + "S"*32,
            "CLOUD_EHI_RESPONSE_KEY=" + "R"*32,
        ])
        self.config_patch = mock.patch.multiple(
            providers, ROOT=self.root, CFG=self.config, ENV=self.env,
            COMPOSE=self.source / "cloud/compose.yaml",
            NUR_ASSET=asset / "nur_tunnel_server_endpoint.json",
            QA_STATE=self.config / "qa-previous.json"
        )
        self.config_patch.start()
        self.addCleanup(self.config_patch.stop)

    def write(self, lines):
        self.env.write_text("\n".join(lines) + "\n")
        self.env.chmod(0o600)

    def test_enabling_persists_flags_and_bumps_catalog(self):
        with mock.patch.object(providers, "compose"), mock.patch.object(providers, "healthy", return_value=True):
            providers.apply("enable", providers.current_lines())
        updated = providers.current_lines()
        self.assertEqual(providers.value(updated, "CLOUD_EHI_IMPORT_ENABLED"), "true")
        self.assertEqual(providers.value(updated, "CLOUD_NUR_FETCH_ENABLED"), "true")
        self.assertEqual(providers.value(updated, "CLOUD_SERVER_VPN_ENABLED"), "true")
        self.assertEqual(providers.value(updated, "CLOUD_SERVER_VPN_CATALOG_VERSION"), "12")
        self.assertEqual(providers.value(updated, "CLOUD_NUR_CATALOG_URL"),
                         "https://strongteam.co/private/path")

    def test_repeating_enable_does_not_bump_cached_catalog(self):
        with mock.patch.object(providers, "compose"), mock.patch.object(providers, "healthy", return_value=True):
            providers.apply("enable", providers.current_lines())
            providers.apply("enable", providers.current_lines())
        self.assertEqual(providers.value(providers.current_lines(), "CLOUD_SERVER_VPN_CATALOG_VERSION"), "12")

    def test_missing_real_ehi_keys_fails_closed_without_disabling_server_vpn(self):
        lines = [x for x in providers.current_lines() if not x.startswith("CLOUD_EHI_RESPONSE_KEY=")]
        self.write(lines)
        with mock.patch.object(providers, "compose"), mock.patch.object(providers, "healthy", return_value=True):
            providers.apply("enable", providers.current_lines())
        self.assertEqual(providers.value(providers.current_lines(), "CLOUD_EHI_IMPORT_ENABLED"), "false")
        self.assertEqual(providers.value(providers.current_lines(), "CLOUD_SERVER_VPN_ENABLED"), "true")

    def test_verified_cloud_method_is_integrated_and_autoprovisioned_without_manual_upload(self):
        # The owner's Python method uses precisely the fixed protocol constants
        # already audited in the production Android HTTP Injector reference.
        # The VPS deployment copies them privately; no method upload is needed.
        import hashlib
        source = Path(__file__).resolve().parents[4] / (
            "android/app/src/main/java/com/ghostdeveloper/spdecode/HttpInjectorCloudPort.kt"
        )
        with mock.patch.object(providers, "EHI_REFERENCE", source):
            credentials = providers.bundled_ehi()
            self.assertIsNotNone(credentials)
            self.assertEqual(
                tuple(hashlib.sha256(x.encode("ascii")).hexdigest() for x in credentials),
                providers.EHI_PROTOCOL_DIGESTS
            )
            previous = [
                line for line in providers.current_lines()
                if not line.startswith(("CLOUD_EHI_SIGN_KEY=", "CLOUD_EHI_RESPONSE_KEY="))
            ]
            self.write(previous)
            with mock.patch.object(providers, "compose"), mock.patch.object(
                providers, "healthy", return_value=True
            ):
                providers.apply("enable", providers.current_lines())
        current = providers.current_lines()
        self.assertEqual(providers.value(current, "CLOUD_EHI_IMPORT_ENABLED"), "true")
        self.assertEqual(
            hashlib.sha256(providers.value(current, "CLOUD_EHI_SIGN_KEY").encode()).hexdigest(),
            providers.EHI_PROTOCOL_DIGESTS[0]
        )
        self.assertEqual(self.env.stat().st_mode & 0o077, 0)

    def test_autoprovision_does_not_replace_explicitly_invalid_user_credentials(self):
        from hashlib import sha256
        lines = [x for x in providers.current_lines()
                 if not x.startswith("CLOUD_EHI_RESPONSE_KEY=")]
        self.write(lines)
        with mock.patch.object(providers, "compose"), mock.patch.object(providers, "healthy", return_value=True):
            providers.apply("enable", providers.current_lines())
        current = providers.current_lines()
        self.assertEqual(providers.value(current, "CLOUD_EHI_IMPORT_ENABLED"), "false")
        self.assertEqual(providers.value(current, "CLOUD_EHI_SIGN_KEY"), "S"*32)

    def test_bundled_method_tamper_fails_closed(self):
        path = self.root / "bad-CloudPort.kt"
        path.write_text('private const val BUILD = "244"\\n'
                        'private const val ENDPOINT = "https://www.ehi.tools/httpinjector/import_config"\\n'
                        'private const val SIGN_KEY = "' + "X"*32 + '"\\n'
                        'private const val RESPONSE_KEY = "' + "Y"*32 + '"\\n')
        with mock.patch.object(providers, "EHI_REFERENCE", path):
            self.assertIsNone(providers.bundled_ehi())

    def test_qa_state_cannot_be_overwritten(self):
        (self.config / "qa-previous.json").write_text("{}")
        with self.assertRaises(SystemExit):
            providers.apply("enable", providers.current_lines())
        self.assertEqual(providers.value(providers.current_lines(), "CLOUD_SERVER_VPN_ENABLED"), "false")

    def test_invalid_catalog_source_is_rejected_without_any_write(self):
        path = providers.NUR_ASSET
        path.write_text(json.dumps({"catalogUrl": "https://127.0.0.1/local"}))
        before = self.env.read_text()
        with self.assertRaises(SystemExit):
            providers.apply("enable", providers.current_lines())
        self.assertEqual(self.env.read_text(), before)

    def test_health_failure_rolls_back_all_flags(self):
        before = self.env.read_text()
        with mock.patch.object(providers, "compose"), mock.patch.object(providers, "healthy", return_value=False):
            with self.assertRaises(SystemExit):
                providers.apply("enable", providers.current_lines())
        self.assertEqual(self.env.read_text(), before)

    def method_script(self, content=None):
        if content is None:
            content = (
                'ENDPOINT = "https://www.ehi.tools/httpinjector/import_config"\n'
                'APP_BUILD = "244"\n'
                'SIGN_SECRET = "T"*32\n'
                'API_KEY = b"U"*32\n'
            )
        # The importer accepts literal constants, not executable expressions.
        content = content.replace('"T"*32', repr("T"*32)).replace('b"U"*32', repr(b"U"*32))
        script = self.root / "HTTPINJECTOR_CLOUD.py"
        script.write_text(content)
        script.chmod(0o600)
        return script

    def test_import_ehi_method_creates_keys_privately_without_running_code(self):
        script = self.method_script()
        with mock.patch.object(providers, "compose"), mock.patch.object(providers, "healthy", return_value=True):
            providers.import_ehi_script(str(script), providers.current_lines())
        lines = providers.current_lines()
        self.assertEqual(providers.value(lines, "CLOUD_EHI_IMPORT_ENABLED"), "true")
        self.assertEqual(providers.value(lines, "CLOUD_EHI_SIGN_KEY"), "T"*32)
        self.assertEqual(providers.value(lines, "CLOUD_EHI_RESPONSE_KEY"), "U"*32)
        self.assertEqual(self.env.stat().st_mode & 0o077, 0)

    def test_import_rejects_unsafe_permissions_and_does_not_run_code(self):
        script = self.method_script(
            'ENDPOINT="https://www.ehi.tools/httpinjector/import_config"\n'
            'APP_BUILD="244"\n'
            'SIGN_SECRET="T"*32\n'
            'API_KEY=b"U"*32\n'
            'raise RuntimeError("NEVER EXECUTE")\n'
        )
        script.chmod(0o644)
        before = self.env.read_text()
        with self.assertRaises(SystemExit):
            providers.import_ehi_script(str(script), providers.current_lines())
        self.assertEqual(self.env.read_text(), before)
        script.chmod(0o600)
        with mock.patch.object(providers, "compose"), mock.patch.object(providers, "healthy", return_value=True):
            providers.import_ehi_script(str(script), providers.current_lines())
        self.assertEqual(providers.value(providers.current_lines(), "CLOUD_EHI_IMPORT_ENABLED"), "true")

    def test_import_rejects_wrong_method_version_without_writing(self):
        script = self.method_script(
            'ENDPOINT="https://www.ehi.tools/httpinjector/import_config"\n'
            'APP_BUILD="300"\n'
            'SIGN_SECRET="T"*32\n'
            'API_KEY=b"U"*32\n'
        )
        before = self.env.read_text()
        with self.assertRaises(SystemExit):
            providers.import_ehi_script(str(script), providers.current_lines())
        self.assertEqual(self.env.read_text(), before)

    def test_import_rolls_back_if_web_is_unhealthy(self):
        script = self.method_script()
        before = self.env.read_text()
        with mock.patch.object(providers, "compose"), mock.patch.object(providers, "healthy", return_value=False):
            with self.assertRaises(SystemExit):
                providers.import_ehi_script(str(script), providers.current_lines())
        self.assertEqual(self.env.read_text(), before)

    def test_disable_preserves_vendor_credentials_but_bumps_version(self):
        with mock.patch.object(providers, "compose"), mock.patch.object(providers, "healthy", return_value=True):
            providers.apply("enable", providers.current_lines())
            providers.apply("disable", providers.current_lines())
        lines = providers.current_lines()
        self.assertEqual(providers.value(lines, "CLOUD_SERVER_VPN_ENABLED"), "false")
        self.assertEqual(providers.value(lines, "CLOUD_NUR_FETCH_ENABLED"), "false")
        self.assertEqual(providers.value(lines, "CLOUD_EHI_IMPORT_ENABLED"), "false")
        self.assertEqual(providers.value(lines, "CLOUD_SERVER_VPN_CATALOG_VERSION"), "13")
        self.assertEqual(providers.value(lines, "CLOUD_EHI_SIGN_KEY"), "S"*32)


if __name__ == "__main__":
    unittest.main()
