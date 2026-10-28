import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("prepare_hardware", Path(__file__).parents[1] / "prepare-hardware-security.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

class HardwareConfigTests(unittest.TestCase):
    def test_preserves_v1_panel_controls_and_existing_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cloud.env"
            path.write_text("CLOUD_LEGACY_API_ENABLED=true\nCLOUD_BETA_ADMISSION_ENABLED=true\nCLOUD_SESSION_SIGNING_KEY=existing\n")
            path.chmod(0o600)
            MODULE.prepare(path, "123456789012", "a1" * 32, "tee")
            first = path.read_text()
            MODULE.prepare(path, "123456789012", "a1" * 32, "tee")
            self.assertEqual(first, path.read_text())
            self.assertIn("CLOUD_LEGACY_API_ENABLED=true", first)
            self.assertIn("CLOUD_BETA_ADMISSION_ENABLED=true", first)
            self.assertIn("CLOUD_SESSION_SIGNING_KEY=existing", first)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_rejects_invalid_configuration_and_public_env_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cloud.env"
            path.write_text("existing=true\n"); path.chmod(0o600)
            for project, cert, level in (("bad", "a1" * 32, "tee"), ("123456", "fake", "tee"), ("123456", "a1" * 32, "software")):
                with self.assertRaises(ValueError):
                    MODULE.prepare(path, project, cert, level)
            self.assertEqual(path.read_text(), "existing=true\n")
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                MODULE.prepare(path, "123456", "a1" * 32, "tee")
