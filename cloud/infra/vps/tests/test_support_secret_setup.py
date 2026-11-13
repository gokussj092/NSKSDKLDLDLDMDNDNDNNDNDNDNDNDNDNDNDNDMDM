"""The VPS support secret is created once and never silently rotated."""
import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path

PATH=Path(__file__).resolve().parents[1]/"commerce-setup.py"
spec=importlib.util.spec_from_file_location("commerce_setup",PATH)
commerce_setup=importlib.util.module_from_spec(spec)
spec.loader.exec_module(commerce_setup)

class SupportSecretSetupTests(unittest.TestCase):
    def new_env(self,text=""):
        tmp=tempfile.TemporaryDirectory()
        file=Path(tmp.name)/"cloud.env"
        file.write_text(text)
        file.chmod(0o600)
        self.addCleanup(tmp.cleanup)
        return file
    def pairs(self,path):
        return dict(row.split("=",1) for row in path.read_text().splitlines() if "=" in row)
    def test_create_and_repeat_support_only(self):
        f=self.new_env("CLOUD_ADMIN_ENABLED=true\n")
        self.assertTrue(commerce_setup.prepare_support_only(f))
        first=self.pairs(f)
        key=first["SPDECODE_SUPPORT_ENCRYPTION_KEY"]
        self.assertRegex(key,r"^[a-f0-9]{64}$")
        self.assertFalse(commerce_setup.prepare_support_only(f))
        self.assertEqual(key,self.pairs(f)["SPDECODE_SUPPORT_ENCRYPTION_KEY"])
        self.assertEqual(first["CLOUD_ADMIN_ENABLED"],"true")
        self.assertEqual(stat.S_IMODE(f.stat().st_mode),0o600)
    def test_commerce_init_preserves_flags_and_secret(self):
        pw="a"*64
        f=self.new_env(
          "SPDECODE_SHOP_APP_PASSWORD="+pw+"\n"
          "SPDECODE_SHOP_DB_PASSWORD="+"b"*64+"\n"
          "SPDECODE_DATABASE_URL=postgresql://spdecode_shop_app:"+pw+"@shop-db:5432/spdecode_shop\n"
          "SPDECODE_PAYMENTS_LIVE=false\nSPDECODE_ACCOUNTS_ENABLED=true\n")
        commerce_setup.prepare_configuration(f)
        first=self.pairs(f)
        self.assertRegex(first["SPDECODE_SUPPORT_ENCRYPTION_KEY"],r"^[0-9a-f]{64}$")
        commerce_setup.prepare_configuration(f)
        latest=self.pairs(f)
        for key in ("SPDECODE_SUPPORT_ENCRYPTION_KEY","SPDECODE_SHOP_APP_PASSWORD",
                    "BETTER_AUTH_SECRET","SPDECODE_SHOP_TOKEN_KEY",
                    "SPDECODE_ACCOUNTS_ENABLED","SPDECODE_PAYMENTS_LIVE"):
            self.assertEqual(latest[key],first[key],key)
        self.assertEqual(stat.S_IMODE(f.stat().st_mode),0o600)
    def test_invalid_key_fails_closed_without_replacing_config(self):
        f=self.new_env("SPDECODE_SUPPORT_ENCRYPTION_KEY=invalid\n")
        before=f.read_bytes()
        with self.assertRaises(ValueError):commerce_setup.prepare_support_only(f)
        with self.assertRaises(ValueError):commerce_setup.prepare_configuration(f)
        self.assertEqual(f.read_bytes(),before)
    def test_duplicate_or_unsafe_file_rejected(self):
        f=self.new_env("SPDECODE_SUPPORT_ENCRYPTION_KEY=\nSPDECODE_SUPPORT_ENCRYPTION_KEY=\n")
        with self.assertRaises(ValueError):commerce_setup.prepare_support_only(f)
        other=self.new_env()
        other.chmod(0o644)
        with self.assertRaises(ValueError):commerce_setup.prepare_support_only(other)
        link=other.with_name("linked.env")
        link.symlink_to(other)
        with self.assertRaises(ValueError):commerce_setup.prepare_support_only(link)
