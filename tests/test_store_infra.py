"""Private configuration is idempotent, fail-closed and never enables sales."""
import importlib.util,tempfile,unittest,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('commerce_setup',ROOT/'cloud/infra/vps/commerce-setup.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class StoreConfigurationTests(unittest.TestCase):
    def test_commercial_proxy_has_one_timeout_and_replaces_client_ip(self):
        output=subprocess.check_output(['python3',str(ROOT/'cloud/infra/vps/nginx-config.py'),'spdecode.test'],text=True)
        block=output.split('location = /api/commercial/v1/decode {',1)[1].split('}',1)[0]
        self.assertEqual(block.count('proxy_read_timeout'),1)
        self.assertIn('proxy_read_timeout 70s;',block)
        self.assertIn('proxy_set_header X-Real-IP $remote_addr;',block)
        self.assertIn('client_max_body_size 12m;',block)

    def test_creates_separate_secrets_once_and_keeps_sales_disabled(self):
        with tempfile.TemporaryDirectory()as folder:
            path=Path(folder)/'cloud.env';path.write_text('CLOUD_API_ENABLED=true\n');path.chmod(0o600)
            module.prepare_configuration(path);first=path.read_text();values=dict(row.split('=',1)for row in first.splitlines())
            for key in ['BETTER_AUTH_SECRET','SPDECODE_SHOP_TOKEN_KEY','SPDECODE_SHOP_DB_PASSWORD','SPDECODE_SHOP_APP_PASSWORD']:
                self.assertGreaterEqual(len(values[key]),32)
            self.assertNotEqual(values['SPDECODE_SHOP_DB_PASSWORD'],values['SPDECODE_SHOP_APP_PASSWORD'])
            self.assertTrue(values['SPDECODE_DATABASE_URL'].startswith('postgresql://spdecode_shop_app:'))
            self.assertEqual(values['SPDECODE_STORE_ENABLED'],'false')
            self.assertEqual(values['SPDECODE_PAYMENTS_LIVE'],'false')
            module.prepare_configuration(path);self.assertEqual(first,path.read_text())
            self.assertEqual(path.stat().st_mode&0o777,0o600)

    def test_rejects_database_password_mismatch_before_changing_env(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'cloud.env'
            lines=[
                'SPDECODE_SHOP_APP_PASSWORD=expected-password',
                'SPDECODE_DATABASE_URL=postgresql://spdecode_shop_app:wrong-password@shop-db:5432/spdecode_shop',
                'SPDECODE_ACCOUNTS_ENABLED=true'
            ]
            initial='\n'.join(lines)+'\n'
            path.write_text(initial)
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError,'Inconsistent commerce database credentials'):
                module.prepare_configuration(path)
            self.assertEqual(path.read_text(),initial)

    def test_role_sync_is_idempotent_and_invoked_before_migration(self):
        script=(ROOT/'cloud/accounts/shop-db-init.sh').read_text()
        ctl=(ROOT/'cloud/infra/vps/spdecodectl').read_text()
        self.assertIn("WHERE rolname='spdecode_shop_app'",script)
        self.assertIn('ALTER ROLE spdecode_shop_app WITH LOGIN PASSWORD %L',script)
        self.assertIn('CREATE ROLE spdecode_shop_app LOGIN NOSUPERUSER',script)
        self.assertEqual(ctl.count('compose exec -T shop-db sh /docker-entrypoint-initdb.d/00-shop-role.sh'),2)
        self.assertIn('docker-entrypoint-initdb.d/00-shop-role.sh',ctl)

    def test_rejects_unsafe_permissions_duplicates_and_symlinks(self):
        with tempfile.TemporaryDirectory()as folder:
            path=Path(folder)/'cloud.env';path.write_text('');path.chmod(0o644)
            with self.assertRaises(ValueError):module.prepare_configuration(path)
            path.chmod(0o600);path.write_text('BETTER_AUTH_SECRET=a\nBETTER_AUTH_SECRET=b\n')
            with self.assertRaises(ValueError):module.prepare_configuration(path)
            link=Path(folder)/'linked.env';link.symlink_to(path)
            with self.assertRaises(ValueError):module.prepare_configuration(link)

if __name__=='__main__':unittest.main()
