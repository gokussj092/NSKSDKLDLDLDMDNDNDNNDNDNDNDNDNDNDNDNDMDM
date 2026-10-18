"""Offline VPS installer security checks; never access a real server."""
from __future__ import annotations
from pathlib import Path
import subprocess
import unittest
ROOT=Path(__file__).resolve().parents[4]
VPS=ROOT/"cloud/infra/vps"
class VPSInstallerTests(unittest.TestCase):
    def test_bash_parses(self):
        for name in ("install.sh","resume-install.sh","spdecodectl","android-build.sh"):
            with self.subTest(file=name):
                result=subprocess.run(["bash","-n",str(VPS/name)],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
    def test_https_proxy_and_cidr(self):
        result=subprocess.run(["python3",str(VPS/"nginx-config.py"),"ghost.duckdns.org","198.51.100.12/32"],capture_output=True,text=True,check=True)
        for line in ("listen 443 ssl","allow 198.51.100.12/32","deny all","location ^~ /api/admin/","proxy_set_header X-Real-IP $remote_addr"):
            self.assertIn(line,result.stdout)
    def test_three_host_isolation_for_spdecode(self):
        result=subprocess.run(["python3",str(VPS/"nginx-config.py"),
            "spdecode.xyz","198.51.100.12/32","--api-domain","api.spdecode.xyz",
            "--panel-domain","panel.spdecode.xyz","--www"],
            capture_output=True,text=True,check=True)
        config=result.stdout
        for host in ("server_name spdecode.xyz;","server_name api.spdecode.xyz;",
                     "server_name panel.spdecode.xyz;","server_name www.spdecode.xyz;"):
            self.assertIn(host,config)
        self.assertEqual(config.count("listen 443 ssl;"),4)
        self.assertEqual(config.count("ssl_certificate /etc/letsencrypt/live/spdecode.xyz/fullchain.pem;"),4)
        self.assertIn("location ^~ /api/v1/",config)
        self.assertIn("location ^~ /api/admin/",config)
        self.assertIn("location ^~ /_next/",config)
        self.assertIn("location ^~ /api/v1/ { return 404; }",config)
        self.assertIn("location ^~ /api/admin { return 404; }",config)
        self.assertIn("allow 198.51.100.12/32;",config)
        self.assertIn("deny all;",config)
        self.assertNotIn("proxy_pass http://127.0.0.1:8000",config)
        self.assertNotIn("proxy_pass http://127.0.0.1:3001",config)
    def test_invalid_or_cross_domain_subdomains_rejected(self):
        args=[
            ["--api-domain","evil.example.com"],
            ["--panel-domain","api.spdecode.xyz"],
            ["--api-domain","-injection.spdecode.xyz"],
            ["--panel-domain","panel.spdecode.xyz;return 200"],
        ]
        for extra in args:
            p=subprocess.run(["python3",str(VPS/"nginx-config.py"),
                "spdecode.xyz","198.51.100.12/32",*extra],
                capture_output=True,text=True)
            self.assertNotEqual(p.returncode,0,extra)
    def test_real_domain_and_support_email_wiring(self):
        install=(VPS/"install.sh").read_text()
        android=(VPS/"android-build.sh").read_text()
        compose=(ROOT/"cloud/compose.yaml").read_text()
        for term in ('--api-domain','--panel-domain','--support-email',
                     'CLOUD_ADMIN_PUBLIC_ORIGIN=https://$PANEL_DOMAIN',
                     'CLOUD_API_PUBLIC_ORIGIN=https://$API_DOMAIN',
                     'CLOUD_SUPPORT_EMAIL=$SUPPORT_EMAIL',
                     'CERTBOT_DOMAINS=(-d "$DOMAIN" -d "$API_DOMAIN" -d "$PANEL_DOMAIN")'):
            self.assertIn(term,install)
        self.assertIn('"$CFG/api-domain"',android)
        self.assertIn('SPDECODE_CLOUD_API_BASE_URL="https://$domain"',android)
        self.assertIn("CLOUD_SUPPORT_EMAIL:",compose)
    def test_interrupted_certbot_install_recovery_keeps_existing_secrets(self):
        script=(VPS/"resume-install.sh").read_text()
        for fragment in ('/etc/spdecode/cloud.env', 'sites-enabled/spdecode',
                         '--disable-legacy-spdecode','/var/www/spdecode-acme/',
                         'SPDECODE-ACME-READY', 'nginx -t',
                         'certbot certonly --webroot',
                         'docker compose --project-name spdecode',
                         'spdecode status'):
            self.assertIn(fragment,script)
        self.assertNotIn('openssl rand',script)
        self.assertNotIn('CLOUD_SESSION_SIGNING_KEY=',script)
        self.assertNotIn('CLOUD_WORKER_TOKEN=',script)
        self.assertNotIn('git clone ',script)
    def test_acme_parents_are_traversable_even_under_umask_077(self):
        for name in ("install.sh","resume-install.sh"):
            script=(VPS/name).read_text()
            self.assertIn("umask 077",script)
            self.assertIn("install -d -m 0755 /var/www/spdecode-acme",script)
            self.assertIn("install -d -m 0755 /var/www/spdecode-acme/.well-known",script)
            self.assertIn("chmod 0755 /var/www/spdecode-acme /var/www/spdecode-acme/.well-known",script)
            self.assertLess(script.index("chmod 0755 /var/www/spdecode-acme"),
                            script.index("certbot certonly"))
            self.assertNotIn("chmod -R",script)
    def test_initial_installer_checks_webroot_before_letsencrypt(self):
        source=(VPS/"install.sh").read_text()
        pos=source.index('SPDECODE-ACME-READY')
        self.assertLess(pos,source.index('certbot certonly'))
        self.assertIn('--resolve "$host:80:127.0.0.1"',source)
    def test_http01_preflight_bypasses_http_proxy_and_diagnoses_wrong_vhost(self):
        resume=(VPS/"resume-install.sh").read_text()
        initial=(VPS/"install.sh").read_text()
        for script in (resume,initial):
            self.assertIn("--noproxy '*'",script)
            self.assertIn("--proxy ''",script)
            self.assertIn("--resolve \"$host:80:127.0.0.1\"",script)
        self.assertIn('observed HTTP $status',resume)
        self.assertIn('namei -l "$ACME/$probe"',resume)
        self.assertIn('nginx -T 2>&1',resume)
        self.assertIn('NGINX_GEN="$SCRIPT_DIR/nginx-config.py"',resume)
        self.assertIn('git -C "$ROOT/repo" fetch --no-tags --depth=1',resume)
    def test_nginx_rejects_injection(self):
        for value in ("bad;inject","http://host.test","host.test/path","localhost","host.test\nserver {"):
            p=subprocess.run(["python3",str(VPS/"nginx-config.py"),value],capture_output=True)
            self.assertNotEqual(p.returncode,0,value)
    def test_admin_rejects_worldwide_allowlist(self):
        for cidr in ("0.0.0.0/0","::/0","198.51.100.0/24"):
            p=subprocess.run(["python3",str(VPS/"nginx-config.py"),
              "ghost.duckdns.org",cidr],capture_output=True)
            self.assertNotEqual(p.returncode,0,cidr)
    def test_installer_fail_closed(self):
        data=(VPS/"install.sh").read_text()
        for text in ("CLOUD_API_ENABLED=false","CLOUD_ADMIN_ENABLED=false","CLOUD_FORCE_MAINTENANCE=true","certbot certonly","nginx -t && systemctl reload nginx"):
            self.assertIn(text,data)
    def test_operator_updaters_and_rollback(self):
        data=(VPS/"spdecodectl").read_text()
        for word in ("api|web|panel","worker|engines","update app","rollback)","backup)","flock -x 9","git -C \"$REPO\" fetch","google-service-account","admin-password"):
            self.assertIn(word,data)
        self.assertNotIn("curl | bash",data)
    def test_android_signing_and_gate(self):
        data=(VPS/"android-build.sh").read_text()
        for word in ("--testing-only",":app:assembleRelease :app:bundleRelease","apksigner","jarsigner","cloud_c5_apk_audit.py","gradle-8.11.1","SPDECODE_CLOUD_RELEASE=true","sha256sum -c -"):
            self.assertIn(word,data)
        self.assertNotIn("curl | bash",data)
    def test_server_only_provider_secrets_forwarded(self):
        yml=(ROOT/"cloud/compose.yaml").read_text()
        for word in ("CLOUD_EHI_SIGN_KEY:","CLOUD_EHI_RESPONSE_KEY:","CLOUD_NUR_CATALOG_URL:","CLOUD_SITE_PUBLIC_ORIGIN:"):
            self.assertIn(word,yml)
        worker=yml.split("\n  decoder-worker:",1)[1]
        for word in ("CLOUD_EHI_SIGN_KEY:","CLOUD_ADMIN_SESSION_KEY:"):
            self.assertNotIn(word,worker)
if __name__=="__main__":unittest.main()
