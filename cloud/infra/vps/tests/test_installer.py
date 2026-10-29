"""Offline VPS installer security checks; never access a real server."""
from __future__ import annotations
from pathlib import Path
import subprocess
import unittest
ROOT=Path(__file__).resolve().parents[4]
VPS=ROOT/"cloud/infra/vps"
class VPSInstallerTests(unittest.TestCase):
    def test_bash_parses(self):
        for name in ("install.sh","resume-install.sh","resume-services.sh","spdecodectl","android-build.sh"):
            with self.subTest(file=name):
                result=subprocess.run(["bash","-n",str(VPS/name)],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
    def test_https_proxy_panel_uses_authentication_not_ip(self):
        result=subprocess.run(["python3",str(VPS/"nginx-config.py"),"ghost.duckdns.org"],capture_output=True,text=True,check=True)
        for line in ("listen 443 ssl","location ^~ /api/admin/","proxy_set_header X-Real-IP $remote_addr"):
            self.assertIn(line,result.stdout)
    def test_three_host_isolation_for_spdecode(self):
        result=subprocess.run(["python3",str(VPS/"nginx-config.py"),
            "spdecode.xyz","--api-domain","api.spdecode.xyz",
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
        self.assertIn("location @spdecode_v1_unrouted { return 404; }",config)
        self.assertIn("location ^~ /api/admin { return 404; }",config)
        self.assertNotIn("allow 198.51.100.12/32;",config)
        self.assertNotIn("deny all;",config)
        self.assertNotIn("proxy_pass http://127.0.0.1:8000",config)
        self.assertNotIn("proxy_pass http://127.0.0.1:3001",config)
    def test_panel_route_allowlist_and_api_host_isolation(self):
        config=subprocess.run(["python3",str(VPS/"nginx-config.py"),
           "spdecode.xyz","--api-domain","api.spdecode.xyz",
           "--panel-domain","panel.spdecode.xyz"],capture_output=True,
           text=True,check=True).stdout
        panel=config.split("server_name panel.spdecode.xyz;",1)[1]
        panel=panel.split("\\n}",1)[0]
        for route in ("/features","/docs","/privacy","/status","/api/site/status"):
            self.assertIn("location = "+route+" {",panel)
        self.assertIn("location ^~ /api/admin/",panel)
        self.assertIn("location ^~ /admin",panel)
        self.assertIn("location / { return 404; }",panel)
        entry=panel.split("location ^~ /api/v1/ {",1)[1].split("}",1)[0]
        self.assertIn("auth_request /_spdecode_v1_gate;",entry)
        self.assertIn("@spdecode_v1_unrouted",entry)
        self.assertNotIn("proxy_pass",entry)
        self.assertIn("location @spdecode_v1_unrouted { return 404; }",panel)
        cli=(VPS/"spdecodectl").read_text()
        self.assertIn("panel_routes(){",cli)
        self.assertIn("sync-routes)",cli)
        self.assertIn("nginx -t",cli)
    def test_invalid_or_cross_domain_subdomains_rejected(self):
        args=[
            ["--api-domain","evil.example.com"],
            ["--panel-domain","api.spdecode.xyz"],
            ["--api-domain","-injection.spdecode.xyz"],
            ["--panel-domain","panel.spdecode.xyz;return 200"],
        ]
        for extra in args:
            p=subprocess.run(["python3",str(VPS/"nginx-config.py"),
                "spdecode.xyz",*extra],
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
    def test_admin_username_is_actually_forwarded_into_nextjs_container(self):
        compose=(ROOT/"cloud/compose.yaml").read_text()
        self.assertIn('CLOUD_ADMIN_USERNAME: ${CLOUD_ADMIN_USERNAME:-}',compose)
        self.assertIn('CLOUD_ADMIN_PASSWORD_SCRYPT: ${CLOUD_ADMIN_PASSWORD_SCRYPT:-}',compose)
        auth=(ROOT/"cloud/web/lib/c6-admin-auth.mjs").read_text()
        self.assertIn('env.CLOUD_ADMIN_USERNAME',auth)
        self.assertIn('USERNAME.test(username)',auth)
    def test_panel_enable_probes_actual_backend_before_reporting_success(self):
        cli=(VPS/"spdecodectl").read_text()
        self.assertIn('panel_check(){',cli)
        self.assertIn('compose exec -T web node --input-type=module',cli)
        self.assertIn('adminSettings().enabled?0:1',cli)
        self.assertIn('expected 401 for a guest',cli)
        self.assertIn('panel_check || die',cli)
        self.assertIn('check) [[ $# -eq 2 ]]',cli)
    def test_public_login_uses_credentials_no_ip_gating(self):
        config=subprocess.run(["python3",str(VPS/"nginx-config.py"),
          "spdecode.xyz","--api-domain","api.spdecode.xyz",
          "--panel-domain","panel.spdecode.xyz"],
          capture_output=True,text=True,check=True).stdout
        # Check actual Nginx directives, not a comment that says "allow".
        import re
        self.assertIsNone(re.search(r"(?m)^\s*allow\s+",config))
        self.assertIsNone(re.search(r"(?m)^\s*deny\s+",config))
        self.assertIn("location ^~ /api/admin/",config)
        self.assertIn("location ^~ /admin",config)
        cli=(VPS/"spdecodectl").read_text()
        for marker in ('panel_enable()', 'CLOUD_ADMIN_USERNAME',
                       'admin_password', 'set_env CLOUD_ADMIN_ENABLED true',
                       'nginx -t', 'systemctl reload nginx'):
            self.assertIn(marker,cli)
        self.assertNotIn("admin-cidr",cli)
        installer=(VPS/"install.sh").read_text()
        self.assertNotIn("--admin-cidr",installer)
    def test_nur_catalog_only_gets_extended_nginx_https_response_budget(self):
        output=subprocess.run(["python3",str(VPS/"nginx-config.py"),
              "spdecode.xyz","--api-domain","api.spdecode.xyz",
              "--panel-domain","panel.spdecode.xyz"],
              capture_output=True,text=True,check=True).stdout
        api=output.split("server_name api.spdecode.xyz;",1)[1].split("server_name panel.spdecode.xyz;",1)[0]
        self.assertIn("location = /api/v1/decode/import/catalog/remote {",api)
        entry=api.split("location = /api/v1/decode/import/catalog/remote {",1)[1].split("}",1)[0]
        self.assertIn("auth_request /_spdecode_v1_gate;",entry)
        self.assertIn("@spdecode_v1_catalog",entry)
        self.assertNotIn("limit_req ",entry)
        catalog=api.split("location @spdecode_v1_catalog {",1)[1].split("}",1)[0]
        normal=api.split("location @spdecode_v1_general {",1)[1].split("}",1)[0]
        self.assertIn("proxy_read_timeout 155s;",catalog)
        self.assertIn("proxy_read_timeout 35s;",normal)
        file_route=api.split("location @spdecode_v1_file {",1)[1].split("}",1)[0]
        self.assertIn("proxy_read_timeout 65s;",file_route)
        public=output.split("server_name spdecode.xyz;",1)[1].split("server_name api.spdecode.xyz;",1)[0]
        self.assertNotIn("location = /api/v1/decode/import/catalog/remote {",public)
        self.assertIn("location @spdecode_v1_unrouted { return 404; }",public)
    def test_nur_catalog_gets_independent_worker_cpu_and_walltime_caps(self):
        engine=(ROOT/"cloud/workers/python/engine.py").read_text()
        native=(ROOT/"android/app/src/main/cpp/spdecode_transport.cpp").read_text()
        gateway=(ROOT/"cloud/web/lib/c3-gateway.mjs").read_text()
        self.assertIn("TIMEOUT_SECONDS = 20",engine)
        self.assertIn("CATALOG_TIMEOUT_SECONDS = 120",engine)
        self.assertIn("timeout: int = CATALOG_TIMEOUT_SECONDS",engine)
        self.assertIn("preexec_fn=partial(_child_limits,CATALOG_TIMEOUT_SECONDS)",engine)
        # Preserve NUR's 135-second bridge budget and extend the same bound
        # only to the separately allowlisted VPN provider-catalog endpoint.
        self.assertIn('(kind==="catalog"||kind==="server-vpn")?135000:',gateway)
        self.assertIn('kind==="file"&&payload.compatibleExport?50000:25000',gateway)
        self.assertIn('"server-vpn":"import/server-vpn"',gateway)
        self.assertIn("kNurCatalogReadTimeoutMs = 165000",native)
        self.assertIn('operation == 12',native)
        self.assertIn('operation == 9',native)
    def test_worker_permissions_are_normalized_for_root_owned_umask_checkout(self):
        dockerfile=(ROOT/"cloud/workers/python/Dockerfile").read_text()
        self.assertIn("RUN chmod -R a+rX /opt/spdecode",dockerfile)
        self.assertIn("USER 65532:65532",dockerfile)
        self.assertLess(dockerfile.index("RUN chmod -R a+rX /opt/spdecode"),
                        dockerfile.index("USER 65532:65532"))
        self.assertIn("len(load_file_engines()) == 240",dockerfile)
        compose=(ROOT/"cloud/compose.yaml").read_text()
        self.assertIn("start_period: 30s",compose)
    def test_post_tls_recovery_preserves_credentials_and_diagnoses_worker(self):
        script=(VPS/"resume-services.sh").read_text()
        for value in ('/etc/spdecode/cloud.env','/etc/letsencrypt/live/spdecode.xyz/',
                      'pull --ff-only origin "$SPDECODE_REF"',
                      'up -d --build','logs --no-color --tail 65',
                      'curl --noproxy', 'flock -x 9'):
            self.assertIn(value,script)
        self.assertNotIn('certbot certonly',script)
        self.assertNotIn('openssl rand',script)
        self.assertNotIn('git reset --hard',script)
    def test_routing_diagnostics_do_not_expose_secrets_or_modify_state(self):
        script=(VPS/"diagnose-routing.sh").read_text()
        self.assertEqual(subprocess.run(["bash","-n",str(VPS/"diagnose-routing.sh")],
                        capture_output=True).returncode,0)
        for fragment in ('/api/v1/health','/api/v1/ready','/admin/login',
                         '/api/admin/session','--resolve "$host:443:127.0.0.1"',
                         '--noproxy', 'docker ps','nginx -t'):
            self.assertIn(fragment,script)
        for forbidden in ('docker inspect','docker compose config',
                          'cat /etc/spdecode/cloud.env','CLOUD_WORKER_TOKEN=',
                          'CLOUD_ADMIN_SESSION_KEY=','CLOUD_API_ENABLED=true',
                          'systemctl restart'):
            self.assertNotIn(forbidden,script)
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
    def test_goku_private_repo_source_is_explicitly_allowed(self):
        cli=(VPS/"spdecodectl").read_text()
        installer=(VPS/"install.sh").read_text()
        for url in (
            "https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM.git",
            "git@github.com:gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM.git",
            "git@github-spdecode-goku:gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM.git",
        ):
            self.assertIn(url,cli)
        self.assertIn("REPO_URL=\"https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM.git\"",installer)
        self.assertIn("REPO_URL=\"git@github-spdecode-goku:gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM.git\"",installer)
        self.assertIn('*) die "Untrusted repo" ;;',cli)

if __name__=="__main__":unittest.main()
