"""Unit and mocked deployment tests for noninteractive admin reset."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SCRIPT=Path(__file__).resolve().parents[1]/"panel-reset.py"
spec=importlib.util.spec_from_file_location("spdecode_panel_reset",SCRIPT)
reset=importlib.util.module_from_spec(spec)
spec.loader.exec_module(reset)

class PanelResetTests(unittest.TestCase):
    def test_credentials_match_nextjs_scrypt_contract(self):
        username,password,digest,key=reset.fresh_account()
        self.assertRegex(username,r"^[a-zA-Z][a-zA-Z0-9._-]{2,63}$")
        self.assertGreaterEqual(len(password),16)
        self.assertEqual(len(key),64)
        algo,n,r,p,salt,hash_hex=digest.split("$")
        self.assertEqual((algo,n,r,p),("scrypt","16384","8","1"))
        actual=hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt),
                              n=16384,r=8,p=1,dklen=64,maxmem=32*1024*1024)
        self.assertEqual(actual.hex(),hash_hex)

    def test_env_replaces_old_admin_but_preserves_other_secrets(self):
        before=(b"CLOUD_WORKER_TOKEN=still-private\nCLOUD_ADMIN_USERNAME=oldadmin\n"
                b"CLOUD_ADMIN_PASSWORD_SCRYPT='oldhash'\nCLOUD_ADMIN_ENABLED=false\n")
        changed=reset.replace_env(before,{
            "CLOUD_ADMIN_USERNAME":"admin_new",
            "CLOUD_ADMIN_PASSWORD_SCRYPT":"'newhash'",
            "CLOUD_ADMIN_ENABLED":"true",
        }).decode()
        self.assertIn("CLOUD_WORKER_TOKEN=still-private",changed)
        self.assertNotIn("oldadmin",changed)
        self.assertNotIn("oldhash",changed)
        self.assertEqual(changed.count("CLOUD_ADMIN_ENABLED="),1)

    def test_validate_login_checks_actual_authenticated_cookie(self):
        observed=[]
        def fake_status(panel,path,*,body=None,cookies=None,save_cookies=False):
            observed.append((path,body,bool(cookies),save_cookies))
            return {"/admin/login":"200","/api/admin/login":"200",
                    "/api/admin/session":"200" if cookies else "401"}[path]
        with mock.patch.object(reset,"https_status",side_effect=fake_status):
            reset.validate_login("panel.spdecode.xyz","admin_test","password_for_testing_123")
        self.assertEqual([entry[0] for entry in observed],
            ["/admin/login","/api/admin/session","/api/admin/login","/api/admin/session"])
        self.assertEqual(observed[2][1],{
            "username":"admin_test","password":"password_for_testing_123"})
        self.assertTrue(observed[2][3])
        self.assertTrue(observed[3][2])

    def test_login_rejects_missing_session_cookie(self):
        with mock.patch.object(reset,"https_status",side_effect=["200","401","200","401"]):
            with self.assertRaisesRegex(reset.ResetError,"authenticated session is invalid"):
                reset.validate_login("panel.spdecode.xyz","admin_test","password_for_testing_123")

    def test_password_in_stdin_not_subprocess_arguments(self):
        calls=[]
        def fake_run(args,**kwargs):
            calls.append((args,kwargs))
            return mock.Mock(returncode=0,stdout="200")
        secret="only-in-stdin-password-123456"
        with mock.patch.object(reset.subprocess,"run",side_effect=fake_run):
            reset.https_status("panel.spdecode.xyz","/api/admin/login",
                body={"username":"admin_test","password":secret})
        argv,kwargs=calls[0]
        self.assertNotIn(secret," ".join(argv))
        self.assertIn(secret,kwargs["input"])
        self.assertIn("--data-binary",argv)
        self.assertIn("@-",argv)
        self.assertIn("--resolve",argv)
        self.assertNotIn("--insecure",argv)

    def test_reset_prints_only_after_real_login_and_restores_on_failure(self):
        for fail_login in (False,True):
            with self.subTest(fail_login=fail_login):
                with tempfile.TemporaryDirectory() as temp:
                    root=Path(temp)
                    cfg=root/"etc";cfg.mkdir()
                    repo=root/"repo";(repo/"cloud/infra/vps").mkdir(parents=True)
                    (repo/"cloud/compose.yaml").write_text("services: {}\n")
                    env=cfg/"cloud.env"
                    before=b"CLOUD_ADMIN_USERNAME=oldadmin\nCLOUD_WORKER_TOKEN=keep\n"
                    env.write_bytes(before)
                    env.chmod(0o600)
                    for name,value in [("domain","spdecode.xyz"),
                            ("api-domain","api.spdecode.xyz"),
                            ("panel-domain","panel.spdecode.xyz")]:
                        (cfg/name).write_text(value)
                    nginx=root/"spdecode.conf";nginx.write_bytes(b"old nginx conf\n")
                    def fake_invoke(args,*,input_text=None):
                        if args[0]=="python3":
                            return "generated nginx config\n"
                        if args[0]=="curl":
                            return "200"
                        return ""
                    out=io.StringIO()
                    patchers=[
                        mock.patch.object(reset,"CFG",cfg),
                        mock.patch.object(reset,"ENV",env),
                        mock.patch.object(reset,"REPO",repo),
                        mock.patch.object(reset,"NGINX",nginx),
                        mock.patch.object(reset.os,"geteuid",return_value=0),
                        mock.patch.object(reset,"invoke",side_effect=fake_invoke),
                        mock.patch.object(reset,"compose",return_value=""),
                        mock.patch.object(reset,"validate_login",
                            side_effect=reset.ResetError("wrong session") if fail_login else None),
                    ]
                    with contextlib.ExitStack() as stack:
                        for patcher in patchers:
                            stack.enter_context(patcher)
                        with contextlib.redirect_stdout(out):
                            if fail_login:
                                with self.assertRaises(reset.ResetError):
                                    reset.reset_admin()
                            else:
                                reset.reset_admin()
                    if fail_login:
                        self.assertEqual(env.read_bytes(),before)
                        self.assertEqual(nginx.read_bytes(),b"old nginx conf\n")
                        self.assertNotIn("CONTRASEÑA:",out.getvalue())
                    else:
                        self.assertNotIn(b"oldadmin",env.read_bytes())
                        self.assertIn(b"CLOUD_WORKER_TOKEN=keep",env.read_bytes())
                        self.assertIn(b"CLOUD_ADMIN_ENABLED=true",env.read_bytes())
                        self.assertIn(b"CLOUD_ADMIN_PUBLIC_ORIGIN=https://panel.spdecode.xyz",env.read_bytes())
                        self.assertIn("USUARIO:",out.getvalue())
                        self.assertIn("CONTRASEÑA:",out.getvalue())
                        self.assertEqual(env.stat().st_mode & 0o777,0o600)

if __name__=="__main__":
    unittest.main()
