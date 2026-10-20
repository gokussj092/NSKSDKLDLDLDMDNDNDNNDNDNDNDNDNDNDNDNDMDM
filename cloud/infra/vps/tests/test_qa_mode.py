"""Offline unit tests: QA session issuance never leaks plaintext to Redis or APK."""
import contextlib
import importlib.util
import io
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

SCRIPT=Path(__file__).resolve().parents[1]/"qa-test.py"
spec=importlib.util.spec_from_file_location("spdecode_qa_test",SCRIPT)
qa=importlib.util.module_from_spec(spec)
spec.loader.exec_module(qa)

class QATests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        root=Path(self.temp.name)
        self.env=root/"cloud.env"
        self.state=root/"qa-previous.json"
        self.env.write_text(
            "CLOUD_API_ENABLED=false\n"
            "CLOUD_FORCE_MAINTENANCE=true\n"
            "CLOUD_QA_ENABLED=false\n"
            "CLOUD_QA_EXPIRES_AT=0\n"
            "CLOUD_TRUST_PROXY=true\n"
            "CLOUD_SESSION_SIGNING_KEY="+"x"*48+"\n"
            "CLOUD_WORKER_TOKEN="+"w"*48+"\n"
            "CLOUD_ADMIN_USERNAME=realadmin\n")
        self.orig_env,self.orig_state,self.orig_nur_asset=qa.ENV,qa.STATE,qa.NUR_ASSET
        self.asset=root/"nur_tunnel_server_endpoint.json"
        self.asset.write_text('{"catalogUrl":"https://strongteam.co/api/catalog/vpn"}')
        qa.ENV,qa.STATE,qa.NUR_ASSET=self.env,self.state,self.asset
    def tearDown(self):
        qa.ENV,qa.STATE,qa.NUR_ASSET=self.orig_env,self.orig_state,self.orig_nur_asset
        self.temp.cleanup()
    def call(self,command):
        output=io.StringIO();calls=[]
        def composed(*args):
            calls.append(args)
            return None
        with patch.object(qa.os,"geteuid",return_value=0),\
             patch.object(qa.sys,"argv",["qa-test.py",command]),\
             patch.object(qa,"compose",side_effect=composed),\
             patch.object(qa,"health",return_value=True),\
             contextlib.redirect_stdout(output):
            qa.main()
        return output.getvalue(),calls
    def test_start_and_stop_restore_original_gates(self):
        out,calls=self.call("start")
        self.assertIn("QA ENABLED",out)
        match=re.search(r"QA CODE: (spqa-[A-Za-z0-9_-]{40,64})",out)
        self.assertIsNotNone(match)
        code=match.group(1)
        self.assertIn("CLOUD_QA_ENABLED=true",self.env.read_text())
        self.assertIn("CLOUD_FORCE_MAINTENANCE=false",self.env.read_text())
        self.assertIn("CLOUD_API_ENABLED=true",self.env.read_text())
        self.assertIn("CLOUD_NUR_FETCH_ENABLED=true",self.env.read_text())
        self.assertIn("CLOUD_SERVER_VPN_ENABLED=true",self.env.read_text())
        self.assertIn("CLOUD_SERVER_VPN_CATALOG_VERSION=12",self.env.read_text())
        self.assertIn("Additional Server VPN providers: ENABLED",out)
        self.assertIn("CLOUD_NUR_CATALOG_URL=https://strongteam.co/api/catalog/vpn",self.env.read_text())
        self.assertIn("NUR Server VPN: ENABLED",out)
        self.assertIn("HTTP Injector Cloud: NOT CONFIGURED",out)
        self.assertTrue(self.state.is_file())
        self.assertNotIn(code,self.env.read_text())
        self.assertNotIn(code,self.state.read_text())
        self.assertTrue(any("redis-cli" in call and "SET" in call for call in calls))
        self.assertFalse(any(code in str(call) for call in calls))
        out,_=self.call("stop")
        self.assertIn("QA stopped",out)
        self.assertIn("CLOUD_API_ENABLED=false",self.env.read_text())
        self.assertIn("CLOUD_FORCE_MAINTENANCE=true",self.env.read_text())
        self.assertIn("CLOUD_QA_ENABLED=false",self.env.read_text())
        self.assertIn("CLOUD_NUR_FETCH_ENABLED=",self.env.read_text())
        self.assertNotIn("CLOUD_NUR_FETCH_ENABLED=true",self.env.read_text())
        self.assertNotIn("CLOUD_SERVER_VPN_ENABLED=true",self.env.read_text())
        self.assertIn("CLOUD_SERVER_VPN_CATALOG_VERSION=13",self.env.read_text())
        self.assertNotIn("CLOUD_NUR_CATALOG_URL=https://strongteam.co",self.env.read_text())
        self.assertFalse(self.state.exists())
    def test_stop_without_prior_state_keeps_existing_server_gates(self):
        self.env.write_text(self.env.read_text().replace("CLOUD_API_ENABLED=false","CLOUD_API_ENABLED=true"))
        self.call("stop")
        self.assertIn("CLOUD_API_ENABLED=true",self.env.read_text())
        self.assertIn("CLOUD_FORCE_MAINTENANCE=true",self.env.read_text())
    def test_catalog_version_upgrade_keeps_existing_higher_versions(self):
        self.assertEqual(qa.next_catalog_version([]),"12")
        self.assertEqual(qa.next_catalog_version(["CLOUD_SERVER_VPN_CATALOG_VERSION=2"]),"12")
        self.assertEqual(qa.next_catalog_version(["CLOUD_SERVER_VPN_CATALOG_VERSION=3"]),"12")
        self.assertEqual(qa.next_catalog_version(["CLOUD_SERVER_VPN_CATALOG_VERSION=4"]),"12")
        self.assertEqual(qa.next_catalog_version(["CLOUD_SERVER_VPN_CATALOG_VERSION=5"]),"12")
        self.assertEqual(qa.next_catalog_version(["CLOUD_SERVER_VPN_CATALOG_VERSION=6"]),"12")
        self.assertEqual(qa.next_catalog_version(["CLOUD_SERVER_VPN_CATALOG_VERSION=7"]),"12")
        self.assertEqual(qa.next_catalog_version(["CLOUD_SERVER_VPN_CATALOG_VERSION=8"]),"12")
        self.assertEqual(qa.next_catalog_version(["CLOUD_SERVER_VPN_CATALOG_VERSION=9"]),"12")
        self.assertEqual(qa.next_catalog_version(["CLOUD_SERVER_VPN_CATALOG_VERSION=10"]),"12")
        self.assertEqual(qa.next_catalog_version(["CLOUD_SERVER_VPN_CATALOG_VERSION=11"]),"12")
        self.assertEqual(qa.next_catalog_version(["CLOUD_SERVER_VPN_CATALOG_VERSION=30"]),"31")
        for invalid in ("1","-1","abc","999999999"):
            with self.subTest(version=invalid),self.assertRaises(RuntimeError):
                qa.next_catalog_version(["CLOUD_SERVER_VPN_CATALOG_VERSION="+invalid])
    def test_enable_services_during_existing_qa_keeps_code_and_revokes_at_stop(self):
        # A QA session provisioned by an older CLI does not yet have provider state.
        self.asset.write_text('{"catalogUrl":"https://strongteam.co/allowed-path"}')
        output,_=self.call("start")
        code=output.split("QA CODE: ",1)[1].splitlines()[0]
        self.env.write_text(self.env.read_text()
            .replace("CLOUD_NUR_FETCH_ENABLED=true","CLOUD_NUR_FETCH_ENABLED=false"))
        output,calls=self.call("services")
        self.assertIn("NUR Server VPN: ENABLED",output)
        self.assertIn("Additional Server VPN providers: ENABLED",output)
        # The current flags were deliberately changed before services was called.
        self.assertIn("CLOUD_SERVER_VPN_CATALOG_VERSION=13",self.env.read_text())
        self.assertNotIn(code,output)
        self.assertTrue(any("web" in call for call in calls))
        self.call("stop")
        self.assertIn("CLOUD_NUR_FETCH_ENABLED=",self.env.read_text())
    def test_optional_ehi_enabled_only_with_valid_keys(self):
        self.env.write_text(self.env.read_text()+
            "CLOUD_EHI_SIGN_KEY="+"S"*32+"\n"+
            "CLOUD_EHI_RESPONSE_KEY="+"R"*32+"\n")
        output,_=self.call("start")
        self.assertIn("HTTP Injector Cloud: ENABLED",output)
        self.assertIn("CLOUD_EHI_IMPORT_ENABLED=true",self.env.read_text())
        self.call("stop")
        self.assertNotIn("CLOUD_EHI_IMPORT_ENABLED=true",self.env.read_text())
    def test_invalid_nur_asset_never_opens_qa(self):
        for url in ("http://strongteam.co/catalog","https://other.example/catalog",
                    "https://strongteam.co/catalog?token=bad",
                    "https://strongteam.co:443/catalog"):
            with self.subTest(url=url):
                self.asset.write_text('{"catalogUrl":'+__import__("json").dumps(url)+'}')
                with self.assertRaises(RuntimeError):
                    self.call("start")
                self.assertNotIn("CLOUD_API_ENABLED=true",self.env.read_text())
                self.assertFalse(self.state.exists())
    def test_nur_host_python_probe_exposes_only_status(self):
        class Response:
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def read(self,amount):
                self_amount=amount
                assert self_amount==1
                return b"x"
        class Opener:
            def open(self,request,timeout):
                self.assertEqual(request.headers["User-agent"],"NUR TUNNEL VPN")
                self.assertEqual(timeout,10)
                return Response()
        opener=Opener()
        opener.assertEqual=self.assertEqual
        with patch.object(qa,"permitted_catalog",return_value="https://strongteam.co/approved"),\
             patch("urllib.request.build_opener",return_value=opener),\
             contextlib.redirect_stdout(io.StringIO()) as output:
            qa.probe_nur_host_python()
        result=output.getvalue()
        self.assertIn('"stage": "host_python"',result)
        self.assertIn('"code": "HTTP_200"',result)
        self.assertNotIn("strongteam.co",result)
    def test_nur_diagnostic_denied_outside_qa(self):
        with self.assertRaises(SystemExit):
            self.call("probe-nur")
    def test_nur_diagnostic_calls_isolated_web_without_secret_output(self):
        output,_=self.call("start")
        code=output.split("QA CODE: ",1)[1].splitlines()[0]
        captured=[]
        def fake_compose(*args):
            captured.append(args)
            return type("Result",(),{"stdout":'{"stage":"download","status":"failed","code":"REMOTE_PROVIDER_UNAVAILABLE"}\n'})()
        with patch.object(qa.os,"geteuid",return_value=0),\
             patch.object(qa.sys,"argv",["qa-test.py","probe-nur"]),\
             patch.object(qa,"compose",side_effect=fake_compose),\
             contextlib.redirect_stdout(io.StringIO()) as stream:
            qa.main()
        self.assertIn('"stage":"download"',stream.getvalue())
        self.assertNotIn(code,stream.getvalue())
        self.assertEqual(captured[0][:4],("exec","-T","web","node"))
        self.assertNotIn("CLOUD_SESSION_SIGNING_KEY",str(captured[0]))
        self.assertNotIn("CLOUD_NUR_CATALOG_URL",str(captured[0]))
    def test_qa_code_never_printed_by_status(self):
        out,_=self.call("start")
        code=out.split("QA CODE: ",1)[1].splitlines()[0]
        status,_=self.call("status")
        self.assertIn("QA active: True",status)
        self.assertNotIn(code,status)

if __name__=="__main__":unittest.main()
