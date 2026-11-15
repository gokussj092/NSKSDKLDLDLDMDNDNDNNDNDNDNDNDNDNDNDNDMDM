"""One transient retry, fixed endpoint/installation and mandatory policy gate."""
import io,unittest
from pathlib import Path
from urllib.error import HTTPError
from unittest.mock import patch
from decoders.Python.apps.CATNET_VPN import server_catalog_decoder as cli
FIX=Path(__file__).resolve().parents[1]/'analysis/net.catnet.vpn/27/tests/fixtures'
class Reply:
    status=200;headers={}
    def __init__(self,data):self.data=data
    def __enter__(self):return self
    def __exit__(self,*a):pass
    def read(self,n):return self.data[:n]
class CatnetRetryTests(unittest.TestCase):
    def invoke(self,answers):
        self.calls=[]
        class Opener:
            def open(_,request,timeout):
                self.assertTrue(0<timeout<=30);self.calls.append(request);answer=answers[len(self.calls)-1]
                if isinstance(answer,Exception):raise answer
                return Reply(answer)
        with patch.object(cli,'build_opener',return_value=Opener()):return cli.download()
    def error(self,n):return HTTPError(cli.PREFLIGHT,n,'',{},io.BytesIO(b'private'))
    def test_transient_503_reuses_installation_then_fetches_complete_servers(self):
        data=(FIX/'servers.json').read_bytes();self.assertEqual(self.invoke([self.error(503),(FIX/'preflight.json').read_bytes(),data]),data)
        self.assertEqual([r.full_url for r in self.calls],[cli.PREFLIGHT,cli.PREFLIGHT,cli.SOURCE])
        self.assertEqual(len({r.get_header('X-xj-installation-id') for r in self.calls}),1)
    def test_persistent_outage_stops_after_two_requests(self):
        with self.assertRaises(ValueError):self.invoke([self.error(503),self.error(503)])
        self.assertEqual(len(self.calls),2)
    def test_authorization_and_rate_limits_do_not_retry(self):
        for n in [401,403,429]:
            with self.subTest(status=n),self.assertRaises(ValueError):self.invoke([self.error(n)])
            self.assertEqual(len(self.calls),1)
if __name__=='__main__':unittest.main()
