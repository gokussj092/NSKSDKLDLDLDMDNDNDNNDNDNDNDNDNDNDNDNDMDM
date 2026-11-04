import base64,importlib.util,subprocess,sys,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(HERE/'tools'))
from probe import classify_response,NoRedirect
from recover import b64
class ResearchChecks(unittest.TestCase):
    def test_independent_jdk_string_reference_on_pinned_build_literals(self):
        # Two actual non-secret literals from ARTunnelApp: AdMob TEST id and library name.
        text='5516027718822215041,-7420923530462964723,8888858397064566163,-3808918827315240971,7438972452715235316,-5089807994837897919\n3942504665332414875,-9217327079507985953\n'
        out=subprocess.run(['java',str(HERE/'tools/StringOracle.java')],input=text,text=True,capture_output=True,check=True)
        self.assertEqual([base64.b64decode(x).decode() for x in out.stdout.splitlines()],
            ['ca-app-pub-3940256099942544/9257395921','ovpn3'])
    def test_html_http200_is_not_a_catalog(self):
        self.assertEqual(classify_response(200,(HERE/'tests/fixtures/site-unavailable.html').read_bytes()),'HTML_NOT_CATALOG')
        self.assertEqual(classify_response(200,b' \n<html>denied</html>'),'HTML_NOT_CATALOG')
    def test_unknown_bytes_cannot_claim_verified_remote(self):
        self.assertEqual(classify_response(200,b'YWJjZA=='),'CIPHERTEXT_NOT_YET_VERIFIED')
        self.assertEqual(classify_response(200,b''),'EMPTY_RESPONSE')
        self.assertEqual(classify_response(403,b'bad'),'HTTP_FAILURE')
        self.assertEqual(classify_response(200,b'x'*(8*1024*1024+1)),'OVERSIZED_RESPONSE')
    def test_base64_rejects_invalid_alphabet(self):
        self.assertEqual(b64('Y W\nJjZA=='),'abcd'.encode())
        for x in ['bad!', '<html>', 'YWJjZA=']:
            with self.assertRaises(ValueError):b64(x)
    def test_redirect_is_not_an_authorized_alternate_source(self):
        with self.assertRaises(ValueError):NoRedirect().redirect_request(None,None,302,'',{},'https://example.org/')
if __name__=='__main__':unittest.main()
