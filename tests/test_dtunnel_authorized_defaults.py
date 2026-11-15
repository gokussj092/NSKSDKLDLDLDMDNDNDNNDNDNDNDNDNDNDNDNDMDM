"""Authorized defaults, fixed-origin boundaries and standalone CLI behavior."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch
from decoders.Python.apps.DTunnel_Mod import DTunnel as codec


class DTunnelAuthorizedDefaultTests(unittest.TestCase):
    def test_cli_url_uses_authorized_default_without_credentials_file(self):
        sample=[{"name":"synthetic"}]
        with patch.object(codec,"fetch_catalog",return_value=b"synthetic") as fetch, \
             patch.object(codec,"decode_catalog",return_value=sample), \
             contextlib.redirect_stdout(io.StringIO()) as out,contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(codec.main(["--url"]),0)
        self.assertTrue(fetch.call_args.args[1]==codec.DEFAULT_REQUEST_ID)
        self.assertEqual(json.loads(out.getvalue()),sample)
        self.assertFalse(codec.DEFAULT_REQUEST_ID in out.getvalue())

    def test_default_identity_never_goes_to_another_endpoint(self):
        for url in ["https://example.invalid/api/dtunnelmod",codec.CATALOG_URL+"?forward=1"]:
            with self.subTest(endpoint=url),patch.object(codec,"build_opener") as opener:
                with self.assertRaises(codec.DecodeError):codec.fetch_catalog(url)
                opener.assert_not_called()

    def test_explicit_request_ids_remain_supported(self):
        with patch.object(codec,"fetch_catalog",return_value=b"synthetic") as fetch, \
             patch.object(codec,"decode_catalog",return_value=[]), \
             patch.object(codec,"_read",return_value=b"synthetic-override"), \
             contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(codec.main(["--url","--request-id-file","/private/id"]),0)
        self.assertEqual(fetch.call_args.args[1],"synthetic-override")


if __name__=="__main__":unittest.main()
