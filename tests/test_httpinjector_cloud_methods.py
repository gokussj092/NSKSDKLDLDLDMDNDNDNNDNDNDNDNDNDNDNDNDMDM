"""Offline verification of the author's uploaded HTTP Injector Cloud/emoji methods."""
from __future__ import annotations

import base64
import hashlib
import unittest

from decoders.Python import HTTPINJECTOR_CLOUD as cloud
from decoders.Python import HTTPINJECTOR_EMOJI as emoji


class HttpInjectorCloudMethodsTest(unittest.TestCase):
    def test_exact_method_constants_match_existing_cloud_broker(self):
        self.assertEqual(cloud.ENDPOINT, "https://www.ehi.tools/httpinjector/import_config")
        self.assertEqual(cloud.APP_BUILD, "244")
        self.assertEqual(hashlib.sha256(cloud.SIGN_SECRET.encode()).hexdigest(),
                         "1ed7b6c1537ab20dca655f7f69f6c5debfe38912e1fe9899da3a0cb127da1ee8")
        self.assertEqual(hashlib.sha256(cloud.API_KEY).hexdigest(),
                         "9e5e8ad1459ccfc0ba87811a2153e4e7bce0e88e81bfec0972bf45e33b9a5789")

    def test_fixed_request_signature_matches_production_broker_vector(self):
        body, headers = cloud.build_request(
            "TEST1234", timestamp=1700000000,
            nonce="00000000-0000-4000-8000-000000000000",
            identity="identity-synthetic",
        )
        self.assertEqual(body, b"config_key=TEST1234")
        self.assertEqual(headers["x-app-build"], "244")
        self.assertEqual(headers["x-signature"], "03p7UQBNZXTELXW82PMwoNeyta0%3D")

    def test_cloud_reference_and_emoji_share_identical_key(self):
        key = "TEST1234"
        token = emoji.encode_emoji_key(key)
        self.assertTrue(token.startswith("💉") and token.endswith("🚀"))
        self.assertEqual(emoji.decode_emoji_key(token), key)
        self.assertEqual(cloud.parse_reference("https://ehi.link/" + key), key)
        self.assertEqual(cloud.parse_reference("ehi://ehi.link/" + key), key)
        with self.assertRaises(cloud.CloudError):
            cloud.parse_reference("http://127.0.0.1/TEST1234")
        with self.assertRaises(emoji.EmojiError):
            emoji.decode_emoji_key("💉INCOMPLETE🚀")

    def test_no_download_or_unsafe_response_without_valid_authentication(self):
        with self.assertRaises(cloud.CloudError):
            cloud.decode_response({"code": 401})
        with self.assertRaises(cloud.CloudError):
            cloud.decrypt_api_response({"code": 200, "data": base64.b64encode(b"bad").decode()})


if __name__ == "__main__":
    unittest.main()
