"""Real adapters, negative cases and original-codec parity; no vendor network."""
import base64
import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cloud.workers.python.engine import decode_file, decode_text, decode_provider_catalog, DecodeFailure
from cloud.workers.python.supplied_bridge import BY_ID, ITEMS, FILE_ROUTES, load, catalog


class SuppliedIntegrationTests(unittest.TestCase):
    def test_inventory_has_all_owner_batches_and_loadable_offline_codecs(self):
        self.assertEqual(len(ITEMS), 57)
        for item in ITEMS:
            with self.subTest(provider=item["id"]):
                module = load(item)
                self.assertTrue(any(callable(getattr(module, name, None)) for name in
                                    ("decode", "decode_json_bytes", "decode_blob_text", "run")))
                if item["fileModule"]:
                    self.assertTrue((ROOT/"decoders/Python/apps"/item["appDir"]/item["fileModule"]).is_file())

    def test_native_argon2_matches_each_original_supplied_primitive(self):
        for provider in ("at-net-vpn", "jetroi", "marvs-ssh", "reg-tunnel", "rnv-tunnel-vpn", "shield-tunnel", "mm-tunnel"):
            with self.subTest(provider=provider):
                fn = load(BY_ID[provider])._argon2id
                arguments = (b"synthetic-password", b"synthetic-salt-16", 1, 8, 1, 32)
                self.assertEqual(fn(*arguments), fn.__wrapped__(*arguments))

    def test_complete_dtunnel_catalog_and_text_reach_isolated_worker(self):
        folder=ROOT/"decoders/Python/apps/DTunnel_Mod"
        result=decode_provider_catalog("dtunnel-mod",(folder/"catalog_sample.b64").read_bytes())
        expected=json.loads((folder/"catalog_sample.json").read_text())
        # A hash comparison prevents a failed assertion dumping private profile fields.
        import hashlib
        digest=lambda value:hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()
        self.assertEqual(digest(result["structuredJson"]),digest(expected))
        self.assertEqual(len(expected),49)
        doc={"name":"synthetic","server":"example.invalid","port":22}
        link="vpn://"+base64.b64encode(json.dumps(doc).encode()).decode()
        self.assertEqual(decode_text(link)["structuredJson"],doc)
        with self.assertRaises(DecodeFailure):decode_provider_catalog("dtunnel-mod",b"invalid")

    def test_supplied_file_and_text_twins_preserve_full_synthetic_documents(self):
        sample={"Version":"synthetic","Servers":[],"Networks":[],"extra":{"kept":True}}
        for provider,suffix,encoder,prefix in (
                ("binke-volt","bvv","encode_bvv","binkevoltvpn://"),
                ("zam-vip-net","zvn","encode_zvn","zamvipnet://")):
            with self.subTest(provider=provider):
                module=load(BY_ID[provider],"fileModule")
                encrypted=getattr(module,encoder)(sample)
                raw=encrypted.encode() if isinstance(encrypted,str) else encrypted
                self.assertEqual(decode_file(suffix,raw)["structuredJson"],sample)
                text=raw.decode()
                if not text.startswith(prefix):text=prefix+text
                self.assertEqual(decode_text(text)["structuredJson"],sample)

    def test_docnet_unresolved_payloads_are_explicitly_partial(self):
        raw=json.dumps([{"id":"synthetic","config":base64.b64encode(b"encrypted").decode()}]).encode()
        result=decode_provider_catalog("docnet-vpn",raw)
        self.assertTrue(result["isPartial"])
        self.assertEqual(result["warnings"],["ENCRYPTED_FIELDS_PENDING"])
        self.assertEqual(result["structuredJson"]["total"],1)

    def test_multisource_bundle_is_bound_to_provider_and_complete_source_set(self):
        for provider in ("edoz-tunnel-pro","sn-vpn","pnt-vpn","slow-dns"):
            with self.subTest(provider=provider):
                bad=json.dumps({"kind":"spdecode-supplied-catalog-v1","providerId":"other","sources":{}}).encode()
                with self.assertRaises(ValueError):catalog(provider,bad)
        with self.assertRaises(DecodeFailure):decode_provider_catalog("https://attacker.invalid/",b"x")

    def test_private_dtunnel_configuration_is_atomic_and_never_prints_values(self):
        path=ROOT/"cloud/infra/vps/catalog-auth.py"
        spec=importlib.util.spec_from_file_location("catalog_auth_test",path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/"credentials.json";env=Path(folder)/"cloud.env"
            env.write_text("OTHER_SETTING=preserved\n")
            source.write_text(json.dumps({"user_id":"synthetic-private-id"}))
            out=io.StringIO()
            with contextlib.redirect_stdout(out):module.configure(source,env)
            self.assertFalse(out.getvalue())
            self.assertIn("OTHER_SETTING=preserved",env.read_text())
            self.assertEqual(os.stat(env).st_mode&0o777,0o600)
            before=env.read_bytes();source.write_text(json.dumps({"user_id":"x\nINJECTED=yes"}))
            with self.assertRaises(ValueError):module.configure(source,env)
            self.assertEqual(env.read_bytes(),before)


if __name__=="__main__":
    unittest.main()
