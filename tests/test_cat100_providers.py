"""CAT 100 integration: the 13 apps' new/updated decoders, fixture-based.

Synthetic round-trips only: each script's own encrypt helper builds the
input, so no real catalog, credential or live body is stored in the repo.
The live re-runs (same versions, same counts) are verified separately by
the coordinator against the stored live samples; this suite proves the
wiring (broker bridge -> adapter -> decoder, C8 engine, supplied bridge,
text bridge, gateway partial handling) with synthetic data.
"""
import base64
import hashlib
import json
import os
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "cloud/workers/python"))

from engine import DecodeFailure, decode_file, decode_provider_catalog, load_runtime_file_engines  # noqa: E402
from decoders.Python.apps.MSY_VPN import server_catalog_decoder as msy_adapter  # noqa: E402
from decoders.Python.apps.MSY_VPN import msyvpn  # noqa: E402
from decoders.Python.apps.AlsaherFree import alsaherfree  # noqa: E402
from decoders.Python.apps.PulseTunnel import server_catalog_decoder as pulse_adapter  # noqa: E402
from decoders.Python.apps.PulseTunnel import pulsetunnel  # noqa: E402
from decoders.Python.apps.IrfanVPN import server_catalog_decoder as irfan_adapter  # noqa: E402
from decoders.Python.apps.IrfanVPN import irfanvpn  # noqa: E402
from decoders.Python.apps.KatibaVPN import server_catalog_decoder as katiba_adapter  # noqa: E402
from decoders.Python.apps.KatibaVPN import katiba  # noqa: E402
from decoders.Python.apps.DTunnel_VPN import server_catalog_decoder as dtunnel_adapter  # noqa: E402
from decoders.Python.apps.Tx_Tunnel import server_catalog_decoder as tx_adapter  # noqa: E402
from decoders.Python.apps.Tx_Tunnel import txtunnel  # noqa: E402
from decoders.Python.apps.AR_PRO_VPN import arpro  # noqa: E402
from cloud.workers.python import supplied_bridge, text_bridge  # noqa: E402

GOLDEN = ROOT / "tests/golden/cat100"


def _synthetic_server(name):
    return {"Name": name, "ServerIPHost": "10.0.0.1", "ServerPort": "443"}


def _synthetic_network(name):
    return {"Name": name, "Payload": "CONNECT example.org:443 HTTP/1.1",
            "SNI": "example.org", "TunnelType": 3}


class Cat100Providers(unittest.TestCase):
    def test_registry_counts_and_names(self):
        extended = load_runtime_file_engines()
        self.assertEqual(len(extended), 298)
        for suffix in ("pulse", "irfan", "katiba", "txtunnel", "nad"):
            self.assertIn(suffix, extended)
            self.assertEqual(extended[suffix]["phase"], "C8")
        self.assertEqual(extended["ar"]["name"], "AR PRO VPN 2.0")
        self.assertEqual(extended["mehaf"]["name"], "Mehaf VPN 1.0.9.20")
        self.assertEqual(extended["nad"]["name"], "NadiaVPN 1.4.6")

    def test_msy_catalog_roundtrip(self):
        # Raw catalog shape: obfuscated keys (v_k7/s_nd/c_mx) and raw
        # server/config records (x_*/z_*); parse_catalog maps them to
        # the catalog shape.
        doc = {"v_k7": 64, "a_v3": "11.4.1", "a_vn": "11.4.1",
               "a_ur": "https://example.invalid/", "a_mg": "synthetic",
               "s_nd": [{"x_i": "srv-1", "x_n": "Synthetic-1",
                         "x_h": "example.org", "x_a": "10.0.0.1"}],
               "c_mx": [{"z_i": "cfg-1", "z_t": "tls",
                         "z_b": "CONNECT example.org:443 HTTP/1.1"}]}
        body = msyvpn.encrypt_blob(json.dumps(doc))
        out = decode_provider_catalog("msy-vpn", body)
        self.assertEqual(out["status"], "success")
        self.assertEqual(out["structuredJson"]["catalog_version"], 64)
        self.assertEqual(len(out["structuredJson"]["servers"]), 1)
        self.assertEqual(out["structuredJson"]["servers"][0]["name"], "Synthetic-1")
        # The adapter itself returns the same document.
        self.assertEqual(json.loads(msy_adapter.run(body)), out["structuredJson"])

    def test_alsaherfree_catalog_plain_json(self):
        doc = {"Version": "9.9.72",
               "Servers": [{"Name": "Synthetic", "HTTPNetworks": [], "SSLNetworks": []}],
               "HTTPNetworks": [], "SSLNetworks": []}
        out = decode_provider_catalog("alsaherfree", json.dumps(doc).encode())
        self.assertEqual(out["status"], "success")
        self.assertEqual(out["structuredJson"]["Version"], "9.9.72")
        self.assertEqual(out["structuredJson"]["Servers"][0]["Name"], "Synthetic")

    def test_pulse_file_synthetic(self):
        raw = (GOLDEN / "synthetic-test.pulse").read_bytes()
        out = decode_file("pulse", raw)["structuredJson"]
        self.assertEqual(out["Networks"][0]["Name"], "Synthetic Test")
        self.assertFalse(out["passworded"])

    def test_pulse_file_passworded_roundtrip(self):
        networks = json.loads((GOLDEN / "synthetic-test.json").read_text())["Networks"]
        wire = pulsetunnel.encode_pulse(networks, password="test123")
        with self.assertRaises(DecodeFailure):
            decode_file("pulse", wire.encode())
        out = decode_file("pulse", wire.encode(), credentials={"password": "test123"})["structuredJson"]
        self.assertEqual(out["Networks"][0]["Name"], "Synthetic Test")

    def test_pulse_catalog_adapter_rejects_bad_blobs(self):
        with self.assertRaises(ValueError):
            pulse_adapter.decode_catalog(b"")
        with self.assertRaises(ValueError):
            pulse_adapter.decode_catalog(b"not-an-s1-blob")
        # A well-formed S1. frame with a random signature fails closed.
        fake = "S1." + base64.b64encode(os.urandom(32)).decode() + ".AAAA"
        with self.assertRaises(ValueError):
            pulse_adapter.decode_catalog(fake.encode())

    def test_irfan_catalog_roundtrip(self):
        doc = {"Version": "2.8",
               "Servers": [_synthetic_server("Synthetic-1")],
               "Networks": [_synthetic_network("Net-1")]}
        text = irfanvpn.encrypt_blob(json.dumps(doc).encode(), irfanvpn.PASSWORD_II)
        out = decode_provider_catalog("irfan-vpn", text.encode())
        self.assertEqual(out["status"], "success")
        self.assertEqual(out["structuredJson"]["Version"], "2.8")
        self.assertEqual(out["structuredJson"]["Servers"][0]["Name"], "Synthetic-1")
        self.assertEqual(out["structuredJson"]["Networks"][0]["Name"], "Net-1")

    def test_irfan_file_roundtrip(self):
        network = {"NetworkList": [_synthetic_network("Net-1")]}
        text = irfanvpn.encrypt_irfan(network)
        out = decode_file("irfan", text.encode())["structuredJson"]
        self.assertEqual(out["NetworkList"][0]["Name"], "Net-1")

    def test_katiba_catalog_roundtrip(self):
        doc = {"Version": "1.12",
               "Servers": [_synthetic_server("Synthetic-1")],
               "Networks": [_synthetic_network("Net-1")]}
        text = katiba.encrypt_catalog(json.dumps(doc))
        out = decode_provider_catalog("katiba-vpn", text.encode())
        self.assertEqual(out["status"], "success")
        self.assertNotIn("decryptionStatus", out["structuredJson"])
        self.assertEqual(len(out["structuredJson"]["Servers"]), 1)

    def test_katiba_catalog_partial_is_honest(self):
        # A network field that looks encrypted but opens with no key in
        # the APK: kept verbatim, reported with locations only (never the
        # raw value) so the engine/gateway can mark the catalog partial.
        garbage = base64.b64encode(os.urandom(44)).decode()
        doc = {"Version": "1.12", "Servers": [],
               "Networks": [dict(_synthetic_network("Net-1"), Payload=garbage)]}
        text = katiba.encrypt_catalog(json.dumps(doc))
        out = decode_provider_catalog("katiba-vpn", text.encode())
        self.assertTrue(out["isPartial"])
        self.assertEqual(out["warnings"], ["ENCRYPTED_FIELDS_PENDING"])
        status = out["structuredJson"]["decryptionStatus"]
        self.assertFalse(status["complete"])
        self.assertEqual(status["unresolvedFields"], 1)
        self.assertEqual(status["locations"], ["Networks[0].Payload"])
        self.assertNotIn(garbage, json.dumps(status))

    def test_katiba_file_roundtrip(self):
        doc = {"Name": "Synthetic-1", "TunnelType": 3}
        text = katiba.encrypt_file(json.dumps(doc))
        out = decode_file("katiba", text.encode())["structuredJson"]
        self.assertEqual(out["Name"], "Synthetic-1")

    def test_dtunnel_synthetic_envelope(self):
        # Same envelope layout as the live `data` string (int32 length +
        # base64 key material + base64 GCM blob), built with a synthetic
        # key and two synthetic profiles — no real catalog is involved.
        profiles = [{"name": "Synthetic A", "mode": "DTUNNEL"},
                    {"name": "Synthetic B", "mode": "DTUNNEL"}]
        key_material = os.urandom(16)
        key = hashlib.sha256(key_material).digest()
        nonce = os.urandom(12)
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(json.dumps(profiles).encode())
        blob = nonce + tag + ct
        key_b64 = base64.b64encode(key_material)
        outer = struct.pack(">I", len(key_b64)) + key_b64 + base64.b64encode(blob)
        data = base64.b64encode(outer)
        out = decode_provider_catalog("dtunnel-vpn", data)
        self.assertEqual(out["status"], "success")
        self.assertEqual(len(out["structuredJson"]), 2)
        self.assertEqual(out["structuredJson"][0]["name"], "Synthetic A")
        self.assertEqual(json.loads(dtunnel_adapter.run(data)), profiles)

    def test_tx_catalog_roundtrip(self):
        doc = {"Version": "66.87",
               "Servers": [_synthetic_server("Synthetic-1")],
               "Networks": [_synthetic_network("Net-1")]}
        text = txtunnel.encrypt_live(json.dumps(doc).encode())
        out = decode_provider_catalog("tx-tunnel", text.encode())
        self.assertEqual(out["status"], "success")
        self.assertEqual(out["structuredJson"]["Version"], "66.87")
        self.assertEqual(len(out["structuredJson"]["Networks"]), 1)

    def test_tx_file_roundtrip(self):
        network = {"Name": "Synthetic-1", "TunnelType": 3}
        text = txtunnel.export_txtunnel(network)
        out = decode_file("txtunnel", text.encode())["structuredJson"]
        self.assertEqual(out["Name"], "Synthetic-1")

    def test_tx_v2rayng_link(self):
        config = {"v": "2", "ps": "Synthetic", "add": "example.org",
                  "port": "443", "id": "00000000-0000-4000-8000-000000000000",
                  "aid": "0", "net": "tcp", "type": "none", "host": "",
                  "path": "", "tls": "tls"}
        vmess = "vmess://" + base64.urlsafe_b64encode(
            json.dumps(config).encode()).decode().rstrip("=")
        import urllib.parse
        link = "v2rayng://install-config?url=" + urllib.parse.quote(vmess, safe="")
        out = json.loads(text_bridge.dispatch(link))
        self.assertEqual(out["kind"], "vmess")
        self.assertEqual(out["config"]["ps"], "Synthetic")

    def test_arpro_file_roundtrip(self):
        profile = {"Name": "Synthetic-1", "TunnelType": 3,
                   "ServerHost": "example.org", "ServerPort": "443"}
        text = arpro.encode_ar(profile)
        out = decode_file("ar", text.encode())["structuredJson"]
        self.assertEqual(out["Name"], "Synthetic-1")

    def test_arpro_catalog_branch(self):
        doc = {"Version": "3.4.9",
               "Servers": [_synthetic_server("Synthetic-1")], "Tweaks": []}
        body = base64.b64encode(arpro.mode_encrypt(5, json.dumps(doc).encode()))
        item = supplied_bridge.BY_ID["ar-pro-vpn"]
        out = supplied_bridge.decode_one(item, body)
        self.assertEqual(out["Version"], "3.4.9")
        self.assertEqual(out["Servers"][0]["Name"], "Synthetic-1")

    def test_mehaf_vless_link_and_json(self):
        link = b"vless://00000000-0000-4000-8000-000000000000@example.org:443?security=tls#Synthetic"
        out = decode_file("mehaf", link)["structuredJson"]
        self.assertEqual(out["protocol"], "vless://")
        self.assertEqual(out["address"], "example.org")
        self.assertEqual(out["port"], 443)
        self.assertEqual(out["name"], "Synthetic")
        doc = {"Name": "Synthetic-1", "TunnelType": 3}
        out = decode_file("mehaf", json.dumps(doc).encode())["structuredJson"]
        self.assertEqual(out["Name"], "Synthetic-1")

    def test_darktunnel_synthetic_link(self):
        from decoders.Python import DARKTUNNEL
        link = (GOLDEN / "darktunnel-synthetic-link.txt").read_text().strip()
        out = DARKTUNNEL.run(link.encode())
        self.assertIsNotNone(out)
        self.assertIn("vless.example.org", out)
        self.assertIn("synthetic-30dayz", out)


if __name__ == "__main__":
    unittest.main()
