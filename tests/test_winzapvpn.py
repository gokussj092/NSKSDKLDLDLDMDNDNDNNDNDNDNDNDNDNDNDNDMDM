"""HTTP WinzapVPN 1.1.61 cloud catalog: synthetic fixtures through the real worker.

The catalog uses the bootstrap route (``decoders/Python/apps/WinzapVPN/codec.py``):
plain HTTPS JSON, no envelope and no signature; the codec validates the
structure and redacts everything that is not catalog data (per-device
session, ads controls, notifications, asset URLs, per-server tokens).
Fixtures are built below with literal synthetic values (test.invalid);
no live catalog bytes, session values or decrypted credentials are
stored here.

The ``Winzap01`` blob (``encrypted_mobile_config`` of a server profile)
is AES-256-CBC over an EVP_BytesToKey-MD5 key/IV, with per-field
AES-256-CBC + ROT13 layer-3 fields; fixtures are built with the inverse
generators in ``codec`` (fixed salt/IV). The blob route is
VERIFIED_SYNTHETIC: no real blob has been supplied. The per-server
profile endpoint needs the app's HMAC signature, which is NOT
reproduced or forged, so no profile download is exercised here.
"""
import base64
import json
import subprocess
import sys
import unittest
from pathlib import Path

from decoders.Python.apps.WinzapVPN import codec
from decoders.Python.apps.WinzapVPN import server_catalog_decoder as catalog
from cloud.workers.python.engine import decode_provider_catalog

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = json.loads((ROOT / "tests/golden/winzapvpn_catalog_vectors.json").read_text())
GOLDEN_RAW = GOLDEN["catalog"].encode("utf-8")  # worker input is the raw bootstrap JSON
GOLDEN_EXPECTED = GOLDEN["expected"]


def build_catalog():
    """(raw bootstrap bytes, expected redacted document)."""
    raw = {
        "config_version": 1,
        "ads_enabled": True,
        "support_contact": "winzap-support",
        "session": {"device_id": "WINZAP-TEST0001", "time_balance_seconds": 1200,
                    "level": 1, "device_access_grant": None, "gift_grant": None,
                    "can_connect": True},
        "countries": [{
            "id": "c1", "name": "MÉXICO", "flag_emoji": "🇲🇽", "sort_order": 1,
            "is_active": True, "server_count": 2,
            "servers": [{
                "id": "11111111-1111-4111-8111-111111111111",
                "name": "Test Server MX 1", "country": "MÉXICO",
                "subtitle": "SSH Direct", "flag_emoji": "🇲🇽",
                "is_active": True, "is_vip_only": False,
                "available_access_count": 5, "online_users": 3,
                "latency_host": "test.invalid", "latency_port": 443,
                "ad_ip_host": "ad.test.invalid", "ad_ip_limit": 10,
                "ad_ip_remaining": 7, "ad_ip_used": 3,
                "change_token": "synthetic-token-must-be-stripped",
                "country_id": "c1", "owner_display_name": "synthetic-owner",
            }, {
                "id": "22222222-2222-4222-8222-222222222222",
                "name": "Test Server MX 2", "country": "MÉXICO",
                "subtitle": "V2Ray", "flag_emoji": "🇲🇽",
                "is_active": True, "is_vip_only": False,
                "available_access_count": 0, "online_users": 0,
                "latency_host": "test.invalid", "latency_port": 80,
            }],
        }, {
            "id": "c2", "name": "COLOMBIA", "flag_emoji": "🇨🇴", "sort_order": 2,
            "is_active": True, "server_count": 1,
            "servers": [{
                "id": "33333333-3333-4333-8333-333333333333",
                "name": "Test Server CO 1", "country": "COLOMBIA",
                "subtitle": "BHTTP", "flag_emoji": "🇨🇴",
                "is_active": False, "is_vip_only": True,
                "available_access_count": 2, "online_users": 1,
                "latency_host": "test.invalid", "latency_port": 8080,
            }],
        }],
        # Duplicated flat server list: dropped, like every non-catalog field.
        "servers": [{"id": "11111111-1111-4111-8111-111111111111",
                     "name": "Test Server MX 1"}],
        "global_notification": {"id": "n1", "title": "t", "message": "m",
                                "created_at": "2026-01-01T00:00:00Z"},
        "home_background": {"asset_url": "https://example.test/bg.png",
                            "mime_type": "image/png", "is_animated": False,
                            "opacity": 1, "fit_mode": "cover", "scale": 1,
                            "scale_x": 1, "scale_y": 1, "offset_x": 0,
                            "offset_y": 0,
                            "updated_at": "2026-01-01T00:00:00Z"},
        "device_banned": False, "device_ban_reason": "",
        "update_available": False, "latest_version": "1.1.61",
        "ad_controls": {"app_open": True, "app_open_always": False,
                        "connect_interstitial": True,
                        "disconnect_interstitial": False,
                        "server_change_interstitial": True,
                        "server_change_always": False,
                        "native_advanced": False, "home_banner": True},
    }
    expected = {
        "app": "HTTP WinzapVPN", "package": "com.winzap.winzap_vpn",
        "version": "1.1.61", "version_code": 76, "config_version": 1,
        "countries": [{
            "id": "c1", "name": "MÉXICO", "flag_emoji": "🇲🇽", "sort_order": 1,
            "is_active": True, "server_count": 2,
            "servers": [{
                "id": "11111111-1111-4111-8111-111111111111",
                "name": "Test Server MX 1", "country": "MÉXICO",
                "subtitle": "SSH Direct", "flag_emoji": "🇲🇽",
                "is_active": True, "is_vip_only": False,
                "available_access_count": 5, "online_users": 3,
                "latency_host": "test.invalid", "latency_port": 443,
            }, {
                "id": "22222222-2222-4222-8222-222222222222",
                "name": "Test Server MX 2", "country": "MÉXICO",
                "subtitle": "V2Ray", "flag_emoji": "🇲🇽",
                "is_active": True, "is_vip_only": False,
                "available_access_count": 0, "online_users": 0,
                "latency_host": "test.invalid", "latency_port": 80,
            }],
        }, {
            "id": "c2", "name": "COLOMBIA", "flag_emoji": "🇨🇴", "sort_order": 2,
            "is_active": True, "server_count": 1,
            "servers": [{
                "id": "33333333-3333-4333-8333-333333333333",
                "name": "Test Server CO 1", "country": "COLOMBIA",
                "subtitle": "BHTTP", "flag_emoji": "🇨🇴",
                "is_active": False, "is_vip_only": True,
                "available_access_count": 2, "online_users": 1,
                "latency_host": "test.invalid", "latency_port": 8080,
            }],
        }],
    }
    return json.dumps(raw).encode("utf-8"), expected


RAW, EXPECTED = build_catalog()

BLOB_FIELDS = {
    "na": "TEST SERVER", "si": "203.0.113.10", "sr": "8080",
    "py": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "sn": "example.com", "su": "usuario1", "sw": "clave-secreta",
    "pu": "proxyuser", "pw": "proxypass", "vj": '{"outbounds":[]}',
    "oc": "client\ndev tun\n",
    "d6": "true", "tt": "HTTP",
}
BLOB_EXPECTED = {codec.SHORT_TO_LONG.get(k, k): v for k, v in BLOB_FIELDS.items()}


def build_blob():
    """Deterministic synthetic Winzap01 blob (fixed salt/IV)."""
    enc = {}
    for k, v in BLOB_FIELDS.items():
        enc[k] = codec.encode_field(k, v, iv=b"\x01" * 16) if k in codec.LAYER3_FIELDS else v
    return codec.encode_winzap01_blob(enc, salt=b"\x00" * 8)


class WinzapVpnCatalogTests(unittest.TestCase):
    def test_synthetic_catalog_codec_cli_and_isolated_worker(self):
        self.assertEqual(json.loads(catalog.run(RAW)), EXPECTED)
        result = decode_provider_catalog("winzap-vpn", RAW)
        self.assertEqual(result["structuredJson"], EXPECTED)
        self.assertEqual(json.loads(result["rawText"]), EXPECTED)
        self.assertFalse(result["isPartial"])
        path = ROOT / "decoders/Python/apps/WinzapVPN/server_catalog_decoder.py"
        proc = subprocess.run(
            [sys.executable, str(path), "--stdin"], input=RAW,
            cwd="/tmp", capture_output=True, check=True)
        self.assertEqual(json.loads(proc.stdout), EXPECTED)

    def test_golden_vector_opens_through_codec(self):
        self.assertEqual(json.loads(catalog.run(GOLDEN_RAW)), GOLDEN_EXPECTED)

    def test_result_has_no_session_tokens_or_download_apis(self):
        rendered = catalog.run(RAW)
        for forbidden in ("vpnapi.winzapg.online", "device_id", "session",
                          "change_token", "ad_ip", "owner_display_name",
                          "asset_url", "support_contact", "ad_controls",
                          "global_notification", "home_background",
                          '"script":', "source_script", "privateKey",
                          "decoders/Python/"):
            self.assertNotIn(forbidden, rendered)
        doc = json.loads(rendered)
        self.assertEqual(sorted(doc.keys()), sorted(
            ["app", "package", "version", "version_code",
             "config_version", "countries"]))

    def test_winzap01_blob_round_trip_synthetic(self):
        blob = build_blob()
        self.assertEqual(codec.decode_winzap01_blob(blob), BLOB_EXPECTED)
        # Same blob twice: deterministic with fixed salt/IV.
        self.assertEqual(build_blob(), blob)
        # Invalid header.
        with self.assertRaises(ValueError):
            codec.decode_winzap01_blob(base64.b64encode(b"XXXXXXXX" + b"\x00" * 32).decode())
        # Body not a multiple of 16.
        raw = base64.b64decode(blob)
        with self.assertRaises(ValueError):
            codec.decode_winzap01_blob(base64.b64encode(raw + b"\x00").decode())
        # Corrupt layer-3 field: the app leaves it as-is and continues.
        tampered = dict(BLOB_FIELDS)
        tampered["sw"] = "not-valid-base64!!!"
        enc = {}
        for k, v in tampered.items():
            enc[k] = codec.encode_field(k, v, iv=b"\x01" * 16) if k in codec.LAYER3_FIELDS and k != "sw" else v
        dec = codec.decode_winzap01_blob(codec.encode_winzap01_blob(enc, salt=b"\x00" * 8))
        self.assertEqual(dec["ServerPass"], "not-valid-base64!!!")
        self.assertEqual(dec["ServerUser"], "usuario1")
        # ROT13 + KDF determinism.
        self.assertEqual(codec._rot13("AbcZz 123"), "NopMm 123")
        k1, iv1 = codec._evp_bytes_to_key_md5(b"pw", b"12345678")
        k2, iv2 = codec._evp_bytes_to_key_md5(b"pw", b"12345678")
        self.assertEqual((k1, iv1), (k2, iv2))
        self.assertEqual((len(k1), len(iv1)), (32, 16))

    def test_corruption_rejects_entire_catalog(self):
        no_version = dict(json.loads(RAW.decode("utf-8")))
        del no_version["config_version"]
        no_countries = dict(json.loads(RAW.decode("utf-8")))
        no_countries["countries"] = []
        no_servers = json.loads(RAW.decode("utf-8"))
        no_servers["countries"][0]["servers"] = []
        no_servers["countries"][1]["servers"] = []
        no_id = json.loads(RAW.decode("utf-8"))
        del no_id["countries"][0]["servers"][0]["id"]
        for invalid in (b"", b"<html/>", RAW[:-5],
                        json.dumps(no_version).encode("utf-8"),
                        json.dumps(no_countries).encode("utf-8"),
                        json.dumps(no_servers).encode("utf-8"),
                        json.dumps(no_id).encode("utf-8"),
                        b'{"config_version": 1, "config_version": 1, "countries": []}'):
            with self.subTest(length=len(invalid)):
                with self.assertRaises(codec.DecodeError):
                    catalog.run(invalid)


if __name__ == "__main__":
    unittest.main()
