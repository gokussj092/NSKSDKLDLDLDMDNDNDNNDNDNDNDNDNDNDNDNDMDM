"""Tests del metodo DGM Tunnel 15.11.2026 (build 17).

Vectores SINTETICOS; ningun secreto real, ningun servidor real,
ninguna red. El feed sintetico usa direcciones TEST-NET y hosts
example.com/.org. El share de prueba usa una contrasena de prueba.
"""
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import dgm_tunnel as dgm

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return fh.read()


class TestFeedParsing(unittest.TestCase):
    def test_positive_feed_sample(self):
        profiles, errors = dgm.parse_text(load_fixture("synthetic_feed.txt"))
        self.assertEqual(len(profiles), 4)
        self.assertEqual(len(errors), 1)
        self.assertIn("reality", errors[0].lower())
        self.assertEqual([p["config"]["protocol"] for p in profiles],
                         ["SHADOWSOCKS", "VLESS", "TROJAN", "VMESS"])

    def test_positive_catalog_filter(self):
        profiles, _ = dgm.parse_text(load_fixture("synthetic_feed.txt"))
        catalog = dgm.apply_free_server_catalog(profiles)
        self.assertEqual([p["id"] for p in catalog],
                         ["public-0", "public-1", "public-2", "public-3"])
        self.assertTrue(all(p["config"]["protocol"] == "SHADOWSOCKS"
                            for p in catalog[:1]))

    def test_positive_profile_json(self):
        doc = json.loads(load_fixture("synthetic_profile.json"))
        profiles, errors = dgm.parse_text(json.dumps(doc))
        self.assertEqual(len(profiles), 1)
        self.assertFalse(errors)
        self.assertEqual(profiles[0]["config"]["server"], "example.com")


class TestShare(unittest.TestCase):
    def test_positive_share_roundtrip(self):
        profiles, _ = dgm.parse_text(load_fixture("synthetic_feed.txt"))
        cfg = profiles[1]["config"]
        env = dgm.seal_share(cfg, "test-password-123",
                             expires_at=int(time.time() * 1000) + 3600000)
        opened, _meta = dgm.open_share(env, "test-password-123")
        self.assertEqual(opened["server"], cfg["server"])
        self.assertEqual(opened["uuid"], cfg["uuid"])

    def test_negative_wrong_password(self):
        profiles, _ = dgm.parse_text(load_fixture("synthetic_feed.txt"))
        cfg = profiles[1]["config"]
        env = dgm.seal_share(cfg, "test-password-123",
                             expires_at=int(time.time() * 1000) + 3600000)
        with self.assertRaises(dgm.DecodeError) as ctx:
            dgm.open_share(env, "wrong-password")
        self.assertEqual(ctx.exception.code, "WRONG_PASSWORD")

    def test_negative_expired_share(self):
        profiles, _ = dgm.parse_text(load_fixture("synthetic_feed.txt"))
        cfg = profiles[1]["config"]
        env = dgm.seal_share(cfg, "test-password-123",
                             expires_at=int(time.time() * 1000) - 1000)
        with self.assertRaises(dgm.DecodeError) as ctx:
            dgm.open_share(env, "test-password-123")
        self.assertEqual(ctx.exception.code, "EXPIRED")

    def test_positive_share_without_password(self):
        profiles, _ = dgm.parse_text(load_fixture("synthetic_feed.txt"))
        cfg = profiles[1]["config"]
        env = dgm.seal_share(cfg, None,
                             expires_at=int(time.time() * 1000) + 3600000)
        opened, _meta = dgm.open_share(env, None)
        self.assertEqual(opened["server"], cfg["server"])


class TestRedaction(unittest.TestCase):
    def test_positive_redaction_leaves_zero_ips(self):
        profiles, _ = dgm.parse_text(load_fixture("synthetic_feed.txt"))
        catalog = dgm.apply_free_server_catalog(profiles)
        red, left = dgm.redact({"profiles": catalog})
        self.assertEqual(left, 0)
        self.assertTrue(all(p["config"]["uuid"] == "" for p in red["profiles"]))


if __name__ == "__main__":
    unittest.main()
