from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from spdecode.access import is_admin, is_authorized, require_authorized
from spdecode.config import AppConfig, load_config


def _settings(*, allow_all_groups: bool = False) -> AppConfig:
    return AppConfig(
        token="test-token",
        admins=frozenset({101}),
        allowed_groups=frozenset({-202}),
        allow_all_groups=allow_all_groups,
        downloads_dir=Path("Downloads"),
        results_dir=Path("Results"),
        decoder_timeout_seconds=90,
        max_file_size_bytes=1024,
        text_session_timeout_seconds=600,
        text_session_max_chars=4096,
    )


class AccessPolicyTests(unittest.TestCase):
    def test_admin_is_authorized_in_private_chat(self):
        message = SimpleNamespace(
            from_user=SimpleNamespace(id=101),
            chat=SimpleNamespace(id=101, type="private"),
        )
        self.assertTrue(is_admin(101, _settings()))
        self.assertTrue(is_authorized(message, _settings()))

    def test_member_is_authorized_only_in_allowed_group(self):
        allowed = SimpleNamespace(
            from_user=SimpleNamespace(id=303),
            chat=SimpleNamespace(id=-202, type="supergroup"),
        )
        denied = SimpleNamespace(
            from_user=SimpleNamespace(id=303),
            chat=SimpleNamespace(id=-404, type="supergroup"),
        )
        self.assertTrue(is_authorized(allowed, _settings()))
        self.assertFalse(is_authorized(denied, _settings()))

    def test_allow_all_groups_accepts_group_but_not_private_chat(self):
        group = SimpleNamespace(
            from_user=SimpleNamespace(id=303),
            chat=SimpleNamespace(id=-999, type="group"),
        )
        private = SimpleNamespace(
            from_user=SimpleNamespace(id=303),
            chat=SimpleNamespace(id=303, type="private"),
        )
        settings = _settings(allow_all_groups=True)
        self.assertTrue(is_authorized(group, settings))
        self.assertFalse(is_authorized(private, settings))

    def test_authorization_decorator_is_marked_for_validation(self):
        @require_authorized("Prueba")
        def handler(message):
            return message

        self.assertTrue(handler.__spdecode_requires_authorization__)
        self.assertEqual(handler.__name__, "handler")

    def test_environment_token_overrides_placeholder(self):
        config = {
            "bot": {"token": "PUT_YOUR_TELEGRAM_BOT_TOKEN_HERE"},
            "access": {
                "admins": [101],
                "allow_all_groups": True,
                "allowed_groups": [-202],
            },
            "runtime": {},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            with patch.dict(os.environ, {"SPDECODE_BOT_TOKEN": "from-environment"}):
                loaded = load_config(path)
        self.assertEqual(loaded.token, "from-environment")
        self.assertTrue(loaded.allow_all_groups)

    def test_default_administrator_can_use_private_chat(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            for configured_access, expected in (
                ({}, {5325631223}),
                ({"access": {"admins": []}}, set()),
                ({"admins": [101]}, {101}),
                ({"chat_privado_especial_id": 101}, {101}),
            ):
                with self.subTest(configured_access=configured_access):
                    path.write_text(json.dumps({"bot": {"token": "fixture-only"}, **configured_access}))
                    loaded = load_config(path)
                    self.assertEqual(loaded.admins, expected)
                    message = SimpleNamespace(
                        from_user=SimpleNamespace(id=5325631223),
                        chat=SimpleNamespace(id=5325631223, type="private"),
                    )
                    self.assertEqual(is_authorized(message, loaded), 5325631223 in expected)


if __name__ == "__main__":
    unittest.main()
