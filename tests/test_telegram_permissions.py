from __future__ import annotations

import importlib
import importlib.util
import json
import stat
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from spdecode.access import is_authorized
from spdecode.config import load_config, save_chat_permissions


class TelegramPermissionCommandTests(TestCase):
    def setUp(self):
        work = TemporaryDirectory()
        self.addCleanup(work.cleanup)
        root = Path(work.name)
        self.config_path = root / "config.json"
        self.config_path.write_text(json.dumps({
            "bot": {"token": "fixture-only"},
            "access": {"admins": [20], "allow_all_groups": False, "allowed_groups": [-40, 21]},
            "runtime": {"downloads_dir": str(root / "in"), "results_dir": str(root / "out")},
            "other": {"preserved": True},
        }))
        self.bot = Mock()
        self.bot.message_handler.side_effect = lambda **kwargs: lambda fn: fn
        self.bot.callback_query_handler.side_effect = lambda **kwargs: lambda fn: fn
        source = Path(__file__).resolve().parents[1] / "spdecode/runtime.py"
        spec = importlib.util.spec_from_file_location("spdecode._test_permissions_runtime", source)
        self.runtime = importlib.util.module_from_spec(spec)
        with patch("spdecode.config.load_config", return_value=load_config(self.config_path)), \
                patch("telebot.TeleBot", return_value=self.bot):
            spec.loader.exec_module(self.runtime)
        runtime_patch = patch.dict(sys.modules, {"spdecode.runtime": self.runtime})
        runtime_patch.start()
        self.addCleanup(runtime_patch.stop)
        persistence = patch.object(
            self.runtime, "save_chat_permissions", side_effect=lambda settings: save_chat_permissions(settings, self.config_path),
        )
        persistence.start()
        self.save = self.runtime.save_chat_permissions
        self.addCleanup(persistence.stop)
        self.commands = importlib.import_module("spdecode.handlers.commands")
        bot_patch = patch.object(self.commands, "bot", self.bot)
        bot_patch.start()
        self.addCleanup(bot_patch.stop)

    def _message(self, user_id, chat_id, text, *, group=False):
        return SimpleNamespace(
            from_user=SimpleNamespace(id=user_id),
            chat=SimpleNamespace(id=chat_id, type="supergroup" if group else "private"),
            text=text, message_id=1,
        )

    def test_admin_can_authorize_current_group_then_revoke_without_restart(self):
        allow = self._message(20, -50, "/permitirgrupo@SampleBot", group=True)
        member = self._message(22, -50, "", group=True)
        self.assertFalse(is_authorized(allow, self.runtime.settings))
        self.commands.manage_group_permission(allow)
        self.assertTrue(is_authorized(member, self.runtime.settings))
        self.assertTrue(is_authorized(member, load_config(self.config_path)))
        self.commands.manage_group_permission(self._message(20, 20, "/revocargrupo -50"))
        self.assertFalse(is_authorized(member, self.runtime.settings))
        self.assertFalse(is_authorized(member, load_config(self.config_path)))

    def test_private_permissions_and_legacy_private_allowance(self):
        migrated = self._message(21, 21, "/privados")
        self.assertTrue(is_authorized(migrated, self.runtime.settings))
        applicant = self._message(22, 22, "/privados")
        self.commands.manage_private_permissions(applicant)
        self.assertIn("necesita autorización", self.bot.reply_to.call_args.args[1])
        self.commands.manage_private_permissions(self._message(20, 20, "/privados permitir 22"))
        self.assertTrue(is_authorized(applicant, self.runtime.settings))
        self.assertFalse(is_authorized(self._message(22, -55, "", group=True), self.runtime.settings))
        self.commands.manage_private_permissions(self._message(20, 20, "/privados"))
        self.assertIn("Usuarios autorizados: 21, 22", self.bot.send_message.call_args.kwargs["text"])
        self.commands.manage_private_permissions(self._message(20, 20, "/privados revocar 22"))
        self.assertFalse(is_authorized(applicant, load_config(self.config_path)))
        data = json.loads(self.config_path.read_text())
        self.assertEqual(data["other"], {"preserved": True})
        self.assertEqual(stat.S_IMODE(self.config_path.stat().st_mode), 0o600)

    def test_non_admin_and_invalid_id_cannot_modify_access(self):
        self.commands.manage_group_permission(self._message(22, -50, "/permitirgrupo", group=True))
        self.commands.manage_private_permissions(self._message(22, 22, "/privados permitir 22"))
        self.commands.manage_group_permission(self._message(20, 20, "/permitirgrupo 400"))
        self.commands.manage_private_permissions(self._message(20, 20, "/privados permitir -500"))
        self.save.assert_not_called()

    def test_concurrent_permissions_are_persisted_together(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(list(pool.map(lambda identifier: self.runtime.set_chat_permission(identifier, True),
                                           (-50, 25))), [True, True])
        saved = load_config(self.config_path)
        self.assertEqual(saved.allowed_groups, {-40, -50})
        self.assertEqual(saved.allowed_private_users, {21, 25})

    def test_save_failure_leaves_current_permissions_unchanged(self):
        self.save.side_effect = OSError("synthetic failure")
        self.commands.manage_group_permission(self._message(20, 20, "/permitirgrupo -50"))
        self.assertNotIn(-50, self.runtime.settings.allowed_groups)
        self.assertIn("No se pudo guardar", self.bot.reply_to.call_args.args[1])
