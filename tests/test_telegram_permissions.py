from __future__ import annotations

import importlib
import importlib.util
import json
import stat
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
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

    def _enable_all_groups(self):
        config = replace(self.runtime.settings, allow_all_groups=True)
        save_chat_permissions(config, self.config_path)
        self.runtime.settings = config

    def test_file_list_starts_with_requested_apps_and_pages_in_place(self):
        message = self._message(20, -40, "/archivos", group=True)
        message.message_thread_id = 72
        self.commands.show_formats(message)
        sent = self.bot.reply_to.call_args
        rows = sent.args[1].splitlines()[3:]
        self.assertEqual(rows[:2], [
            "• <b>HTTP Custom</b> <code>[.HC]</code>",
            "• <b>HTTP Injector</b> <code>[.EHI]</code>",
        ])
        self.assertEqual(sent.kwargs["message_thread_id"], 72)
        next_button = sent.kwargs["reply_markup"].keyboard[0][0]
        self.commands.handle_menu_callback(SimpleNamespace(
            id="fixture", data=next_button.callback_data, message=message,
        ))
        self.bot.answer_callback_query.assert_called_once_with("fixture")
        edit = self.bot.edit_message_text.call_args
        self.assertEqual((edit.kwargs["chat_id"], edit.kwargs["message_id"]), (-40, 1))
        self.assertIn("Page 2 of", edit.args[0])
        self.assertEqual(edit.kwargs["reply_markup"].keyboard[0][0].text, "‹ Previous")
        self.bot.send_message.assert_not_called()

    def test_catalogues_group_aliases_and_hide_internal_labels(self):
        files = self.commands.file_format_rows()
        texts = self.commands.text_format_rows()
        joined = "\n".join((*files, *texts))
        self.assertNotRegex(joined, r"RENZ /|AES-GCM|PBKDF2|DES-ECB|XOR VPN")
        ace = next(row for row in files if "[.ACE]" in row)
        self.assertNotIn("<b>", ace)
        self.assertIn("• <b>VIP Snipher Pro</b> <code>[.VIPSNIPHERPRO]</code>", files)
        self.assertIn("• <b>XVEON Tunnel Pro</b> <code>[.XVEON]</code> <code>[.XVN]</code>", files)
        ac = [row for row in texts if "<b>AC Tunnel VPN</b>" in row]
        self.assertEqual(len(ac), 1)
        self.assertIn("<code>[actunnelvpn://]</code>", ac[0])
        self.assertIn("<code>[acvpn://]</code>", ac[0])
        self.assertIn("accepts fragments", next(row for row in texts if "<b>Dark Tunnel</b>" in row))

    def test_welcome_and_about_show_official_links_and_project_timeline(self):
        message = self._message(20, 20, "/start")
        message.from_user.first_name = "Dev <Team>"
        self.commands.send_welcome(message)
        welcome = self.bot.reply_to.call_args
        self.assertIn("Welcome to SP-DECODE, Dev &lt;Team&gt;!", welcome.args[1])
        self.assertIn("https://spdecode.xyz", [
            button.url for row in welcome.kwargs["reply_markup"].keyboard for button in row
        ])
        self.commands.about(message)
        about = self.bot.reply_to.call_args
        self.assertIn("Ghost Developer", about.args[1])
        self.assertIn("Developer and owner", about.args[1])
        self.assertIn("<b>2024</b> · The SP-DECODE project began.", about.args[1])
        self.assertIn("October 4, 2026", about.args[1])
        self.assertIn("October 8, 2026", about.args[1])
        self.assertNotRegex(about.args[1], r"Python|Node\.js|PHP")
        links = {button.url for row in about.kwargs["reply_markup"].keyboard for button in row}
        self.assertTrue({
            "https://t.me/GhostDeve", "https://t.me/CodeBreakersHub", "https://t.me/+N4CnTYwQQ-w0MjNh",
        } <= links)

    def test_admin_can_authorize_current_group_then_revoke_without_restart(self):
        allow = self._message(20, -50, "/allowgroup@SampleBot", group=True)
        member = self._message(22, -50, "", group=True)
        self.assertFalse(is_authorized(allow, self.runtime.settings))
        self.commands.manage_group_permission(allow)
        self.assertTrue(is_authorized(member, self.runtime.settings))
        self.assertTrue(is_authorized(member, load_config(self.config_path)))
        self.commands.manage_group_permission(self._message(20, 20, "/revokegroup -50"))
        self.assertFalse(is_authorized(member, self.runtime.settings))
        self.assertFalse(is_authorized(member, load_config(self.config_path)))

    def test_private_permissions_and_legacy_private_allowance(self):
        migrated = self._message(21, 21, "/privados")
        self.assertTrue(is_authorized(migrated, self.runtime.settings))
        applicant = self._message(22, 22, "/private")
        self.commands.manage_private_permissions(applicant)
        self.assertIn("needs permission", self.bot.reply_to.call_args.args[1])
        self.commands.manage_private_permissions(self._message(20, 20, "/private allow 22"))
        self.assertTrue(is_authorized(applicant, self.runtime.settings))
        self.assertFalse(is_authorized(self._message(22, -55, "", group=True), self.runtime.settings))
        self.commands.manage_private_permissions(self._message(20, 20, "/privados"))
        self.assertIn("Allowed users: 21, 22", self.bot.send_message.call_args.kwargs["text"])
        self.commands.manage_private_permissions(self._message(20, 20, "/private revoke 22"))
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
        self._enable_all_groups()
        with ThreadPoolExecutor(max_workers=3) as pool:
            changed = [pool.submit(self.runtime.set_chat_permission, identifier, True) for identifier in (-50, 25)]
            changed.append(pool.submit(self.runtime.restrict_groups))
            self.assertTrue(all(change.result() for change in changed))
        saved = load_config(self.config_path)
        self.assertEqual(saved.allowed_groups, {-40, -50})
        self.assertEqual(saved.allowed_private_users, {21, 25})
        self.assertFalse(saved.allow_all_groups)

    def test_only_admin_can_restrict_group_access_and_keep_allowlists(self):
        self._enable_all_groups()
        unlisted = self._message(22, -55, "/restrictgroups", group=True)
        listed = self._message(22, -40, "", group=True)
        allowed_private = self._message(21, 21, "")
        self.assertTrue(is_authorized(unlisted, self.runtime.settings))

        self.commands.restrict_group_access(unlisted)
        self.commands.restrict_group_access(self._message(20, 20, "/restrictgroups all"))
        self.save.assert_not_called()
        self.assertTrue(self.runtime.settings.allow_all_groups)

        admin_command = self._message(20, 20, "/restrictgroups@SampleBot")
        self.commands.restrict_group_access(admin_command)
        self.assertIn("now restricted", self.bot.reply_to.call_args.args[1])
        self.commands.restrict_group_access(admin_command)
        self.assertIn("already restricted", self.bot.reply_to.call_args.args[1])
        self.save.assert_called_once()
        for config in (self.runtime.settings, load_config(self.config_path)):
            self.assertFalse(is_authorized(unlisted, config))
            self.assertTrue(is_authorized(listed, config))
            self.assertTrue(is_authorized(allowed_private, config))

    def test_save_failure_leaves_current_permissions_unchanged(self):
        self._enable_all_groups()
        self.save.side_effect = OSError("synthetic failure")
        self.commands.manage_group_permission(self._message(20, 20, "/permitirgrupo -50"))
        self.assertNotIn(-50, self.runtime.settings.allowed_groups)
        self.assertIn("Could not save", self.bot.reply_to.call_args.args[1])
        self.commands.restrict_group_access(self._message(20, 20, "/restrictgroups"))
        self.assertTrue(self.runtime.settings.allow_all_groups)
        self.assertIn("Could not save", self.bot.reply_to.call_args.args[1])
