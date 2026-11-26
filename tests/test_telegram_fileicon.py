"""Tests for /fileicon, the group password fix, /groups and /allowallgroups."""
from __future__ import annotations

import importlib
import importlib.util
import io
import json
import re
import sys
import types
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

from PIL import Image
from telebot.handler_backends import ContinueHandling

from tests.golden.hc_sip_new_variants import (
    S4_SYNTHETIC_PASSWORD, SYNTHETIC_HWID, hccfg_hwid_file,
)

FILEICON_DATE = int(datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc).timestamp())


def _settings(**overrides):
    base = dict(
        admins={20, 21}, allowed_groups={-40}, allow_all_groups=False, allowed_private_users=set(),
        decoder_timeout_seconds=20, max_file_size_bytes=16 * 1024 * 1024,
        text_session_timeout_seconds=600, text_session_max_chars=250000,
    )
    base.update(overrides)
    return types.SimpleNamespace(**base)


def _mock_bot():
    bot = Mock()
    bot.message_handler.side_effect = lambda **kwargs: lambda fn: fn
    bot.callback_query_handler.side_effect = lambda **kwargs: lambda fn: fn
    return bot


def _png_bytes(width, height, color="red"):
    buffer = io.BytesIO()
    Image.new("RGB", (width, height), color=color).save(buffer, format="PNG")
    return buffer.getvalue()


class _RuntimePatchedCase(unittest.TestCase):
    """Patch spdecode.runtime before importing a bot handler module."""

    def _patch_runtime(self, *, extra=None):
        self.bot = _mock_bot()
        self.settings = _settings()
        runtime = types.SimpleNamespace(bot=self.bot, settings=self.settings)
        if extra:
            for key, value in extra.items():
                setattr(runtime, key, value)
        patcher = patch.dict(sys.modules, {"spdecode.runtime": runtime})
        patcher.start()
        self.addCleanup(patcher.stop)
        return runtime

    def _clear_sessions(self, module):
        for pending in list(getattr(module, "_pending", {}).values()):
            timer = getattr(pending, "timer", None)
            if timer is not None:
                timer.cancel()
        getattr(module, "_pending", {}).clear()


class ActivityTests(_RuntimePatchedCase):
    def setUp(self):
        self.recorded = []
        self._patch_runtime(extra={"record_known_group": lambda chat_id, title: self.recorded.append((chat_id, title)) or True})
        sys.modules.pop("spdecode.handlers.activity", None)
        self.activity = importlib.import_module("spdecode.handlers.activity")

    def _message(self, chat_id=-40, title="Test Group", chat_type="supergroup"):
        return SimpleNamespace(
            chat=SimpleNamespace(id=chat_id, type=chat_type, title=title),
            from_user=SimpleNamespace(id=20), message_id=7,
        )

    def test_activity_handler_is_registered_for_groups_first(self):
        registrations = [call.kwargs for call in self.bot.message_handler.call_args_list]
        activity = next(item for item in registrations if item.get("chat_types") == ["group", "supergroup"])
        self.assertIn("text", activity["content_types"])
        self.assertIn("document", activity["content_types"])
        self.assertIn("photo", activity["content_types"])
        self.assertIn("new_chat_members", activity["content_types"])

    def test_group_activity_is_recorded_and_dispatch_continues(self):
        result = self.activity.record_group_activity(self._message())
        self.assertEqual(self.recorded, [(-40, "Test Group")])
        self.assertIsInstance(result, ContinueHandling)

    def test_group_without_title_is_recorded_with_empty_title(self):
        self.activity.record_group_activity(self._message(title=None))
        self.assertEqual(self.recorded, [(-40, None)])


class FileiconCaptionTests(_RuntimePatchedCase):
    def setUp(self):
        self._patch_runtime()
        self.fileicon = importlib.import_module("spdecode.handlers.fileicon")
        patcher = patch.multiple(self.fileicon, bot=self.bot, settings=self.settings)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_exact_caption_design_2(self):
        caption = self.fileicon.build_fileicon_caption("report.json", 583311, FILEICON_DATE)
        self.assertEqual(caption, (
            "══════════════════\n"
            "<b>📄 report.json</b>\n"
            "✦ 569.6 KB · JSON\n"
            "✦ 25 Nov 2026\n"
            "══════════════════\n"
            "✦ Decode by @GhostDeve"
        ))

    def test_caption_date_uses_tijuana_time_not_utc(self):
        # 2026-11-26 01:30 UTC is still 2026-11-25 17:30 in Tijuana.
        timestamp = int(datetime(2026, 11, 26, 1, 30, tzinfo=timezone.utc).timestamp())
        caption = self.fileicon.build_fileicon_caption("report.json", 583311, timestamp)
        self.assertIn("✦ 25 Nov 2026\n", caption)

    def test_caption_date_early_utc_is_the_previous_day_in_tijuana(self):
        # 2026-11-25 02:00 UTC is 2026-11-24 18:00 in Tijuana.
        timestamp = int(datetime(2026, 11, 25, 2, 0, tzinfo=timezone.utc).timestamp())
        caption = self.fileicon.build_fileicon_caption("report.json", 583311, timestamp)
        self.assertIn("✦ 24 Nov 2026\n", caption)

    def test_dividers_have_eighteen_chars(self):
        caption = self.fileicon.build_fileicon_caption("a.txt", 10, FILEICON_DATE)
        lines = caption.splitlines()
        self.assertEqual(lines[0], "═" * 18)
        self.assertEqual(lines[4], "═" * 18)

    def test_filename_is_html_escaped(self):
        caption = self.fileicon.build_fileicon_caption('x<b>&"y.json', 100, FILEICON_DATE)
        self.assertIn("x&lt;b&gt;&amp;&quot;y.json", caption)
        self.assertNotIn('x<b>&"y.json', caption)

    def test_size_formatting(self):
        cases = {0: "0 B", 500: "500 B", 1024: "1 KB", 1536: "1.5 KB", 583311: "569.6 KB"}
        for size, expected in cases.items():
            with self.subTest(size=size):
                caption = self.fileicon.build_fileicon_caption("f.bin", size, FILEICON_DATE)
                self.assertIn(f"✦ {expected} · BIN", caption)

    def test_extension_uppercase_and_missing_extension(self):
        caption = self.fileicon.build_fileicon_caption("archive.tar.gz", 10, FILEICON_DATE)
        self.assertIn("✦ 10 B · GZ", caption)
        caption = self.fileicon.build_fileicon_caption("noext", 10, FILEICON_DATE)
        self.assertIn("✦ 10 B · FILE", caption)

    def test_long_filename_is_truncated_within_the_caption_limit(self):
        caption = self.fileicon.build_fileicon_caption("a" * 2000 + ".json", 10, FILEICON_DATE)
        self.assertLessEqual(len(caption), 1024)
        self.assertIn("…</b>", caption)
        self.assertTrue(caption.startswith("═" * 18 + "\n<b>📄 "))
        self.assertTrue(caption.endswith("✦ Decode by @GhostDeve"))

    def test_long_escapable_filename_still_fits(self):
        caption = self.fileicon.build_fileicon_caption("&" * 900 + ".json", 10, FILEICON_DATE)
        self.assertLessEqual(len(caption), 1024)
        self.assertIn("…</b>", caption)

    def test_date_uses_tijuana_time_and_english_months(self):
        # 2026-01-05 03:04 UTC is still 2026-01-04 19:04 in Tijuana.
        timestamp = int(datetime(2026, 1, 5, 3, 4, tzinfo=timezone.utc).timestamp())
        caption = self.fileicon.build_fileicon_caption("f.txt", 10, timestamp)
        self.assertIn("✦ 4 Jan 2026", caption)


class FileiconThumbnailTests(_RuntimePatchedCase):
    def setUp(self):
        self._patch_runtime()
        self.fileicon = importlib.import_module("spdecode.handlers.fileicon")
        patcher = patch.multiple(self.fileicon, bot=self.bot, settings=self.settings)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_large_png_becomes_jpeg_within_limits(self):
        thumbnail = self.fileicon.make_thumbnail(_png_bytes(1200, 800))
        self.assertIsNotNone(thumbnail)
        self.assertLessEqual(len(thumbnail), 200 * 1024)
        self.assertEqual(thumbnail[:3], b"\xff\xd8\xff")
        with Image.open(io.BytesIO(thumbnail)) as image:
            self.assertEqual(image.format, "JPEG")
            self.assertLessEqual(image.size[0], 320)
            self.assertLessEqual(image.size[1], 320)

    def test_small_png_keeps_its_dimensions(self):
        thumbnail = self.fileicon.make_thumbnail(_png_bytes(100, 60))
        with Image.open(io.BytesIO(thumbnail)) as image:
            self.assertEqual(image.format, "JPEG")
            self.assertEqual(image.size, (100, 60))

    def test_transparent_png_is_converted(self):
        buffer = io.BytesIO()
        Image.new("RGBA", (200, 200), color=(255, 0, 0, 0)).save(buffer, format="PNG")
        thumbnail = self.fileicon.make_thumbnail(buffer.getvalue())
        self.assertIsNotNone(thumbnail)
        with Image.open(io.BytesIO(thumbnail)) as image:
            self.assertEqual(image.format, "JPEG")

    def test_non_image_returns_none(self):
        self.assertIsNone(self.fileicon.make_thumbnail(b"not an image"))


class FileiconFlowTests(_RuntimePatchedCase):
    def setUp(self):
        self._patch_runtime()
        self.fileicon = importlib.import_module("spdecode.handlers.fileicon")
        patcher = patch.multiple(self.fileicon, bot=self.bot, settings=self.settings)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(lambda: self._clear_sessions(self.fileicon))
        self.document_bytes = b'{"servers": []}'
        self.bot.get_file.side_effect = lambda file_id: SimpleNamespace(
            file_path="thumb.jpg" if file_id in {"thumb-small", "thumb-large", "img-1"} else "doc.json"
        )
        self.bot.download_file.side_effect = lambda file_path: (
            _png_bytes(1200, 800) if file_path == "thumb.jpg" else self.document_bytes
        )
        self.replies = []
        self.bot.reply_to.side_effect = lambda message, text, **kwargs: self.replies.append(text)

    def _message(self, *, user=20, group=False, text=None, document=None, photo=None,
                 message_id=1, thread=None, date=FILEICON_DATE):
        return SimpleNamespace(
            chat=SimpleNamespace(id=-40 if group else user, type="supergroup" if group else "private"),
            from_user=SimpleNamespace(id=user),
            message_thread_id=thread, message_id=message_id, text=text,
            reply_to_message=None, date=date, document=document, photo=photo,
        )

    def _document(self, file_name="report.json", file_id="file-123", file_size=583311, mime="application/json"):
        return SimpleNamespace(
            file_name=file_name, file_id=file_id, file_size=file_size, mime_type=mime,
        )

    def _photo(self):
        return [
            SimpleNamespace(file_id="thumb-small", file_size=1000),
            SimpleNamespace(file_id="thumb-large", file_size=5000),
        ]

    def _start_flow(self, **kwargs):
        self.fileicon.start_fileicon(self._message(text="/fileicon", **kwargs))
        self.assertIn("Send the file you want to attach a thumbnail to.", self.replies)

    def test_full_flow_reuploads_the_document_with_thumbnail_and_caption(self):
        self._start_flow()
        self.fileicon.handle_fileicon_document(
            self._message(document=self._document(), message_id=2)
        )
        self.assertIn("File received. Now send the thumbnail image.", self.replies)
        self.fileicon.handle_fileicon_photo(self._message(photo=self._photo(), message_id=3))
        self.assertEqual(self.bot.send_document.call_count, 1)
        sent = self.bot.send_document.call_args.kwargs
        # The file bytes are re-uploaded (not re-sent by file_id): Telegram
        # ignores the thumbnail on a file_id resend, so the file would come
        # back with the generic document icon instead of the thumbnail.
        document = sent["document"]
        self.assertEqual(document.name, "report.json")
        self.assertEqual(document.read(), self.document_bytes)
        self.assertEqual(sent["parse_mode"], "HTML")
        self.assertEqual(sent["caption"], (
            "══════════════════\n"
            "<b>📄 report.json</b>\n"
            "✦ 569.6 KB · JSON\n"
            "✦ 25 Nov 2026\n"
            "══════════════════\n"
            "✦ Decode by @GhostDeve"
        ))
        thumbnail = sent["thumbnail"]
        self.assertEqual(thumbnail.name, "thumbnail.jpg")
        raw = thumbnail.read()
        self.assertLessEqual(len(raw), 200 * 1024)
        with Image.open(io.BytesIO(raw)) as image:
            self.assertEqual(image.format, "JPEG")
            self.assertLessEqual(image.size[0], 320)
            self.assertLessEqual(image.size[1], 320)
        self.assertFalse(self.fileicon._pending)

    def test_full_flow_in_authorized_group(self):
        self._start_flow(group=True, thread=9)
        self.fileicon.handle_fileicon_document(
            self._message(group=True, document=self._document(), message_id=2, thread=9)
        )
        self.fileicon.handle_fileicon_photo(
            self._message(group=True, photo=self._photo(), message_id=3, thread=9)
        )
        sent = self.bot.send_document.call_args.kwargs
        self.assertEqual((sent["chat_id"], sent["message_thread_id"]), (-40, 9))

    def test_html_filename_is_escaped_in_the_sent_caption(self):
        self._start_flow()
        self.fileicon.handle_fileicon_document(
            self._message(document=self._document(file_name='x<b>&"y.json'), message_id=2)
        )
        self.fileicon.handle_fileicon_photo(self._message(photo=self._photo(), message_id=3))
        caption = self.bot.send_document.call_args.kwargs["caption"]
        self.assertIn("x&lt;b&gt;&amp;&quot;y.json", caption)

    def test_image_sent_as_document_counts_as_thumbnail(self):
        self._start_flow()
        self.fileicon.handle_fileicon_document(
            self._message(document=self._document(), message_id=2)
        )
        self.fileicon.handle_fileicon_document(
            self._message(
                document=self._document(file_name="thumb.png", file_id="img-1", file_size=5000, mime="image/png"),
                message_id=3,
            )
        )
        self.assertEqual(self.bot.send_document.call_count, 1)
        self.assertEqual(self.bot.send_document.call_args.kwargs["document"].name, "report.json")

    def test_text_without_image_keeps_waiting(self):
        self._start_flow()
        self.fileicon.handle_fileicon_document(
            self._message(document=self._document(), message_id=2)
        )
        self.fileicon.handle_fileicon_text(self._message(text="hello", message_id=3))
        self.assertIn("Send the thumbnail image.", self.replies)
        self.assertEqual(self.bot.send_document.call_count, 0)
        self.assertEqual(len(self.fileicon._pending), 1)

    def test_non_image_document_while_waiting_for_thumbnail_reprompts(self):
        self._start_flow()
        self.fileicon.handle_fileicon_document(
            self._message(document=self._document(), message_id=2)
        )
        self.fileicon.handle_fileicon_document(
            self._message(document=self._document(file_name="other.zip", file_id="zip-1"), message_id=3)
        )
        self.assertIn("Send the thumbnail image.", self.replies)
        self.assertEqual(self.bot.send_document.call_count, 0)
        self.assertEqual(len(self.fileicon._pending), 1)

    def test_photo_before_the_file_reprompts_for_the_file(self):
        self._start_flow()
        self.fileicon.handle_fileicon_photo(self._message(photo=self._photo(), message_id=2))
        self.assertIn("Send the file you want to attach a thumbnail to.", self.replies)
        self.assertEqual(self.bot.send_document.call_count, 0)

    def test_text_before_the_file_reprompts_for_the_file(self):
        self._start_flow()
        self.fileicon.handle_fileicon_text(self._message(text="hello", message_id=2))
        self.assertIn("Send the file you want to attach a thumbnail to.", self.replies)

    def test_file_too_large_is_rejected_and_flow_keeps_waiting(self):
        self._start_flow()
        self.fileicon.handle_fileicon_document(
            self._message(document=self._document(file_size=17 * 1024 * 1024), message_id=2)
        )
        self.assertIn("That file is too large. Send a smaller file.", self.replies)
        self.assertEqual(len(self.fileicon._pending), 1)

    def test_unusable_image_keeps_waiting(self):
        self._start_flow()
        self.fileicon.handle_fileicon_document(
            self._message(document=self._document(), message_id=2)
        )
        self.bot.download_file.side_effect = lambda file_path: b"not an image"
        self.fileicon.handle_fileicon_photo(self._message(photo=self._photo(), message_id=3))
        self.assertIn("That image could not be used as a thumbnail. Send another image.", self.replies)
        self.assertEqual(self.bot.send_document.call_count, 0)
        self.assertEqual(len(self.fileicon._pending), 1)

    def test_document_over_the_bot_download_limit_is_rejected(self):
        # The Bot API only lets a bot download files up to 20 MB, so a bigger
        # file cannot be re-uploaded with a thumbnail.
        self.settings.max_file_size_bytes = 25 * 1024 * 1024
        self._start_flow()
        self.fileicon.handle_fileicon_document(
            self._message(document=self._document(file_size=21 * 1024 * 1024), message_id=2)
        )
        self.assertIn("File received. Now send the thumbnail image.", self.replies)
        self.fileicon.handle_fileicon_photo(self._message(photo=self._photo(), message_id=3))
        self.assertIn("20 MB", self.replies[-1])
        self.assertEqual(self.bot.send_document.call_count, 0)
        self.assertEqual(len(self.fileicon._pending), 0)

    def test_cancel_discards_the_flow(self):
        self._start_flow()
        self.fileicon.handle_fileicon_document(
            self._message(document=self._document(), message_id=2)
        )
        self.assertTrue(self.fileicon.cancel_pending_fileicon(self._message(text="/cancel", message_id=3)))
        self.assertFalse(self.fileicon._pending)
        self.assertFalse(self.fileicon.cancel_pending_fileicon(self._message(text="/cancel", message_id=4)))
        self.assertFalse(self.fileicon._is_fileicon_document(
            self._message(document=self._document(), message_id=5)
        ))

    def test_unauthorized_user_is_silently_ignored(self):
        self.fileicon.start_fileicon(self._message(user=99, text="/fileicon"))
        self.assertEqual(self.bot.reply_to.call_count, 0)
        self.assertFalse(self.fileicon._pending)

    def test_unauthorized_group_is_silently_ignored(self):
        message = self._message(user=20, group=True, text="/fileicon")
        message.chat.id = -41
        self.fileicon.start_fileicon(message)
        self.assertEqual(self.bot.reply_to.call_count, 0)
        self.assertFalse(self.fileicon._pending)


class GroupPasswordFixTests(_RuntimePatchedCase):
    def setUp(self):
        self._patch_runtime()
        self.bot.get_file.return_value = SimpleNamespace(file_path="synthetic-input.hc")
        self.bot.download_file.return_value = hccfg_hwid_file(password=S4_SYNTHETIC_PASSWORD)
        self.prompts = []
        self.bot.reply_to.side_effect = self._reply_to
        self.sent = []
        self.bot.send_document.side_effect = lambda **kwargs: self.sent.append(
            (kwargs["document"].name, kwargs["document"].read().decode("utf-8"))
        )
        self.credentials = importlib.import_module("spdecode.handlers.decoder_credentials")
        self.documents = importlib.import_module("spdecode.handlers.documents")
        for module in (self.credentials, self.documents):
            patcher = patch.multiple(module, bot=self.bot, settings=self.settings)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(lambda: self._clear_sessions(self.credentials))

    def _reply_to(self, original, text, **kwargs):
        reply = SimpleNamespace(
            message_id=100 + len(self.prompts), text=text,
            chat=original.chat, message_thread_id=kwargs.get("message_thread_id"),
            from_user=SimpleNamespace(id=99, is_bot=True),
        )
        if text.startswith(self.credentials._PROMPT):
            self.prompts.append(reply)
        return reply

    def _message(self, *, user=20, group=False, password="", reply=None, thread=None, message_id=1):
        return SimpleNamespace(
            chat=SimpleNamespace(id=-40 if group else user, type="supergroup" if group else "private"),
            from_user=SimpleNamespace(id=user),
            message_thread_id=thread, message_id=message_id, text=password, reply_to_message=reply,
            date=1763897400,
            document=SimpleNamespace(file_name="synthetic.HC", file_id="test", file_size=200),
        )

    def _send_group_file(self, user=22, thread=50):
        original = self._message(user=user, group=True, thread=thread)
        self.documents.process_received_file(original)
        self.assertEqual(len(self.prompts), 1)
        self.assertIn("HWID", self.prompts[-1].text)
        return original

    def test_plain_password_in_group_decrypts_the_file(self):
        # Regression: a password typed as a plain message in the group used to
        # fall through to the fallback handler and do nothing.
        self._send_group_file()
        plain_hwid = self._message(user=22, group=True, thread=50, password=SYNTHETIC_HWID)
        self.assertTrue(self.credentials._is_credential_reply(plain_hwid))
        self.credentials.handle_credential_reply(plain_hwid)
        self.assertEqual(len(self.prompts), 2)
        self.assertIn("password", self.prompts[-1].text)
        plain_password = self._message(user=22, group=True, thread=50, password=S4_SYNTHETIC_PASSWORD)
        self.assertTrue(self.credentials._is_credential_reply(plain_password))
        self.credentials.handle_credential_reply(plain_password)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0][0], "synthetic.md")
        sent = self.bot.send_document.call_args.kwargs
        self.assertEqual((sent["chat_id"], sent["message_thread_id"]), (-40, 50))
        self.assertFalse(self.credentials._pending)

    def test_plain_password_from_another_user_is_still_ignored(self):
        self._send_group_file()
        foreign = self._message(user=21, group=True, thread=50, password=SYNTHETIC_HWID)
        self.assertFalse(self.credentials._is_credential_reply(foreign))

    def test_plain_password_from_another_thread_is_still_ignored(self):
        self._send_group_file()
        other_thread = self._message(user=22, group=True, thread=51, password=SYNTHETIC_HWID)
        self.assertFalse(self.credentials._is_credential_reply(other_thread))

    def test_plain_text_without_pending_is_not_a_credential(self):
        message = self._message(user=22, group=True, thread=50, password=SYNTHETIC_HWID)
        self.assertFalse(self.credentials._is_credential_reply(message))

    def test_plain_command_is_not_a_credential(self):
        self._send_group_file()
        cancel = self._message(user=22, group=True, thread=50, password="/cancel")
        self.assertFalse(self.credentials._is_credential_reply(cancel))

    def test_private_reply_flow_still_works(self):
        original = self._message(user=20, message_id=1)
        self.documents.process_received_file(original)
        prompt = self.prompts[-1]
        self.credentials.handle_credential_reply(
            self._message(user=20, password=SYNTHETIC_HWID, reply=prompt)
        )
        self.assertIn("password", self.prompts[-1].text)
        self.credentials.handle_credential_reply(
            self._message(user=20, password=S4_SYNTHETIC_PASSWORD, reply=original)
        )
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0][0], "synthetic.md")
        self.assertFalse(self.credentials._pending)


class GroupCommandsTests(_RuntimePatchedCase):
    def setUp(self):
        work = TemporaryDirectory()
        self.addCleanup(work.cleanup)
        root = Path(work.name)
        self.config_path = root / "config.json"
        self.config_path.write_text(json.dumps({
            "bot": {"token": "fixture-only"},
            "access": {
                "admins": [20], "allow_all_groups": False, "allowed_groups": [-40],
                "known_groups": {"-100111222333": "Alpha Group", "-100444555666": "Beta Group"},
            },
            "runtime": {"downloads_dir": str(root / "in"), "results_dir": str(root / "out")},
            "other": {"preserved": True},
        }))
        self.bot = _mock_bot()
        source = Path(__file__).resolve().parents[1] / "spdecode/runtime.py"
        spec = importlib.util.spec_from_file_location("spdecode._test_fileicon_runtime", source)
        self.runtime = importlib.util.module_from_spec(spec)
        from spdecode.config import load_config, save_chat_permissions

        with patch("spdecode.config.load_config", return_value=load_config(self.config_path)), \
                patch("telebot.TeleBot", return_value=self.bot):
            spec.loader.exec_module(self.runtime)
        runtime_patch = patch.dict(sys.modules, {"spdecode.runtime": self.runtime})
        runtime_patch.start()
        self.addCleanup(runtime_patch.stop)
        persistence = patch.object(
            self.runtime, "save_chat_permissions",
            side_effect=lambda config: save_chat_permissions(config, self.config_path),
        )
        persistence.start()
        self.addCleanup(persistence.stop)
        self.commands = importlib.import_module("spdecode.handlers.commands")
        bot_patch = patch.object(self.commands, "bot", self.bot)
        bot_patch.start()
        self.addCleanup(bot_patch.stop)
        self.fileicon = importlib.import_module("spdecode.handlers.fileicon")
        self.addCleanup(lambda: self._clear_sessions(self.fileicon))

    def _message(self, user_id, chat_id, text, *, group=False):
        return SimpleNamespace(
            from_user=SimpleNamespace(id=user_id),
            chat=SimpleNamespace(id=chat_id, type="supergroup" if group else "private"),
            text=text, message_id=1,
        )

    def _reply_text(self):
        return self.bot.reply_to.call_args.args[1]

    def _load_access(self):
        return json.loads(self.config_path.read_text())["access"]

    def test_groups_lists_known_groups_sorted_by_title(self):
        self.commands.list_groups(self._message(20, 20, "/groups"))
        reply = self._reply_text()
        self.assertTrue(reply.startswith("<b>Groups</b>\n"))
        self.assertLess(reply.index("Alpha Group"), reply.index("Beta Group"))
        self.assertIn("<code>-100111222333</code>", reply)
        self.assertIn("<code>-100444555666</code>", reply)

    def test_groups_empty(self):
        self.runtime.settings = replace(self.runtime.settings, known_groups={})
        self.commands.list_groups(self._message(20, 20, "/groups"))
        self.assertEqual(self._reply_text(), "<b>Groups</b>\nThe bot is not in any group yet.")

    def test_groups_escapes_html_in_titles(self):
        self.runtime.settings = replace(
            self.runtime.settings, known_groups={-1001: "A <b>Group</b> & Friends"}
        )
        self.commands.list_groups(self._message(20, 20, "/groups"))
        reply = self._reply_text()
        self.assertIn("A &lt;b&gt;Group&lt;/b&gt; &amp; Friends", reply)
        self.assertNotIn("A <b>Group</b> & Friends", reply)

    def test_groups_untitled_group(self):
        self.runtime.settings = replace(self.runtime.settings, known_groups={-1001: ""})
        self.commands.list_groups(self._message(20, 20, "/groups"))
        self.assertIn("Untitled group — <code>-1001</code>", self._reply_text())

    def test_groups_non_admin_is_rejected(self):
        self.commands.list_groups(self._message(99, 99, "/groups"))
        self.assertEqual(
            self._reply_text(),
            "<b>Restricted access</b>\nThis command is available to administrators only.",
        )

    def test_record_known_group_persists_and_renames(self):
        self.assertTrue(self.runtime.record_known_group(-100777888999, "Gamma Group"))
        self.assertEqual(
            self._load_access()["known_groups"]["-100777888999"], "Gamma Group",
        )
        self.assertEqual(self.runtime.settings.known_groups[-100777888999], "Gamma Group")
        self.assertTrue(self.runtime.record_known_group(-100777888999, "Gamma Renamed"))
        self.assertEqual(
            self._load_access()["known_groups"]["-100777888999"], "Gamma Renamed",
        )
        before = self.config_path.read_text()
        self.assertFalse(self.runtime.record_known_group(-100777888999, "Gamma Renamed"))
        self.assertEqual(self.config_path.read_text(), before)

    def test_record_known_group_ignores_non_groups(self):
        self.assertFalse(self.runtime.record_known_group(12345, "Private"))
        self.assertNotIn("12345", self._load_access()["known_groups"])
        self.assertFalse(self.runtime.record_known_group(-100111222333, "Alpha Group"))

    def test_allowallgroups_opens_restricted_access(self):
        self.commands.allow_all_group_access(self._message(20, 20, "/allowallgroups"))
        self.assertEqual(self._reply_text(), "Group access is now open to all groups.")
        self.assertTrue(self._load_access()["allow_all_groups"])
        self.assertTrue(self.runtime.settings.allow_all_groups)

    def test_allowallgroups_already_open(self):
        self.commands.allow_all_group_access(self._message(20, 20, "/allowallgroups"))
        self.commands.allow_all_group_access(self._message(20, 20, "/allowallgroups"))
        self.assertEqual(self._reply_text(), "Group access is already open to all groups.")

    def test_allowallgroups_then_restrictgroups(self):
        self.commands.allow_all_group_access(self._message(20, 20, "/allowallgroups"))
        self.commands.restrict_group_access(self._message(20, 20, "/restrictgroups"))
        self.assertEqual(self._reply_text(), "Group access is now restricted to allowed groups.")
        self.assertFalse(self._load_access()["allow_all_groups"])

    def test_restrictgroups_then_allowallgroups(self):
        self.commands.allow_all_group_access(self._message(20, 20, "/allowallgroups"))
        self.commands.restrict_group_access(self._message(20, 20, "/restrictgroups"))
        self.commands.allow_all_group_access(self._message(20, 20, "/allowallgroups"))
        self.assertEqual(self._reply_text(), "Group access is now open to all groups.")
        self.assertTrue(self._load_access()["allow_all_groups"])

    def test_allowallgroups_non_admin_is_rejected(self):
        self.commands.allow_all_group_access(self._message(99, 99, "/allowallgroups"))
        self.assertEqual(
            self._reply_text(), "Only SP-DECODE administrators can change group access.",
        )
        self.assertFalse(self._load_access()["allow_all_groups"])

    def test_allowallgroups_with_argument_shows_usage(self):
        self.commands.allow_all_group_access(self._message(20, 20, "/allowallgroups extra"))
        self.assertEqual(self._reply_text(), "Use /allowallgroups to allow all groups.")

    def test_cancel_discards_a_fileicon_flow(self):
        message = self._message(20, 20, "/fileicon")
        message.message_thread_id = None
        message.reply_to_message = None
        message.date = FILEICON_DATE
        message.document = None
        message.photo = None
        self.fileicon.start_fileicon(message)
        self.assertEqual(len(self.fileicon._pending), 1)
        self.commands.cancel_pending_session(message)
        self.assertEqual(self._reply_text(), "File icon request canceled.")
        self.assertFalse(self.fileicon._pending)

    def test_command_menu_lists_new_commands(self):
        commands = {command.command: command.description for command in self.commands.BOT_COMMANDS}
        self.assertEqual(commands["fileicon"], "Attach a thumbnail to a file")
        self.assertEqual(commands["groups"], "List the groups where the bot is (administrators)")
        self.assertEqual(commands["allowallgroups"], "Allow all groups (administrators)")


class MainImportOrderTests(unittest.TestCase):
    def test_handler_import_order(self):
        source = (Path(__file__).resolve().parents[1] / "main.py").read_text()
        order = [
            "from spdecode.handlers import activity as _activity",
            "from spdecode.handlers import decoder_credentials as _decoder_credentials",
            "from spdecode.handlers import commands as _commands",
            "from spdecode.handlers import cloud_texts as _cloud_texts",
            "from spdecode.handlers import extra_text_protocols as _extra_text_protocols",
            "from spdecode.handlers import text_protocols as _text_protocols",
            "from spdecode.handlers import config_batch_texts as _config_batch_texts",
            "from spdecode.handlers import fileicon as _fileicon",
            "from spdecode.handlers import documents as _documents",
            "from spdecode.handlers import fallback as _fallback",
        ]
        positions = [source.index(line) for line in order]
        self.assertEqual(positions, sorted(positions))


if __name__ == "__main__":
    unittest.main()
