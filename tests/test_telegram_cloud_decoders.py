"""Offline regressions through the dispatcher and Telegram message handlers."""
from __future__ import annotations

import importlib
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cloud.workers.python.engine import DecodeFailure
from decoders.Python.apps.XVEON_Tunnel_Pro.xveon import encrypt_envelope
from spdecode.decoder_runtime import FILE_FORMATS, TEXT_FORMATS, decode, file_suffix, text_prefix
from spdecode.registry import DECODER_REGISTRY
from tests.golden.hc_sip_new_variants import S4_SYNTHETIC_PASSWORD, SYNTHETIC_HWID, hccfg_hwid_file
from tests.test_hc_legacy57 import CASES, wire


class TelegramDecoderRuntimeTests(unittest.TestCase):
    def test_file_and_text_inventories_include_current_cloud_routes(self):
        self.assertTrue(DECODER_REGISTRY.keys() <= FILE_FORMATS.keys())
        for suffix in ("xu", "xveon", "xvn", "enaa", "netflux", "rmplite", "pausa", "tut"):
            self.assertIn(suffix, FILE_FORMATS)
            self.assertEqual(file_suffix(f"profile.{suffix.upper()}"), suffix)
        for prefix in ("pausa://", "xveon://", "rmplite://", "netfluxvpn://"):
            self.assertIn(prefix, TEXT_FORMATS)
            self.assertEqual(text_prefix(prefix.upper() + "invalid-test-value"), prefix)
        self.assertIsNone(text_prefix("hccloud://private-reference"))
        self.assertIsNone(text_prefix("darktunnel://preserved-by-multipart-handler"))

    def test_legacy_http_custom_complete_and_partial_results(self):
        for name in ("build564-hwid0", "build565-hwid1", "unresolved"):
            with self.subTest(name=name):
                case = CASES[name]
                result = decode(wire(case, 1), suffix="hc", timeout_seconds=20)
                self.assertEqual(json.loads(result.text), case["expected"])
                self.assertEqual(result.partial, name == "unresolved")

    def test_new_xveon_files_and_texts_share_the_same_result(self):
        fixture = Path(__file__).with_name("golden") / "xveon_vectors.json"
        expected = json.loads(fixture.read_text())
        text = encrypt_envelope(expected)
        payload = text.encode()
        for suffix in ("xveon", "xvn", None):
            with self.subTest(suffix=suffix):
                actual = decode(payload, suffix=suffix, timeout_seconds=20)
                self.assertEqual(json.loads(actual.text)["config"], expected)

    def test_protected_xveon_preserves_error_and_requires_the_password(self):
        fixture = Path(__file__).with_name("golden") / "xveon_vectors.json"
        expected = json.loads(fixture.read_text())
        password = "fixture-only-0123456789ABCDEF"
        payload = encrypt_envelope(expected, password=password).encode()
        for suffix in ("xveon", None):
            with self.subTest(suffix=suffix):
                with self.assertRaises(DecodeFailure) as caught:
                    decode(payload, suffix=suffix, timeout_seconds=20)
                self.assertEqual(caught.exception.code, "PASSWORD_REQUIRED")
                actual = decode(payload, suffix=suffix, timeout_seconds=20, credentials={"password": password})
                self.assertEqual(json.loads(actual.text)["config"], expected)


class TelegramHandlersTests(unittest.TestCase):
    def setUp(self):
        self.bot = Mock()
        self.bot.message_handler.side_effect = lambda **kwargs: lambda fn: fn
        self.bot.send_message.side_effect = self._send_message
        self.prompts = []
        self.bot.get_file.return_value = types.SimpleNamespace(file_path="synthetic-input.hc")
        self.bot.download_file.return_value = hccfg_hwid_file(password=S4_SYNTHETIC_PASSWORD)
        self.sent = []
        self.bot.send_document.side_effect = lambda **kwargs: self.sent.append(kwargs["document"].read())
        settings = types.SimpleNamespace(
            admins={20, 21}, allowed_groups={-40}, allow_all_groups=False,
            decoder_timeout_seconds=20, max_file_size_bytes=16 * 1024 * 1024,
        )
        runtime = types.SimpleNamespace(bot=self.bot, settings=settings)
        self.runtime_patch = patch.dict(sys.modules, {"spdecode.runtime": runtime})
        self.runtime_patch.start()
        self.addCleanup(self.runtime_patch.stop)
        self.credentials = importlib.import_module("spdecode.handlers.decoder_credentials")
        self.documents = importlib.import_module("spdecode.handlers.documents")
        self.texts = importlib.import_module("spdecode.handlers.cloud_texts")
        bot_patch = patch.multiple(self.credentials, bot=self.bot, settings=settings)
        documents_patch = patch.multiple(self.documents, bot=self.bot, settings=settings)
        bot_patch.start()
        documents_patch.start()
        self.addCleanup(bot_patch.stop)
        self.addCleanup(documents_patch.stop)
        self.addCleanup(lambda: [self.credentials._remove(key) for key in list(self.credentials._pending)])

    def _send_message(self, chat_id, text, **kwargs):
        prompt = types.SimpleNamespace(
            message_id=100 + len(self.prompts), text=text,
            from_user=types.SimpleNamespace(is_bot=True),
        )
        self.prompts.append(prompt)
        return prompt

    def _message(self, *, user=20, group=False, password="", reply=None):
        return types.SimpleNamespace(
            chat=types.SimpleNamespace(id=-40 if group else 20, type="group" if group else "private"),
            from_user=types.SimpleNamespace(id=user),
            message_id=1, text=password, reply_to_message=reply,
            document=types.SimpleNamespace(file_name="synthetic.HC", file_id="test", file_size=200),
        )

    def test_locked_http_custom_never_asks_group_or_wrong_user_for_credentials(self):
        self.documents.process_received_file(self._message(group=True))
        self.assertEqual(self.prompts, [])
        self.assertFalse(self.sent)
        self.assertIn("chat privado", self.bot.reply_to.call_args.args[1])
        self.documents.process_received_file(self._message())
        prompt = self.prompts[-1]
        self.credentials.handle_credential_reply(self._message(user=21, password=SYNTHETIC_HWID, reply=prompt))
        self.assertFalse(self.sent)
        self.assertEqual(len(self.prompts), 1)

    def test_dual_http_custom_delivers_on_original_document_without_echoing_credentials(self):
        self.documents.process_received_file(self._message())
        prompt = self.prompts[-1]
        self.assertIn("HWID", prompt.text)
        reply = self._message(password=SYNTHETIC_HWID, reply=prompt)
        self.assertTrue(self.credentials._is_credential_reply(reply))
        self.credentials.handle_credential_reply(reply)
        self.assertIn("contraseña", self.prompts[-1].text)
        self.credentials.handle_credential_reply(
            self._message(password=S4_SYNTHETIC_PASSWORD, reply=self.prompts[-1])
        )
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(json.loads(self.sent[0])["config"][0]["host"], "example.org")
        self.assertEqual(self.bot.send_document.call_args.kwargs["reply_to_message_id"], 1)
        self.assertFalse(self.credentials._pending)
        # The fake no-op Telegram calls retain passed Message objects, so
        # check displayed text separately rather than their object reprs.
        displayed = [call.args[1] for method in (self.bot.send_message, self.bot.reply_to)
                     for call in method.call_args_list]
        self.assertTrue(all(SYNTHETIC_HWID not in text and S4_SYNTHETIC_PASSWORD not in text for text in displayed))

    def test_new_text_handler_and_existing_fallback(self):
        from telebot.handler_backends import ContinueHandling

        fixture = Path(__file__).with_name("golden") / "xveon_vectors.json"
        decoded = json.loads(fixture.read_text())
        text = encrypt_envelope(decoded)
        self.texts.decode_cloud_text(self._message(password=text))
        self.assertIn("example.test", self.bot.reply_to.call_args.args[1])
        fallback = self.texts.decode_cloud_text(self._message(password="wyrvpn://invalid"))
        self.assertIsInstance(fallback, ContinueHandling)

    def test_cancel_drops_pending_and_late_reply_is_consumed(self):
        original = self._message()
        self.documents.process_received_file(original)
        prompt = self.prompts[-1]
        self.assertTrue(self.credentials.cancel_pending_credentials(original))
        late = self._message(password=SYNTHETIC_HWID, reply=prompt)
        self.assertTrue(self.credentials._is_credential_reply(late))
        self.credentials.handle_credential_reply(late)
        self.assertFalse(self.sent)


if __name__ == "__main__":
    unittest.main()
