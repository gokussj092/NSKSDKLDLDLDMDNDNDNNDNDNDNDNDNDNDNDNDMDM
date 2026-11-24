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
from spdecode.decoder_runtime import FILE_FORMATS, TEXT_FORMATS, DecodeResult, decode, file_suffix, text_prefix
from spdecode.handlers.results import send_markdown_result
from spdecode.registry import DECODER_REGISTRY
from tests.golden.a23_generators import (
    FIXTURE_DOMAIN, SYNTHETIC_GENERATORS, dark_bytes, httpcustom_bytes, ssc_bytes, tls_bytes,
)
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
    @classmethod
    def setUpClass(cls):
        cls.tls_fixture = tls_bytes()
        cls.dark_fixture = dark_bytes()
        cls.legacy_fixtures = {
            "mij": SYNTHETIC_GENERATORS["batch4-mij"](),
            "mrc": SYNTHETIC_GENERATORS["batch5-mrc"](),
            "mtl": SYNTHETIC_GENERATORS["batch5-mtl"](),
            "gold": SYNTHETIC_GENERATORS["batch7-gold"](),
            "ssh": SYNTHETIC_GENERATORS["batch8-ssh"](),
        }

    def setUp(self):
        self.bot = Mock()
        self.bot.message_handler.side_effect = lambda **kwargs: lambda fn: fn
        self.bot.reply_to.side_effect = self._reply_to
        self.prompts = []
        self.bot.get_file.return_value = types.SimpleNamespace(file_path="synthetic-input.hc")
        self.bot.download_file.return_value = hccfg_hwid_file(password=S4_SYNTHETIC_PASSWORD)
        self.sent = []
        self.bot.send_document.side_effect = lambda **kwargs: self.sent.append(
            (kwargs["document"].name, kwargs["document"].read().decode("utf-8"))
        )
        settings = types.SimpleNamespace(
            admins={20, 21}, allowed_groups={-40}, allow_all_groups=False, allowed_private_users=set(),
            decoder_timeout_seconds=20, max_file_size_bytes=16 * 1024 * 1024,
            text_session_timeout_seconds=600, text_session_max_chars=250000,
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

    def _reply_to(self, original, text, **kwargs):
        reply = types.SimpleNamespace(
            message_id=100 + len(self.prompts), text=text,
            chat=original.chat, message_thread_id=kwargs.get("message_thread_id"),
            from_user=types.SimpleNamespace(id=99, is_bot=True),
        )
        if text.startswith(self.credentials._PROMPT):
            self.prompts.append(reply)
            self.assertEqual(original.chat.id, reply.chat.id)
            self.assertEqual(getattr(original, "message_thread_id", None), reply.message_thread_id)
        return reply

    def _message(self, *, user=20, group=False, password="", reply=None, thread=None, message_id=1):
        return types.SimpleNamespace(
            chat=types.SimpleNamespace(id=-40 if group else user, type="supergroup" if group else "private"),
            from_user=types.SimpleNamespace(id=user),
            message_thread_id=thread, message_id=message_id, text=password, reply_to_message=reply,
            date=1763897400,
            document=types.SimpleNamespace(file_name="synthetic.HC", file_id="test", file_size=200),
        )

    def test_group_credentials_are_bound_to_author_chat_and_topic(self):
        original = self._message(user=22, group=True, thread=50)
        self.documents.process_received_file(original)
        prompt = self.prompts[-1]
        self.assertIs(self.bot.reply_to.call_args.args[0], original)
        self.assertTrue(self.bot.reply_to.call_args.kwargs["reply_markup"].selective)
        self.credentials.handle_credential_reply(
            self._message(user=21, group=True, thread=50, password=SYNTHETIC_HWID, reply=prompt)
        )
        same_chat_replies = self.bot.reply_to.call_count
        self.credentials.handle_credential_reply(
            self._message(user=22, group=True, thread=51, password=SYNTHETIC_HWID, reply=prompt)
        )
        self.credentials.handle_credential_reply(
            self._message(user=20, password=SYNTHETIC_HWID, reply=prompt)
        )
        self.assertEqual(self.bot.reply_to.call_count, same_chat_replies)
        self.assertFalse(self.sent)
        self.assertEqual(len(self.prompts), 1)
        self.bot.send_message.assert_not_called()

    def test_dual_http_custom_delivers_on_original_group_document_without_echoing_credentials(self):
        original = self._message(user=22, group=True, thread=50)
        original.document.file_name = "My+profile.v2 (ñ).HC"
        original.from_user.username = "file_author"
        self.documents.process_received_file(original)
        prompt = self.prompts[-1]
        self.assertIn("HWID", prompt.text)
        reply = self._message(user=22, group=True, thread=50, password=SYNTHETIC_HWID, reply=prompt)
        self.assertTrue(self.credentials._is_credential_reply(reply))
        self.credentials.handle_credential_reply(reply)
        self.assertIn("password", self.prompts[-1].text)
        self.assertIs(self.bot.reply_to.call_args.args[0], original)
        self.credentials.handle_credential_reply(
            self._message(user=22, group=True, thread=50, password=S4_SYNTHETIC_PASSWORD, reply=original)
        )
        self.assertEqual(len(self.sent), 1)
        filename, report = self.sent[0]
        self.assertEqual(filename, "My+profile.v2 (ñ).md")
        header, _, payload = report.partition("\n```json\n")
        self.assertIn("**Application:** HTTP Custom", header)
        self.assertIn("**Sent by:** [@file_author](https://t.me/file_author)", header)
        self.assertIn("**Sent at:** 2025-11-23 11:30:00 UTC", header)
        self.assertIn("**Original file:** My+profile.v2 (ñ).HC", header)
        self.assertEqual(json.loads(payload.removesuffix("```\n"))["config"][0]["host"], "example.org")
        sent = self.bot.send_document.call_args.kwargs
        self.assertEqual((sent["chat_id"], sent["message_thread_id"], sent["reply_to_message_id"]), (-40, 50, 1))
        self.assertIn("Application: HTTP Custom\nSent by: @file_author\nSent at: 2025-11-23 11:30:00 UTC", sent["caption"])
        self.assertFalse(self.credentials._pending)
        self.bot.send_message.assert_not_called()
        displayed = [call.args[1] for call in self.bot.reply_to.call_args_list]
        self.assertTrue(all(SYNTHETIC_HWID not in text and S4_SYNTHETIC_PASSWORD not in text for text in displayed))

    def test_numbered_http_custom_files_preserve_the_copy_number(self):
        self.bot.download_file.return_value = wire(CASES["build564-hwid0"], 1)
        for index, separator in enumerate((" ", ""), 1):
            filename = f"file_example.HC{separator}(1)"
            with self.subTest(filename=filename):
                original = self._message(message_id=index)
                original.document.file_name = filename
                self.documents.process_received_file(original)
                result_name, report = self.sent[-1]
                self.assertEqual(result_name, f"file_example{separator}(1).md")
                self.assertIn(f"**Original file:** file\\_example.HC{separator}(1)", report)
                self.assertIn("\n```json\n", report)
        self.assertEqual(len(self.sent), 2)
        self.bot.reply_to.assert_not_called()

    def test_legacy_http_custom_document_has_one_formatted_json_object(self):
        self.bot.download_file.return_value = httpcustom_bytes()
        self.documents.process_received_file(self._message())

        self.assertEqual(len(self.sent), 1)
        filename, report = self.sent[0]
        header, _, payload = report.partition("\n```json\n")
        self.assertEqual(filename, "synthetic.md")
        self.assertIn("**Application:** HTTP Custom", header)
        self.assertNotIn("│[۞]", report)
        self.assertNotIn("bit.ly", report)
        self.assertIn('\n  "Config": {\n', payload)
        self.assertEqual(json.loads(payload.removesuffix("```\n")), {
            "Protections": {},
            "Config": {
                "payload": "GET", "proxy": FIXTURE_DOMAIN,
                "lockAllConfig": "false", "blockedByRoot": "true", "expiryTime": "0",
            },
        })

    def test_tls_tunnel_file_and_link_have_the_same_json(self):
        text_protocols = importlib.import_module("spdecode.handlers.text_protocols")
        self.bot.download_file.return_value = self.tls_fixture
        original = self._message()
        original.document.file_name = "profile.tls"
        self.documents.process_received_file(original)
        text_protocols.decode_tls_text(self._message(password=self.tls_fixture.decode()))

        self.assertEqual(len(self.sent), 2)
        configs = []
        for _, report in self.sent:
            _, _, payload = report.partition("\n```json\n")
            configs.append(json.loads(payload.removesuffix("```\n")))
        self.assertEqual(configs[0]["port"], 443)
        self.assertEqual(configs[0], configs[1])

    def test_additional_legacy_files_deliver_decoded_fields(self):
        for index, (suffix, sample) in enumerate(self.legacy_fixtures.items(), 1):
            with self.subTest(suffix=suffix):
                self.bot.download_file.return_value = sample
                message = self._message(message_id=index)
                message.document.file_name = f"profile.{suffix}"
                self.documents.process_received_file(message)
                self.assertEqual(len(self.sent), index)
                _, _, payload = self.sent[-1][1].partition("\n```json\n")
                result = json.loads(payload.removesuffix("```\n"))
                if suffix == "gold":
                    self.assertEqual(result["network"], {"Host": FIXTURE_DOMAIN, "Port": 443})
                else:
                    self.assertEqual(result["Host"], FIXTURE_DOMAIN)
                    self.assertEqual(result["Port"], "443")
                self.assertNotIn("𝗚𝗥𝗢𝗨𝗣", payload)
                self.assertNotIn("unlockKeys 🔽", payload)
        self.bot.reply_to.assert_not_called()

    def test_all_frozen_file_outputs_produce_structured_json(self):
        expected_dir = Path(__file__).with_name("golden") / "expected"
        for sample in sorted(expected_dir.glob("*.txt")):
            with self.subTest(sample=sample.name):
                send_markdown_result(self._message(), "Fixture", sample.read_text(encoding="utf-8"))
                _, _, payload = self.sent[-1][1].partition("\n```json\n")
                result = json.loads(payload.removesuffix("```\n"))
                self.assertIsInstance(result, (dict, list))
                if isinstance(result, dict):
                    self.assertNotEqual(set(result), {"text"})

    def test_boxed_properties_keep_json_entries_and_repeated_fields(self):
        output = (
            '┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.mij)\n├───────────────'
            '<entry key="route">{"host":"first.example","enabled":true}</entry>\n'
            '│[۞] route: {"host":"second.example","enabled":false}\n'
            '└───────────────\n'
        )
        send_markdown_result(self._message(), "MIJ Tunnel", output)
        _, _, payload = self.sent[0][1].partition("\n```json\n")
        self.assertEqual(json.loads(payload.removesuffix("```\n")), {
            "route": [
                {"host": "first.example", "enabled": True},
                {"host": "second.example", "enabled": False},
            ],
        })

    def test_ssh_command_delivers_structured_fields(self):
        text_protocols = importlib.import_module("spdecode.handlers.text_protocols")
        text = "/decssh example.org@encoded-user:encoded-password"
        with patch.object(text_protocols, "dec_ssh", side_effect=("test-user", "fixture-only")):
            text_protocols.dec_ssh_command(self._message(password=text))
        _, _, payload = self.sent[0][1].partition("\n```json\n")
        self.assertEqual(json.loads(payload.removesuffix("```\n")), {
            "IP address or domain": FIXTURE_DOMAIN,
            "Username": "test-user",
            "Password": "fixture-only",
            "SSH": "example.org@test-user:fixture-only",
        })

    def test_unsupported_file_and_decode_errors_are_silent(self):
        original = self._message()
        original.document.file_name = "file_example.unsupported (1)"
        self.documents.process_received_file(original)
        self.bot.get_file.assert_not_called()

        original.document.file_name = "file_example.hc"
        with patch.object(self.credentials, "decode", side_effect=DecodeFailure("DECODE_FAILED")):
            self.documents.process_received_file(original)
            self.texts.decode_cloud_text(self._message(password="xveon://broken"))

        self.assertFalse(self.sent)
        self.bot.reply_to.assert_not_called()

    def test_wrong_password_allows_silent_retry_to_same_prompt(self):
        original = self._message(password="xveon://synthetic")
        results = [
            DecodeFailure("PASSWORD_REQUIRED"), DecodeFailure("AUTH_FAILED"), DecodeResult('{"test": true}'),
        ]
        with patch.object(self.credentials, "decode", side_effect=results):
            self.texts.decode_cloud_text(original)
            prompt = self.prompts[0]
            self.credentials.handle_credential_reply(self._message(password="wrong", reply=prompt))
            self.assertFalse(self.sent)
            self.bot.reply_to.assert_called_once()
            self.credentials.handle_credential_reply(self._message(password="right", reply=prompt))
        self.assertEqual(len(self.sent), 1)
        self.assertFalse(self.credentials._pending)

    def test_ssc_and_dark_fragments_stay_silent_until_complete(self):
        text_protocols = importlib.import_module("spdecode.handlers.text_protocols")
        from spdecode.text_sessions import clear_session, get_session

        for protocol, prefix, payload, handler in (
            ("ssc", "ssc://", ssc_bytes()[::-1], text_protocols.decode_ssc_text),
            ("dark", "darktunnel://", self.dark_fixture, text_protocols.decode_dark_text),
        ):
            with self.subTest(protocol=protocol), patch.object(text_protocols, "settings", sys.modules["spdecode.runtime"].settings):
                first = self._message(password=prefix + payload[:12].decode(), message_id=1)
                second = self._message(password=payload[12:24].decode(), message_id=2)
                third = self._message(password=payload[24:].decode(), message_id=3)
                self.addCleanup(clear_session, first)
                before = len(self.sent)
                handler(first)
                handler(second)
                self.assertEqual(len(self.sent), before)
                self.assertEqual(get_session(first, 600).parts, 2)
                handler(third)
                self.assertEqual(len(self.sent), before + 1)
                _, _, payload_json = self.sent[-1][1].partition("\n```json\n")
                result = json.loads(payload_json.removesuffix("```\n"))
                if protocol == "ssc":
                    self.assertEqual(result["CONFIGS"][0]["ADDRESS"], FIXTURE_DOMAIN)
                else:
                    self.assertEqual(result["encryptedLockedConfig"]["Server"], FIXTURE_DOMAIN)
                self.assertIsNone(get_session(first, 600))
        self.bot.reply_to.assert_not_called()

    def test_multiple_pending_files_are_independent(self):
        first = self._message(group=True, message_id=1)
        second = self._message(group=True, message_id=2)
        self.documents.process_received_file(first)
        self.documents.process_received_file(second)
        self.assertEqual(len(self.credentials._pending), 2)
        cancel = self._message(group=True, password="/cancel", reply=first)
        self.assertFalse(self.credentials._is_credential_reply(cancel))
        restrict = self._message(group=True, password="/restrictgroups@SampleBot", reply=first)
        self.assertFalse(self.credentials._is_credential_reply(restrict))
        self.assertTrue(self.credentials.cancel_pending_credentials(cancel))
        reply = self._message(group=True, password=SYNTHETIC_HWID, reply=second)
        self.assertTrue(self.credentials._is_credential_reply(reply))
        self.credentials.handle_credential_reply(reply)
        self.assertIn("password", self.prompts[-1].text)
        self.assertEqual(len(self.credentials._pending), 1)

    def test_new_text_handler_and_existing_fallback(self):
        from telebot.handler_backends import ContinueHandling

        fixture = Path(__file__).with_name("golden") / "xveon_vectors.json"
        decoded = json.loads(fixture.read_text())
        text = encrypt_envelope(decoded)
        self.texts.decode_cloud_text(self._message(password=text))
        self.assertIn("example.test", self.sent[0][1])
        self.bot.reply_to.assert_not_called()
        fallback = self.texts.decode_cloud_text(self._message(password="wyrvpn://invalid"))
        self.assertIsInstance(fallback, ContinueHandling)

    def test_markdown_result_preserves_links_and_delimiters_and_identifies_the_request(self):
        original = self._message(user=22, group=True, thread=50)
        original.from_user.username = "test_sender"
        output = "  example.org\n```\nvmess://example\nhttps://example.invalid/?a=*\n"
        send_markdown_result(original, "7NET VPN", output, partial=True)
        filename, report = self.sent[0]
        self.assertEqual(filename, "7NET-VPN-spdecode-result.md")
        self.assertIn("**Application:** 7NET VPN", report)
        self.assertIn("**Sent by:** [@test_sender](https://t.me/test_sender)", report)
        self.assertIn("**Partial result.**", report)
        _, _, payload = report.partition("\n````json\n")
        self.assertEqual(json.loads(payload.removesuffix("````\n")), {"text": output})
        sent = self.bot.send_document.call_args.kwargs
        self.assertEqual((sent["chat_id"], sent["message_thread_id"], sent["reply_to_message_id"]), (-40, 50, 1))
        self.assertIn("Partial result", sent["caption"])
        self.assertEqual(
            [(button.text, button.url) for row in sent["reply_markup"].keyboard for button in row],
            [
                ("Channel", "https://t.me/GhostDeve"),
                ("Group", "https://t.me/CodeBreakersHub"),
                ("Ghost Developer", "https://t.me/Gh0stDeveloper"),
            ],
        )
        self.bot.reply_to.assert_not_called()

    def test_markdown_result_keeps_the_import_link_in_json(self):
        config = {"profiles": [{"port": 443}], "customJson": '{"routing": {"rules": []}}'}
        output = f"{json.dumps(config)}\n\nEncoded configuration:\nvmess://example"
        send_markdown_result(self._message(), "NetMod Syna", output)
        _, _, payload = self.sent[0][1].partition("\n```json\n")
        self.assertEqual(json.loads(payload.removesuffix("```\n")), {
            "config": config,
            "encodedConfiguration": "vmess://example",
        })

    def test_netmod_fallback_preserves_nested_json(self):
        fallback = importlib.import_module("spdecode.handlers.fallback")
        config = {"Common": [{"Server": "first.example"}, {"Server": "second.example"}], "Options": {"enabled": True}}
        message = self._message(password="dGVzdA==")
        with patch.object(fallback, "decrypt_aes_ecb_128", return_value=json.dumps(config).encode()):
            fallback.handle_message(message)
        _, _, payload = self.sent[0][1].partition("\n```json\n")
        self.assertEqual(json.loads(payload.removesuffix("```\n")), config)

    def test_family_result_uses_app_name_without_changing_decoded_config(self):
        original = self._message()
        data = {"application": "RENZ / ACTUNNELVPN", "config": {"note": "fixture content"}}
        send_markdown_result(original, "AC Tunnel VPN", json.dumps(data))
        filename, report = self.sent[0]
        self.assertEqual(filename, "AC-Tunnel-VPN-spdecode-result.md")
        self.assertIn("**Application:** AC Tunnel VPN", report)
        self.assertNotIn("RENZ /", report)
        _, _, payload = report.partition("\n```json\n")
        self.assertEqual(json.loads(payload.removesuffix("```\n")), {
            "application": "AC Tunnel VPN", "config": data["config"],
        })

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
