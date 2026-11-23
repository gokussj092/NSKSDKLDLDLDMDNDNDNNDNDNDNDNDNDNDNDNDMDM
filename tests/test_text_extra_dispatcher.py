"""Registration and authorization-boundary tests for additional text handlers."""
from __future__ import annotations

import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from decoders.Python import text_legacy_protocols as legacy
from decoders.Python import text_structured_protocols as structured

ROOT=Path(__file__).resolve().parents[1]


class FakeBot:
    def __init__(self):
        self.handlers=[]
        self.replies=[]

    def message_handler(self, func=None, **kwargs):
        def decorate(callback):
            self.handlers.append((func,callback))
            return callback
        return decorate

    def reply_to(self, message, text, **kwargs):
        self.replies.append((message,text,kwargs))


def load_handler_with_fake_bot():
    bot=FakeBot()
    module=types.ModuleType("spdecode.runtime")
    module.bot=bot
    # No live Telegram token is required to load the handler.
    with patch.dict(sys.modules,{"spdecode.runtime":module}):
        path=ROOT/"spdecode/handlers/extra_text_protocols.py"
        spec=importlib.util.spec_from_file_location("_spdecode_test_extra_texts",path)
        imported=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(imported)
    return imported,bot


class ExtraTextDispatcherTests(unittest.TestCase):
    def test_registry_has_every_source_additional_protocol(self):
        handler, bot=load_handler_with_fake_bot()
        needed=set(legacy.ALL_PREFIXES)|set(structured.PREFIXES)
        self.assertTrue(needed.issubset(handler.PROTOCOL_HANDLERS))
        self.assertEqual(len(handler.PROTOCOL_HANDLERS),len(needed))
        self.assertEqual(len(bot.handlers),1)
        self.assertTrue(hasattr(bot.handlers[0][1],
                                "__spdecode_requires_authorization__"))
        self.assertEqual(
            handler._match(types.SimpleNamespace(text="Mark://abc")),
            "mark://",
        )
        self.assertEqual(
            handler._match(types.SimpleNamespace(text='{"type":"creeb_profile_bundle","profiles":[]}')),
            "__creeb__",
        )
        self.assertIsNone(
            handler._match(types.SimpleNamespace(text="unrelated regular text")),
        )

    def test_handler_import_is_prioritized_before_legacy_handler(self):
        source=(ROOT/"main.py").read_text(encoding="utf-8")
        self.assertLess(source.index("import extra_text_protocols as _extra_text_protocols"),
                        source.index("import text_protocols as _text_protocols"))
        self.assertLess(source.index("import extra_text_protocols as _extra_text_protocols"),
                        source.index("import config_batch_texts as _config_batch_texts"))
        self.assertLess(source.index("import extra_text_protocols as _extra_text_protocols"),
                        source.index("import fallback as _fallback"))

    def test_authorized_handler_cannot_bypass_central_access(self):
        handler,bot=load_handler_with_fake_bot()
        message=types.SimpleNamespace(
            text="vmess://"+__import__("base64").b64encode(
                b'{"add":"example.net","port":"443"}').decode(),
            chat=types.SimpleNamespace(id=123,type="private"),
            from_user=types.SimpleNamespace(id=123),
        )
        fake_settings=types.SimpleNamespace(
            admins=frozenset({999}), allowed_groups=frozenset(),
            allow_all_groups=False, allowed_private_users=frozenset(),
        )
        fake_runtime=types.SimpleNamespace(bot=bot,settings=fake_settings)
        with patch.dict(sys.modules,{"spdecode.runtime":fake_runtime}):
            handler.decode_extra_text(message)
        self.assertEqual(len(bot.replies),1)
        self.assertIn("Acceso no autorizado",bot.replies[0][1])
        self.assertNotIn("example.net",bot.replies[0][1])

    def test_authorized_handler_preserves_full_payload_and_escapes_html(self):
        handler,bot=load_handler_with_fake_bot()
        content=json.dumps({"name":"<server>","port":443,"password":"fixture-only"})
        message=types.SimpleNamespace(
            text="vmess://"+__import__("base64").b64encode(content.encode()).decode(),
            chat=types.SimpleNamespace(id=999,type="private"),
            from_user=types.SimpleNamespace(id=999),
        )
        fake_settings=types.SimpleNamespace(
            admins=frozenset({999}), allowed_groups=frozenset(),
            allow_all_groups=False, allowed_private_users=frozenset(),
        )
        fake_runtime=types.SimpleNamespace(bot=bot,settings=fake_settings)
        with patch.dict(sys.modules,{"spdecode.runtime":fake_runtime}):
            handler.decode_extra_text(message)
        self.assertEqual(len(bot.replies),1)
        self.assertIn("&lt;server&gt;",bot.replies[0][1])
        self.assertIn("fixture-only",bot.replies[0][1])
        self.assertEqual(bot.replies[0][2].get("parse_mode"),"HTML")

    def test_v2box_password_prompt_normalizes_base64url(self):
        import base64
        handler, bot = load_handler_with_fake_bot()
        envelope = {
            "magic": "v2box_export",
            "nonce": "MDEyMzQ1Njc4OTAx",
            "tag": "MTIzNDU2Nzg5MDEyMzQ1Ng==",
            "ciphertext": "Y2lwaGVydGV4dA==",
            "isPasswordProtected": True,
        }
        token = base64.urlsafe_b64encode(json.dumps(envelope).encode()).decode().rstrip("=")
        msg = types.SimpleNamespace(
            text="v2box://" + token,
            chat=types.SimpleNamespace(id=999,type="private"),
            from_user=types.SimpleNamespace(id=999))
        settings = types.SimpleNamespace(
            admins={999},allowed_groups=set(),allow_all_groups=False)
        runtime = types.SimpleNamespace(bot=bot,settings=settings)
        calls = []
        stub = types.ModuleType("spdecode.handlers.config_batch_texts")
        stub.prompt_v2box_password = lambda m, data: calls.append(data)
        with patch.dict(sys.modules,{
            "spdecode.runtime":runtime,
            "spdecode.handlers.config_batch_texts":stub}):
            handler.decode_extra_text(msg)
        self.assertEqual(len(calls),1)
        self.assertEqual(json.loads(calls[0]),envelope)

    def test_oversized_text_rejected_before_decode(self):
        handler,_bot=load_handler_with_fake_bot()
        self.assertIsNone(handler._match(types.SimpleNamespace(
            text="howdy://"+"A"*(2*1024*1024+1))))
        self.assertIsNone(handler._match(types.SimpleNamespace(text=None)))


if __name__=="__main__":
    unittest.main()
