"""Telegram entry point for locally processed text formats shared with Cloud."""
from __future__ import annotations

from telebot.handler_backends import ContinueHandling

from spdecode.access import require_authorized
from spdecode.decoder_runtime import TEXT_FORMATS, text_prefix
from spdecode.format_names import public_format_name
from spdecode.handlers.decoder_credentials import decode_and_reply
from spdecode.handlers.results import send_markdown_result
from spdecode.runtime import bot


# Some historical Telegram exports have alternate envelopes. Preserve their
# existing handlers on a plain decode failure, never on a protection error.
_LEGACY_PREFIXES = {
    "dns://", "npvs1:", "npvt-ssh://", "falcontunnel://import/", "vmess://",
    "flex://", "flexnet://", "nm-xray-json://", "zivpn://", "httptweak://",
    "wyrlite://", "wyrvpnlite://", "wyrl://", "wyrvpn://", "intvpn://",
    "slipnet-enc://", "juanscript://", "mobi://", "eut-settings://",
    "izph://", "izphvpnpro://", "hamaratnl://", "bdnet://",
}


def _match(message) -> str | None:
    text = getattr(message, "text", None)
    return text_prefix(text) if isinstance(text, str) else None


@bot.message_handler(func=lambda message: _match(message) is not None)
@require_authorized
def decode_cloud_text(message):
    prefix = _match(message)
    if prefix is None:
        return ContinueHandling()
    label = public_format_name(TEXT_FORMATS[prefix]) or prefix
    if not decode_and_reply(
        message,
        message.text.strip().encode("utf-8"),
        suffix=None,
        deliver=lambda result: send_markdown_result(message, label, result.text, partial=result.partial),
        legacy_text_fallback=prefix in _LEGACY_PREFIXES,
    ):
        return ContinueHandling()
