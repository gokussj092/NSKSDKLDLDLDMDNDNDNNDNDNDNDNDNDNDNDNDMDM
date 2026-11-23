"""Telegram message handlers for authorized 66.py configuration protocol batches.

Runs the same standalone Python decoders used by bot file imports. Never
executes scripts from Telegram text, fetches URLs or leaks private RSA keys.
"""
from __future__ import annotations

import logging

from decoders.Python import (
    eut, falcon_links, happ_links, intvpn, izph, juanscript, npvt_links,
    slipnet, wyrvpn, wyrlite, xor_family,
)
from decoders.Python.HTTPTWEAK import run as decode_http_tweak
from spdecode.access import require_authorized
from spdecode.handlers.results import send_markdown_result
from spdecode.runtime import bot

logger = logging.getLogger("sp-decode")

TEXT_HANDLERS = {
    **{p: ("HAPP", happ_links.decode_text) for p in happ_links.SCHEMES},
    **{p: ("XOR VPN", xor_family.decode_text) for p in xor_family.SCHEMES},
    "falcontunnel://import/": ("Falcon Tunnel", falcon_links.decode_text),
    "npvt-ssh://": ("NPVT SSH", npvt_links.decode_text),
    "dns://": ("DNS JSON", npvt_links.decode_text),
    "npvs1:": ("NPVS1 legacy values", npvt_links.decode_text),
    "slipnet-enc://": ("SlipNet ENC", lambda s: slipnet.run(s.encode("utf-8"))),
    "slipnet://": ("SlipNet", lambda s: slipnet.run(
        ("slipnet-enc://"+s.split("://",1)[1]).encode("utf-8"))),
    "wyrlite://": ("WyrLite", lambda s: wyrlite.run(s.encode("utf-8"))),
    "wyrvpnlite://": ("WyrLite", lambda s: wyrlite.run(s.encode("utf-8"))),
    "wyrl://": ("WyrLite", lambda s: wyrlite.run(s.encode("utf-8"))),
    "wyrvpn://": ("WyrVPN", lambda s: wyrvpn.run(s.encode("utf-8"))),
    "intvpn://": ("IntVPN", lambda s: intvpn.run(s.encode("utf-8"))),
    "juanscript://": ("JuanScript", lambda s: juanscript.run(s.encode("utf-8"))),
    "mobi://": ("JuanScript", lambda s: juanscript.run(s.encode("utf-8"))),
    "eut-settings://": ("EUT Settings", lambda s: eut.run(s.encode("utf-8"))),
    "httptweak://": ("HTTP Tweak", lambda s: decode_http_tweak(s.encode("utf-8"))),
    "izph://": ("IZPH VPN Pro", lambda s: izph.run(s.encode("utf-8"))),
    "izphvpnpro://": ("IZPH VPN Pro", lambda s: izph.run(s.encode("utf-8"))),
}
_PREFIXES = tuple(sorted(TEXT_HANDLERS, key=len, reverse=True))


def _match(message):
    value = getattr(message, "text", "") or ""
    if not isinstance(value,str) or len(value)>2*1024*1024:
        return None
    text=value.strip()
    return next((p for p in _PREFIXES if text.lower().startswith(p)),None)


@bot.message_handler(func=lambda message: _match(message) is not None)
@require_authorized("Los textos de configuraciones VPN")
def decode_config_batch_text(message):
    text=(getattr(message,"text","") or "").strip()
    prefix=_match(message)
    if prefix is None:
        return
    name, decoder=TEXT_HANDLERS[prefix]
    try:
        output=decoder(text)
        if isinstance(output,(dict,list)):
            import json
            output=json.dumps(output,ensure_ascii=False,indent=2)
        if not output:
            if prefix.startswith("happ://"):
                bot.reply_to(message, "HAPP: no se pudo descifrar. Comprueba las claves RSA privadas configuradas en el servidor.")
            else:
                bot.reply_to(message, "No se pudo descifrar la configuración con este formato.")
            return
        send_markdown_result(message, name, str(output))
    except Exception:
        logger.exception("Configuration text decoding failed for %s",prefix)
        bot.reply_to(message,"Error interno al descifrar la configuración.")


# ---------------------------------------------------------------------------
# Password-protected V2Box exports: short-lived reply workflow in the original chat.
# No extra commands and no persistence or logging of the user password.
# ---------------------------------------------------------------------------
def prompt_v2box_password(message, encrypted: bytes) -> None:
    from spdecode.handlers.decoder_credentials import decode_and_reply

    decode_and_reply(
        message, encrypted, suffix="v2box",
        deliver=lambda result: send_markdown_result(message, "V2Box", result.text, partial=result.partial),
    )
