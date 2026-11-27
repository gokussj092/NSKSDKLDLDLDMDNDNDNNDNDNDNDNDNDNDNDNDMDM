"""Additional offline text-protocol handlers (66.py → modular SP-DECODE bot).

This module is imported BEFORE the legacy text handlers for a small set
of formats needing a correct source-based implementation. Existing SSC,
TLS, RENZ, IZPH, XOR, HAPP and other shared file/text decoders are
untouched and retain their own handlers.

Results use centralized authorization and Markdown attachments.
V2Box credential requests stay in the chat that received the original.
"""
from __future__ import annotations

import json
import logging
import re
from urllib.parse import parse_qs

from decoders.Python import text_legacy_protocols, text_structured_protocols
from spdecode.access import require_authorized
from spdecode.format_names import public_format_name
from spdecode.handlers.results import send_markdown_result
from spdecode.runtime import bot

logger = logging.getLogger("sp-decode")
MAX_TEXT_CHARS = 2 * 1024 * 1024


def _ar_text(value: str) -> str | None:
    result = text_legacy_protocols.decode_ar(value)
    if not result or not re.match(r"^[A-Za-z_][\w.-]*=", result):
        return result
    try:
        params = parse_qs(result, keep_blank_values=True, strict_parsing=True, errors="strict")
    except ValueError:
        return result

    profiles = params.get("profile", [])
    for index, profile in enumerate(profiles):
        if profile.lstrip().startswith(("{", "[")):
            try:
                profiles[index] = json.loads(profile)
            except (ValueError, RecursionError):
                pass
    return json.dumps({
        key: values[0] if len(values) == 1 else values for key, values in params.items()
    }, ensure_ascii=False)


def _nadia_text(value):
    # NadiaVPN 1.4.6 (FILE_ONLY, no catalog): nad://sec2: opens
    # directly; nad://pw2: without a password raises with code
    # PASSWORD_REQUIRED and is answered below, because the bot has no
    # password prompt for text links yet (only the V2Box one and the
    # file credential flow exist). No new flow is invented here.
    from decoders.Python.apps.NadiaVPN.file_decoder import decode_text
    return decode_text(value)


PROTOCOL_HANDLERS = {
    **{prefix: ("NetMod", text_legacy_protocols.decode_netmod)
       for prefix in text_legacy_protocols.NM_PREFIXES},
    **{prefix: ("AR Tunnel", _ar_text)
       for prefix in text_legacy_protocols.AR_PREFIXES},
    **{prefix: ("XrayPB", text_legacy_protocols.decode_pb)
       for prefix in text_legacy_protocols.PB_PREFIXES},
    **{prefix: ("Howdy VPN", text_legacy_protocols.decode_howdy)
       for prefix in text_legacy_protocols.HOWDY_PREFIXES},
    "zivpn://": ("ZI VPN", text_legacy_protocols.decode_zivpn),
    "flex://": ("FlexNet", text_structured_protocols.decode_flex),
    "flexnet://": ("FlexNet", text_structured_protocols.decode_flex),
    "npvs://": ("NPV Tunnel v5", text_structured_protocols.decode_npvs),
    "vpvs://": ("NPV Tunnel v5", text_structured_protocols.decode_npvs),
    "v2box://": ("V2Box", text_structured_protocols.decode_v2box),
    "kivuvpn://": ("Kivu VPN", text_structured_protocols.decode_kivu),
    "slipnet://": ("SlipNet Base64", text_structured_protocols.decode_slipnet_plain),
    "vmess://": ("VMess", text_structured_protocols.decode_vmess),
    "nad://sec2:": ("NadiaVPN", _nadia_text),
    "nad://pw2:": ("NadiaVPN", _nadia_text),
    "nad://": ("NadiaVPN", _nadia_text),
}
_PREFIXES = tuple(sorted(PROTOCOL_HANDLERS, key=len, reverse=True))

def _mnr_text(value):
    from decoders.Python.apps.MNR_TUNNEL_PLUS import codec
    try:
        raw = codec.download_profile(value) if value.startswith(codec.REFERENCE_PREFIX) else value.encode('utf-8')
        return codec.render(codec.decode_profile(raw))
    except (OSError, ValueError):
        # Do not log urllib causes: they can contain the private download token.
        return None


def _match(message) -> str | None:
    value = getattr(message, "text", "") or ""
    if not isinstance(value,str) or not 0 < len(value) <= MAX_TEXT_CHARS:
        return None
    compact = value.strip().lower()
    from decoders.Python.apps.MNR_TUNNEL_PLUS.codec import is_profile_text
    if value.strip().startswith('mnrtunneludp://') or is_profile_text(value.strip()):
        return '__mnr__'
    prefix = next((item for item in _PREFIXES if compact.startswith(item)), None)
    if prefix is not None:
        return prefix
    return "__creeb__" if text_structured_protocols.is_creeb(value) else None


@bot.message_handler(func=lambda message: _match(message) is not None)
@require_authorized
def decode_extra_text(message):
    raw = (getattr(message, "text", "") or "").strip()
    prefix = _match(message)
    if prefix is None:
        return
    if prefix == "__mnr__":
        label, decoder = "MNR TUNNEL PLUS", _mnr_text
    elif prefix == "__creeb__":
        label, decoder = "Creeb Profile Bundle", text_structured_protocols.decode_creeb
    else:
        label, decoder = PROTOCOL_HANDLERS[prefix]
    try:
        result = decoder(raw)
        if isinstance(result, dict) and result.get("__need_password__"):
            from spdecode.handlers.config_batch_texts import prompt_v2box_password
            envelope = text_structured_protocols.normalize_v2box_envelope(raw)
            if envelope is None:
                return
            # Reuse the same normalized fields for the password prompt;
            # the original file decoder expects RFC4648 Base64.
            normalized = json.dumps(
                envelope, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
            prompt_v2box_password(message, normalized)
            return
        if isinstance(result, str) and result.strip():
            send_markdown_result(message, public_format_name(label) or prefix, result)
    except Exception as exc:
        code = getattr(exc, "code", None)
        if code == "PASSWORD_REQUIRED":
            bot.reply_to(
                message,
                "Este enlace NadiaVPN tiene contraseña. El bot todavía "
                "no puede pedir contraseñas para enlaces de texto; el "
                "descifrado con contraseña por texto queda pendiente.",
            )
            return
        if code in ("HWID_REQUIRED", "HWID_PASSWORD_REQUIRED"):
            bot.reply_to(
                message,
                "Este perfil NadiaVPN está bloqueado a un HWID. El bot "
                "todavía no puede descifrar perfiles con bloqueo HWID; "
                "queda pendiente.",
            )
            return
        logger.exception("Internal error decoding text format %s", prefix)
