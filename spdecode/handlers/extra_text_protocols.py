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


def _stlray_text(value):
    # STLRAY 1.1.36 (TVC codec): sray://, tvc://, uv://, gv://, gpx://,
    # insan://, opq://, test:// — the scheme selects the key; hyb:// has
    # no own key and falls back to the sray:// key (handled inside
    # decode_link). Verified MATCH exacto on sray://, sray:// locked and
    # tvc:// links in the batch report.
    from decoders.Python.apps.STLRAY.file_decoder import decode_text
    return decode_text(value)


def _sni_v2rc_text(value):
    # SNI Tunnel 1.3.7: v2rc://<sealed> — sealed link, device record
    # first, else the app-open record; password layer via PBKDF2 +
    # ChaCha20-Poly1305. The adapter raises with code
    # PASSWORD_REQUIRED when the config is sealed and no password was
    # given; the bot has no password prompt for text links yet (same
    # as NadiaVPN below), so that case is answered in decode_extra_text.
    from decoders.Python.apps.SNI_Tunnel.file_decoder import decode_text
    return decode_text(value)


def _dgm_text(value):
    # DGM Tunnel 15.11.2026: dgmtunnel://<base64url JSON> — TunnelConfig
    # or DarkTunnel node form, or dgmtunnel://share/ sealed
    # DGMTUNNEL_SHARE v2 envelope. darktunnel:// itself is NOT wired
    # here: the Dark Tunnel handler already decodes the same node form.
    from decoders.Python.apps.DGM_Tunnel.file_decoder import decode_text
    return decode_text(value)


def _surya_text(value):
    # Surya Tunnel 1.6: SVPN1:/SVPN2:/SVPN3:/SVPN4: text shares.
    # A protected SVPN3:/SVPN4: share without a password raises with
    # code PASSWORD_REQUIRED; answered in decode_extra_text like the
    # NadiaVPN case (no password prompt for text links yet).
    from decoders.Python.apps.Surya_Tunnel.file_decoder import decode_text
    return decode_text(value)


def _xtravpn_text(value):
    # XtraVPN 1.0.36: xtravpn://<blob> — encrypted config blob, B0 key
    # (XtravpnMainActivity.x() accepts text starting with xtravpn://).
    # Landed module has run(data=blob) -> dict, no decode_text yet.
    import json as _json

    from decoders.Python.apps.XtraVPN.XtraVPN import run as _xtravpn_run
    blob = value.strip()
    if blob.lower().startswith("xtravpn://"):
        blob = blob[len("xtravpn://"):]
    blob = "".join(blob.split())
    return _json.dumps(_xtravpn_run(data=blob), ensure_ascii=False)


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
    "sray://": ("STLRAY", _stlray_text),
    "tvc://": ("STLRAY", _stlray_text),
    "uv://": ("STLRAY", _stlray_text),
    "gv://": ("STLRAY", _stlray_text),
    "gpx://": ("STLRAY", _stlray_text),
    "insan://": ("STLRAY", _stlray_text),
    "opq://": ("STLRAY", _stlray_text),
    "test://": ("STLRAY", _stlray_text),
    "hyb://": ("STLRAY", _stlray_text),
    "xtravpn://": ("XtraVPN", _xtravpn_text),
    "v2rc://": ("SNI Tunnel", _sni_v2rc_text),
    "dgmtunnel://": ("DGM Tunnel", _dgm_text),
    "svpn1:": ("Surya Tunnel", _surya_text),
    "svpn2:": ("Surya Tunnel", _surya_text),
    "svpn3:": ("Surya Tunnel", _surya_text),
    "svpn4:": ("Surya Tunnel", _surya_text),
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
            if label == "NadiaVPN":
                bot.reply_to(
                    message,
                    "Este enlace NadiaVPN tiene contraseña. El bot todavía "
                    "no puede pedir contraseñas para enlaces de texto; el "
                    "descifrado con contraseña por texto queda pendiente.",
                )
            else:
                bot.reply_to(
                    message,
                    f"Este enlace {label} tiene contraseña. El bot todavía "
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
