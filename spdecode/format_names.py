"""Public names for the Telegram bot's format lists and results."""
from __future__ import annotations

import json
import re

from spdecode.decoder_runtime import FILE_FORMATS

_FAMILY_APP_NAMES = {
    "7net": "7NET VPN",
    "actunnelvpn": "AC Tunnel VPN",
    "aloplusvpn": "Alo Plus VPN",
    "bshield": "BShield",
    "cranetunnel": "Crane Tunnel",
    "deshtunnelvpn": "Desh Tunnel VPN",
    "gcpvpn": "GCP VPN",
    "hamotunnelplus": "Hamo Tunnel Plus",
    "letsvpngo": "Lets VPN Go",
    "mhrtunnel": "MHR Tunnel",
    "safetunnel": "Safe Tunnel",
    "tcxtunnel": "TCx Tunnel Plus",
    "vipsnipherpro": "VIP Snipher Pro",
    "xhypher": "Xhypher Tunnel Pro",
}
_FAMILY_LINK_ALIASES = {
    "ihome://": "IHome VPN",
    "ihomevpn://": "IHome VPN",
    "osp://": "OSP Tunnel",
    "osptunnel://": "OSP Tunnel",
}
_NAME_ALIASES = {
    "ac tunnel vpn": "AC Tunnel VPN",
    "npv tunnel npvs v5": "NPV Tunnel",
    "npv tunnel v2": "NPV Tunnel",
    "npv tunnel v4": "NPV Tunnel",
    "npv tunnel v5": "NPV Tunnel",
    "npvs": "NPV Tunnel",
    "npvs1 legacy values": "NPV Tunnel",
    "npvt ssh": "NPV Tunnel",
    "netmod": "NetMod Syna",
    "netmodsyna xray json": "NetMod Syna",
    "nur tunnel vpn (.solid)": "NUR Tunnel",
    "slipnet base64": "SlipNet",
    "slipnet enc": "SlipNet",
    "zivpn": "ZiVPN Tunnel",
    "zi vpn": "ZiVPN Tunnel",
}
_METHOD_NAME = re.compile(
    r"\b(?:aes|des|gcm|cbc|ecb|pbkdf2|chacha20|hmac|hkdf|rsa|xor|rc4|xxtea)\b", re.IGNORECASE,
)
_VERSION = re.compile(r"\s+(?:v?\d+\.\d+[^\s/]*|build \d+)(?=\s*(?:/|$))", re.IGNORECASE)


def public_format_name(name: str) -> str | None:
    alias = _NAME_ALIASES.get(name.casefold())
    if alias is not None:
        return alias
    if name.casefold().startswith(("generic ", "renz /")) or _METHOD_NAME.search(name):
        return None
    return _VERSION.sub("", name).strip()


def file_application_name(extension: str) -> str | None:
    name = FILE_FORMATS[extension]["name"]
    if name.startswith("RENZ /"):
        return _FAMILY_APP_NAMES.get(extension)
    return public_format_name(name)


def family_text_application(prefix: str, variant: str) -> str:
    return _FAMILY_LINK_ALIASES.get(prefix) or _FAMILY_APP_NAMES.get(variant, prefix)


def public_result_output(output: str, application: str) -> str:
    """Replace the family decoder's generated label, preserving the config."""
    if "RENZ / " not in output:
        return output
    try:
        result = json.loads(output)
    except (ValueError, RecursionError):
        return output
    if not isinstance(result, dict) or "config" not in result:
        return output
    label = result.get("application")
    if not isinstance(label, str) or not label.startswith("RENZ / "):
        return output
    result["application"] = application
    return json.dumps(result, ensure_ascii=False, indent=2)
