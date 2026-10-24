"""CREEB VPN 50.0: app-derived, contextual XXTEA (delta -1703701580)."""
from __future__ import annotations
import base64
import json
import math
from pathlib import Path
import sys

# Reuse the historical integer/framing primitive; no duplicated cipher engine.
if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from decoders.Python.crev import crev_xxtea_decrypt

MAX_BYTES = 8 * 1024 * 1024
OUTER_KEY = b"DEV_CREEB"
SERVER_KEY = "ᜀᜎᜊᜌᜁᜈᜂ".encode("utf-8")
SERVER_FIELDS = (
    "ServerIP", "ServerUser", "ServerPass", "ProxyIP", "Cloud", "Slowchave",
    "Nameserver", "V2RAY_URI", "UDPServer", "WireGuardConfig",
)
TWEAK_FIELDS = ("Payload", "CHost", "SNI", "DNSHost", "V2RAY_JSON", "V2RAY", "V2RAY_SNI", "V2RAY_URI")


class DecodeError(ValueError):
    """Sanitized errors; never include configuration values."""


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise DecodeError("Claves JSON duplicadas.")
        obj[key] = value
    return obj


def _invalid(_):
    raise DecodeError("Número JSON no finito.")


def _json(text):
    try:
        obj = json.loads(text, object_pairs_hook=_unique, parse_constant=_invalid)
        pending = [(obj, 0)]
        count = 0
        while pending:
            value, depth = pending.pop()
            count += 1
            if depth > 64 or count > 1_000_000:
                raise DecodeError("JSON demasiado complejo.")
            if isinstance(value, dict):
                pending.extend((x, depth + 1) for x in value.keys())
                pending.extend((x, depth + 1) for x in value.values())
            elif isinstance(value, list):
                pending.extend((x, depth + 1) for x in value)
            elif isinstance(value, str):
                value.encode("utf-8")
            elif isinstance(value, float) and not math.isfinite(value):
                raise DecodeError("Número JSON no finito.")
        return obj
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("JSON incompatible.") from exc


def decrypt_text(text: str, key: bytes) -> str:
    if not isinstance(text, str):
        raise DecodeError("Campo cifrado incompatible.")
    if text == "":  # ge6.g returns the empty input unchanged.
        return ""
    try:
        # Only ASCII Base64 whitespace, no URI stripping or guessed keys.
        packed = text.translate(str.maketrans("", "", " \r\n\t"))
        raw = base64.b64decode(packed, validate=True)
        if len(raw) < 8 or len(raw) % 4:
            raise ValueError
        plain = crev_xxtea_decrypt(raw, key)
        if plain is None:
            raise ValueError
        return plain.decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("XXTEA, longitud o UTF-8 inválidos.") from exc


def decode(data: bytes, *, catalog: bool = False) -> dict:
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Entrada vacía o superior a 8 MiB.")
    try:
        text = data.decode("utf-8-sig").strip()
        # MainActivity's import path explicitly accepts direct JSON as fallback.
        obj = _json(text if text.startswith("{") else decrypt_text(text, OUTER_KEY))
        if not isinstance(obj, dict):
            raise ValueError
        sections = [key for key in ("Servers", "Tweaks") if key in obj]
        if not sections or not any(obj[key] for key in sections):
            raise ValueError
        if "Security" in obj and not isinstance(obj["Security"], dict):
            raise ValueError
        if catalog and (set(sections) != {"Servers", "Tweaks"} or not isinstance(obj.get("Version"), str)):
            raise ValueError
        for section in sections:
            rows = obj[section]
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise ValueError
            for row in rows:
                if section == "Servers":
                    fields, key = SERVER_FIELDS, SERVER_KEY
                else:
                    info = row.get("pInfo", "")
                    if not isinstance(info, str):
                        raise ValueError
                    # zv.h0: substring match, case-sensitive. Catalog != custom.
                    fields = TWEAK_FIELDS
                    key = OUTER_KEY if "Custom Tweak" in info else SERVER_KEY
                for field in fields:
                    if field in row and row[field] is not None:
                        row[field] = decrypt_text(row[field], key)
        return obj
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise DecodeError("No se pudo descifrar el documento CREEB VPN completo.") from exc


def render(obj: dict) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
