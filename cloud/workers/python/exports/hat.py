"""HA Tunnel 1.7.1 open export layout, with complete connection preservation."""
from __future__ import annotations

import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from decoders.Python.apps.HA_Tunnel_Plus import hat_decoder as hat
from .lossless import parse, equal, replace_values, remove_member, put_member, _value_spans

PROTECTION_FLAGS = {"anti_sniff", "mobile_data", "block_root", "password", "id_lock", "expiry"}
PROTECTION_VALUES = {"password_value", "id_lock_value", "expiry_value"}


def _put_raw(raw: bytes, name: str, value: bytes) -> bytes:
    """Move a whole JSON value without rounding or respelling unknown tokens."""
    parse(value)
    document = parse(raw)
    text, spans = _value_spans(raw)
    if name in document:
        start, end = spans[(name,)]
        result = (text[:start] + value.decode("utf-8") + text[end:]).encode("utf-8")
    else:
        import json
        end = spans[()][1] - 1
        token = ("," if document else "") + json.dumps(name) + ":" + value.decode("utf-8")
        result = (text[:end] + token + text[end:]).encode("utf-8")
    parse(result)
    return result


def _profile(raw: bytes, field: str) -> bytes:
    text, spans = _value_spans(raw)
    start, end = spans[(field,)]
    result = text[start:end].encode("utf-8")
    value = parse(result)
    if not isinstance(value, dict) or not value:
        raise ValueError("UNSUPPORTED_HAT_PROFILE")
    if field == "profilev5":
        edits = {}
        for key in hat.PROFILE_FIELDS:
            encoded = value.get(key)
            if not isinstance(encoded, str):
                raise ValueError("UNSUPPORTED_HAT_HIDDEN_FIELD")
            # No heuristic fallback to encoded data when generating a file.
            # The app unhides all four fields, including empty strings.
            plain = "" if not encoded else hat.xor_java(hat._base64(encoded).decode("utf-8"))
            edits[(key,)] = plain
        result = replace_values(result, edits)
    if "protextras" in value:
        _check_protection(value["protextras"])
        result = remove_member(result, (), "protextras")
    return result


def _check_protection(value):
    if not isinstance(value, dict) or set(value) - PROTECTION_FLAGS - PROTECTION_VALUES:
        raise ValueError("UNKNOWN_HAT_PROTECTION_LAYOUT")
    if any(type(value[k]) is not bool for k in PROTECTION_FLAGS & value.keys()):
        raise ValueError("UNKNOWN_HAT_PROTECTION_FLAG")


def export(data: bytes, credentials: dict, language="es") -> bytes:
    if credentials or language not in ("es", "en"):
        raise ValueError("UNSUPPORTED_CREDENTIALS")
    if not isinstance(data, bytes) or not 0 < len(data) <= hat.MAX_INPUT_BYTES:
        raise ValueError("INPUT_LIMIT")
    ciphertext = hat._base64(data.decode("utf-8-sig"))
    if not ciphertext or len(ciphertext) % 16:
        raise ValueError("INVALID_HAT_ENVELOPE")
    raw = unpad(AES.new(hat.KEY, AES.MODE_ECB).decrypt(ciphertext), 16)
    before = parse(raw)
    if not isinstance(before, dict):
        raise ValueError("UNSUPPORTED_HAT_LAYOUT")
    field = "profilev5" if "profilev5" in before else "profile"
    if field not in before or ("profilev4" in before and before["profilev4"] not in ({}, None)):
        raise ValueError("UNSUPPORTED_HAT_LAYOUT")
    profile = _profile(raw, field)
    if field == "profilev5" and before.get("profile") not in ({}, None):
        if not equal(before["profile"], parse(profile)):
            raise ValueError("CONFLICTING_HAT_PROFILES")
    if "protextras" in before:
        _check_protection(before["protextras"])
    description = before.get("descriptionv5", "") if field == "profilev5" else before.get("description", "")
    if not isinstance(description, str):
        raise ValueError("UNSUPPORTED_HAT_DESCRIPTION")
    result = raw
    for key in ("profilev5", "profilev4", "protextras", "descriptionv5"):
        result = remove_member(result, (), key)
    result = _put_raw(result, "profile", profile)
    result = put_member(result, (), "description", description)
    output = base64.b64encode(AES.new(hat.KEY, AES.MODE_ECB).encrypt(pad(result, 16)))
    after = hat.decode_hat(output, decode_fields=False)
    if any(k in after for k in ("profilev5", "profilev4", "protextras", "descriptionv5")) or "protextras" in after["profile"]:
        raise ValueError("OUTPUT_STILL_PROTECTED")
    if not equal(after["profile"], parse(profile)) or after["description"] != description:
        raise ValueError("CONNECTION_MISMATCH")
    untouched = {k: v for k, v in before.items() if k not in ("profile", "profilev5", "profilev4", "protextras", "description", "descriptionv5")}
    if not equal(untouched, {k: v for k, v in after.items() if k not in ("profile", "description")}):
        raise ValueError("METADATA_MISMATCH")
    return output
