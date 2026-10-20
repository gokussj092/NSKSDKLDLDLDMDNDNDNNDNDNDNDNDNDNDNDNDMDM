"""Authenticated HCX4 / HCCFG 10 reader for HTTP Custom build 899."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import sys
from typing import Any

if __package__:
    try:
        from ... import _hc_hccfg as historical
    except ImportError:
        # HTTPCUSTOM.py can also run directly and import apps.HTTP_Custom
        # without the surrounding decoders.Python package.
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        import _hc_hccfg as historical
    from .crypto import native_fold
else:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    import _hc_hccfg as historical
    from crypto import native_fold

HCError = historical.HCError
MAX_FILE_BYTES = 16 * 1024 * 1024
PKG = historical.PKG
OUTER_AAD = b"HCX4|" + PKG + b"|1"
OUTER_KEY = historical._hkdf(
    native_fold(b"hc-envelope-seal-v4 " + PKG),
    b"hc-envelope-seal-salt-v4", b"hc-envelope-seal-info-v4",
)


class UnrecognizedFormat(HCError):
    """No HCX4 envelope authenticated; the historical readers may try."""


def _json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise HCError("INVALID_JSON") from error


def open_envelope(data: bytes) -> dict:
    if not isinstance(data, bytes) or len(data) > MAX_FILE_BYTES:
        raise HCError("INVALID_FILE_SIZE")
    if not data:
        raise UnrecognizedFormat("Not a valid HCX4 envelope")
    for logical in historical._carriers(data):
        if len(logical) < 40:
            continue
        try:
            raw = historical._xdec(OUTER_KEY, logical[:24], OUTER_AAD, logical[24:])
        except HCError:
            continue
        envelope = _json(raw)
        if not isinstance(envelope, dict) or envelope.get("a") != "HCCFG":
            raise HCError("INVALID_ENVELOPE")
        return envelope
    raise UnrecognizedFormat("Not a valid HCX4 envelope")


def derive(envelope: dict, password: str | None, hwid: str | None) -> tuple[bytes, bytes]:
    # Only the format actually authenticated against build-899 exports is
    # enabled. Names present in a binary are not evidence of compatibility.
    if type(envelope.get("b")) is not int or envelope["b"] != 10:
        raise HCError("UNSUPPORTED_SCHEMA")
    if envelope.get("c") != "s1" or envelope.get("d") != "h1":
        raise HCError("UNSUPPORTED_CIPHER")
    schedule = envelope.get("e")
    if schedule not in ("n11", "n12"):
        raise HCError("UNSUPPORTED_SCHEDULE")
    for value in (password, hwid):
        if value is not None and (not isinstance(value, str) or not 0 < len(value) <= 4096):
            raise HCError("INVALID_CREDENTIAL")
    seed = historical._env_key(envelope)
    features = historical._features(envelope)
    build = historical._n_bytes(envelope)
    if not build:
        raise HCError("MISSING_BUILD")
    protected = historical._h_flag(envelope)
    locked = schedule == "n12"
    if locked and hwid is None:
        raise HCError("HWID_PASSWORD_REQUIRED" if protected and password is None else "HWID_REQUIRED")
    if protected and password is None:
        raise HCError("PASSWORD_REQUIRED")
    try:
        device = historical._norm_hwid(hwid) if locked else None
    except HCError as error:
        raise HCError("INVALID_HWID") from error
    transcript = b"HCCFG\0" + PKG + b"\0" + b"1\0" + features + b"\0" + build + b"\0"
    if device is not None:
        transcript += b"hwid\0" + device + b"\0"
    ikm = native_fold(transcript + seed)
    protection_aad = b"|0"
    if protected:
        ops, memory = envelope.get("l"), envelope.get("m")
        if (type(ops) is not int or not 1 <= ops <= 10 or type(memory) is not int
                or not 8192 <= memory <= 256 * 1024 * 1024):
            raise HCError("ARGON2_LIMIT")
        password_key, protection_aad = historical._pw_kdf(envelope, password, seed)
        ikm += password_key
    info = b"app-config|" + schedule.encode() + b"|" + PKG + b"|1|" + features + b"|" + build
    if device is not None:
        info += b"|hwid|" + device
    key = historical._hkdf(ikm, seed, info)
    aad = (b"HCCFG|10|XCHACHA20P1305|NATIVE-HKDF-SHA256|" + schedule.encode()
           + b"|" + PKG + b"|1|" + features + protection_aad + b"|" + build)
    if locked:
        slots = envelope.get("o")
        if not isinstance(slots, list) or not 0 < len(slots) <= 4096:
            raise HCError("INVALID_HWID_SLOTS")
        for slot in slots:
            try:
                session = historical._xdec(key, bytes.fromhex(slot["a"]), aad + b"\0w",
                                           bytes.fromhex(slot["b"]))
            except (HCError, KeyError, ValueError, TypeError):
                continue
            if len(session) == 32:
                return session, aad
        raise HCError("AUTH_FAILED")
    return key, aad


def parse_profile(data: bytes, label: str) -> dict:
    reader = historical._R(data)
    if reader.take(4) != b"HPC1" or reader.u32() != 11:
        raise HCError("INVALID_HPC1")
    name, protocol, host = reader.txt(), reader.txt(), reader.txt()
    port = reader.u32()
    username, password, payload = reader.txt(), reader.txt(), reader.txt()
    options_text = reader.txt()
    flags, updated, mode = reader.u32(), reader.u64(), reader.txt()
    if reader.o != len(data):
        raise HCError("HPC1_TRAILING_BYTES")
    try:
        options = json.loads(options_text) if options_text else {}
    except (ValueError, RecursionError):
        options = options_text
    return dict(label=label, name=name, protocol=protocol, host=host, port=port,
                username=username, password=password, payload=payload, options=options,
                options_text=options_text, flags=flags, updated_at_ms=updated, mode=mode)


def _content(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        return {"base64": base64.b64encode(raw).decode("ascii")}
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return text


def decrypt(data: bytes, password: str | None = None, hwid: str | None = None) -> dict:
    envelope = open_envelope(data)
    key, aad = derive(envelope, password, hwid)
    try:
        main_section = envelope.get("i")
        if not isinstance(main_section, dict):
            raise HCError("INVALID_MAIN_SECTION")
        main = _json(historical._dec_section(main_section, key, aad))
        profiles, others = [], []
        collection = envelope.get("j", [])
        for section in historical._sec_list(collection):
            plain = historical._dec_section(section, key, aad)
            label = section["a"]
            if plain.startswith(b"HPR1"):
                if len(plain) < 44:
                    raise HCError("INVALID_HPR1")
                # Both AEAD layers must authenticate. No stream-only fallback.
                plain = historical._xdec(key, plain[4:28], aad + b"\0" + label.encode() + b":r", plain[28:])
            sidecar = historical._dec_sidecar(section, key, aad)
            if plain.startswith(b"HPC1"):
                profile = parse_profile(plain, label)
                if sidecar is not None:
                    try:
                        profile["custom_payload_sidecar"] = sidecar.decode("utf-8")
                    except UnicodeError:
                        profile["custom_payload_sidecar_hex"] = sidecar.hex()
                profiles.append(profile)
            else:
                entry = {"label": label, "content": _content(plain)}
                if sidecar is not None:
                    entry["sidecar"] = _content(sidecar)
                others.append(entry)
    except HCError as error:
        if "auth failed" in str(error).lower():
            raise HCError("AUTH_FAILED") from error
        raise
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as error:
        raise HCError("INVALID_SECTION") from error
    return {
        "app_version": "7.11.28 - Patch 1 (899)" if envelope.get("n") == 899 else f"build-{envelope.get('n')}",
        "config": profiles, "main": main,
        "protections": historical._norm_prot(main.get("g", {})) if isinstance(main, dict) else {},
        "other_sections": others,
    }
