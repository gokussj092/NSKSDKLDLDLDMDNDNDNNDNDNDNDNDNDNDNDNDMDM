#!/usr/bin/env python3
"""Engine entry point for DGM Tunnel 15.11.2026 .eyj / .dgm files and
dgmtunnel:// text.

Thin adapter over dgm_tunnel.py (no new crypto, no network: the feed
fetch is never used here). The engine runs
``[python, file_decoder.py, input.eyj]`` and passes credentials as JSON
on stdin (``{"password": ...}``), exactly like the Sentinel .st file
decoder. A DGMTUNNEL_SHARE envelope opens with open_share(); anything
else goes through parse_text() (links, JSON profile/array, Base64
subscription). Credential mapping, same as the engine contract: a
protected share without a password is exit 3 PASSWORD_REQUIRED; a
wrong password is exit 3 AUTH_FAILED (DGM's WRONG_PASSWORD); expired
or malformed shares are exit 1 (the engine reports DECODE_FAILED).
``decode_text`` is the text_bridge entry point for ``dgmtunnel://``
links (same contract, password via argument). The adapter deliberately
does NOT reuse _open_maybe_share(): that helper prompts on the
terminal (getpass) when a protected share has no password, which
must never happen inside the worker.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

if __package__:
    from .dgm_tunnel import (
        APP_PACKAGE,
        APP_VERSION_CODE,
        APP_VERSION_NAME,
        DecodeError,
        _profile,
        _share_envelope_text,
        open_share,
        parse_text,
    )
else:
    from dgm_tunnel import (
        APP_PACKAGE,
        APP_VERSION_CODE,
        APP_VERSION_NAME,
        DecodeError,
        _profile,
        _share_envelope_text,
        open_share,
        parse_text,
    )


def _read_password() -> str | None:
    """One-shot stdin credentials ({} when the worker sent none)."""
    try:
        raw = sys.stdin.buffer.read(8193)
    except OSError:
        return None
    if not raw:
        return None
    try:
        request = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(request, dict) or set(request) - {"password"}:
        return None
    password = request.get("password")
    return password if isinstance(password, str) and password else None


def _decode_document(text: str, password: str | None) -> dict:
    """Share envelope or ConfigImporter parse -> result document."""
    envelope = _share_envelope_text(text)
    if envelope is not None:
        config, meta = open_share(text.strip(), password)
        profile = _profile(config)
        profile["share"] = meta
        profiles, errors = [profile], []
    else:
        profiles, errors = parse_text(text)
    return {
        "app": "DGM Tunnel",
        "package": APP_PACKAGE,
        "versionName": APP_VERSION_NAME,
        "versionCode": APP_VERSION_CODE,
        "profiles": profiles,
        "errors": errors,
    }


def decode_text(value: str, password: str | None = None) -> str | None:
    """Decode one dgmtunnel:// link (or .eyj/.dgm file text) -> JSON str.

    Raises DecodeError("PASSWORD_REQUIRED" | "AUTH_FAILED") for the
    share password flow; returns None for any other undecodable input.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        document = _decode_document(value.strip(), password)
    except DecodeError as error:
        if error.code == "PASSWORD_REQUIRED":
            raise
        if error.code == "WRONG_PASSWORD":
            raise DecodeError("AUTH_FAILED", "Wrong share password.") from None
        return None
    return json.dumps(document, ensure_ascii=False, indent=2)


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    password = _read_password()
    try:
        text = Path(sys.argv[1]).read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return 2
    try:
        output = decode_text(text, password=password)
    except DecodeError as error:
        if error.code in ("PASSWORD_REQUIRED", "AUTH_FAILED"):
            sys.stdout.write(json.dumps({"workerError": error.code}))
            return 3
        return 1
    if output is None:
        return 1
    sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
