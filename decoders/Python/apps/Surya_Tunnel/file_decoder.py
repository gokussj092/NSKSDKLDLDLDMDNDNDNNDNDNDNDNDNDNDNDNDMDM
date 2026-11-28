#!/usr/bin/env python3
"""Engine entry point for Surya Tunnel 1.6 .st files and SVPN text.

Thin adapter over surya_tunnel.py (no new crypto, no network: the
Cloud Sync fetch is never used here). The engine runs
``[python, file_decoder.py, input.st]`` and passes credentials as JSON
on stdin (``{"password": ...}``), exactly like the Sentinel .st file
decoder; engine.decode_file() routes .st files with SPN1/SPW1 magic
here and every other .st file to the Sentinel decoder (see
_is_surya_st in engine.py). A password-protected SPW1 file without a
password is exit 3 PASSWORD_REQUIRED; a wrong password on an SPW1
file is exit 3 AUTH_FAILED (surya_tunnel returns None for a failed
open, so the adapter maps SPW1 + password given + no result to
AUTH_FAILED); anything else undecodable is exit 1 (the engine
reports DECODE_FAILED). ``decode_text`` is the text_bridge entry
point for ``SVPN1:``/``SVPN2:``/``SVPN3:``/``SVPN4:`` shares (same
contract, password via argument; a missing password on a protected
SVPN3:/SVPN4: share raises PASSWORD_REQUIRED with .code).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

if __package__:
    from .surya_tunnel import SuryaDecodeError, decode_file, decode_text as _decode_text
else:
    from surya_tunnel import SuryaDecodeError, decode_file, decode_text as _decode_text


class _CredentialError(ValueError):
    """Text credential failure with an engine worker ``code``.

    A ValueError subclass so text_bridge.main() (which maps
    error.code -> exit 3) catches it instead of crashing.
    """

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


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


def decode_text(value: str, password: str | None = None) -> str | None:
    """Decode one SVPN1:/SVPN2:/SVPN3:/SVPN4: share -> JSON string.

    Raises _CredentialError("PASSWORD_REQUIRED") for a protected
    SVPN3:/SVPN4: share without a password; returns None for any
    other undecodable input (including a wrong SVPN3:/SVPN4:
    password, which the codec reports as a plain decode failure).
    SuryaDecodeError is translated here because it is a plain
    Exception and text_bridge.main() only maps ValueError codes.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        result = _decode_text(value.strip(), password)
    except SuryaDecodeError as error:
        if error.code == "PASSWORD_REQUIRED":
            raise _CredentialError("PASSWORD_REQUIRED") from None
        return None
    if result is None:
        return None
    return json.dumps(result, ensure_ascii=False, indent=2)


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    password = _read_password()
    try:
        data = Path(sys.argv[1]).read_bytes()
    except OSError:
        return 2
    try:
        result = decode_file(data, password)
    except SuryaDecodeError as error:
        if error.code in ("PASSWORD_REQUIRED", "AUTH_FAILED"):
            sys.stdout.write(json.dumps({"workerError": error.code}))
            return 3
        return 1
    if result is None:
        if password is not None and len(data) > 48 and data[:4] == b"SPW1":
            # SPW1 open with a password either succeeds or fails on the
            # password (the codec returns None instead of raising).
            sys.stdout.write(json.dumps({"workerError": "AUTH_FAILED"}))
            return 3
        return 1
    sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
