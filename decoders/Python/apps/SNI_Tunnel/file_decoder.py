#!/usr/bin/env python3
"""Engine entry point for SNI Tunnel 1.3.7 .v2rc files and v2rc:// text.

Thin adapter over sni_tunnel.py (no new crypto, no network, no sealing):
the engine runs ``[python, file_decoder.py, input.v2rc]`` and passes
credentials as JSON on stdin (``{"password": ...}``), exactly like the
Sentinel .st file decoder. A sealed config without a password is exit 3
with ``{"workerError": "PASSWORD_REQUIRED"}`` on stdout; a wrong
password is exit 3 ``AUTH_FAILED``; anything else undecodable is exit 1
(the engine reports DECODE_FAILED). ``decode_text`` is the text_bridge
entry point for ``v2rc://`` links (same contract, password via argument).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

if __package__:
    from .sni_tunnel import SniError, b64std_decode, fmt_ts, open_v2rc, parse_link
else:
    from sni_tunnel import SniError, b64std_decode, fmt_ts, open_v2rc, parse_link


class _CredentialError(ValueError):
    """Text/file credential failure with an engine worker ``code``.

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


def _render(result: dict) -> dict:
    """Same public shape as the ``v2rc`` CLI subcommand (no inner JSON)."""
    out = {
        "name": result["name"],
        "version": result["version"],
        "password_protected": result["password_protected"],
        "cellular_only": result["cellular_only"],
        "expires_at": (
            fmt_ts(result["expires_at_unix"]) if result["expires_at_unix"] else None
        ),
        "expired": result["expired"],
        "record_kind": result["record_kind"],
        "device_id": result["device_id"],
        "inner_expires_at": (
            fmt_ts(result["inner_expires_at_unix"])
            if result["inner_expires_at_unix"]
            else None
        ),
        "inner_expired": result.get("inner_expired"),
        "config": result["config"],
    }
    if result["password_envelope"] is not None and result["config"] is None:
        pe = result["password_envelope"]
        out["password_envelope"] = {
            "salt_hex": b64std_decode(pe["salt"]).hex(),
            "iterations": pe["iterations"],
            "ciphertext_bytes": len(b64std_decode(pe["ciphertext"])),
            "plaintext_bytes": len(b64std_decode(pe["ciphertext"])) - 28,
            "status": "STILL ENCRYPTED -- password required",
        }
    if result["config"]:
        try:
            out["parsed_config"] = parse_link(result["config"])
        except SniError:
            out["parsed_config"] = None
    return out


def decode_text(value: str, password: str | None = None) -> str | None:
    """Decode one v2rc:// link (or .v2rc file text) -> JSON string.

    Raises _CredentialError("PASSWORD_REQUIRED" | "AUTH_FAILED") for the
    password flow; returns None for any other undecodable input.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        result = open_v2rc(value.strip(), password=password)
    except SniError as error:
        message = str(error)
        if "password is incorrect" in message:
            raise _CredentialError("AUTH_FAILED") from None
        if "requires a password" in message:
            raise _CredentialError("PASSWORD_REQUIRED") from None
        return None
    if result["config"] is None and result["password_envelope"] is not None:
        # Sealed behind the password layer; open_v2rc reports this as a
        # result, not an exception (same as the CLI's "STILL ENCRYPTED").
        raise _CredentialError("PASSWORD_REQUIRED")
    return json.dumps(_render(result), ensure_ascii=False, indent=2)


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    password = _read_password()
    try:
        text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 2
    try:
        output = decode_text(text, password=password)
    except _CredentialError as error:
        sys.stdout.write(json.dumps({"workerError": error.code}))
        return 3
    if output is None:
        return 1
    sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
