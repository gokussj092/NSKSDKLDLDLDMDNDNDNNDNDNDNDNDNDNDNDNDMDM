#!/usr/bin/env python3
"""XVEON Tunnel Pro 8.1 `.xveon`/`.xvn` files and `xveontunnel://` /
`xveon://` / `xvn://` text links.

Worker adapter over the original decoder in ``xveon.py`` (kept
verbatim): PBKDF2-HMAC-SHA256 (10,000 iterations) + AES-256-GCM over a
GZIP JSON envelope (``XVN1:<flag>:<b64 salt>:<b64 iv>:<b64 ct>``).
A file holds the same 5-part string as a link body, with the
``xveontunnel://`` prefix optional.

This module exposes the three contracts the repo uses:

* ``decode(raw, password=None) -> dict`` — the supplied-bridge generic
  route (``cloud/workers/python/supplied_bridge.py`` calls
  ``module.decode`` with the raw bytes and any ``password`` credential).
* ``run(data, password=None) -> str`` — JSON document, the file-decoder
  route (``cloud/workers/python/engine.py`` runs this file as a
  subprocess with the input file as argv and credentials on stdin).
* ``decode_text(text, password=None) -> str | None`` — the text-bridge
  route (``cloud/workers/python/text_bridge.py``); None when the text
  is not an XVEON link, never a fallback to another format.

There is NO built-in server catalog in this app: no catalog URL, no
API host, no billing SDK anywhere in the DEX. Server lists only arrive
as user-supplied V2Ray/Xray subscription URLs, handled locally by
``xveon_catalog.py`` (NOT wired here: the worker never fetches a
user-supplied URL). ``decode`` therefore returns only the decrypted
configuration, never any download API.

Locked (flag ``1``) configurations raise ``XveonDecodeError`` with
``code == "PASSWORD_REQUIRED"`` when no password is given and
``code == "AUTH_FAILED"`` when the password fails GCM authentication
(a wrong password and tampered data are indistinguishable here).
``text_bridge`` and ``supplied_bridge`` surface those codes with exit
code 3; this file's own CLI does the same.
"""
import argparse
import json
import sys
from pathlib import Path

if __package__:
    from .xveon import NeedsPassword, XveonError, decrypt_text
else:
    from xveon import NeedsPassword, XveonError, decrypt_text

SCHEMES = ("xveontunnel://", "xveon://", "xvn://")
MAX_BYTES = 8 * 1024 * 1024


class XveonDecodeError(ValueError):
    """Decode failure with a worker ``code`` (``PASSWORD_REQUIRED``,
    ``AUTH_FAILED`` or ``DECODE_FAILED``)."""

    def __init__(self, message, code="DECODE_FAILED"):
        super().__init__(message)
        self.code = code


def _as_text(raw):
    if isinstance(raw, bytes):
        try:
            return raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise XveonDecodeError("Invalid .xveon file: not UTF-8 text")
    if isinstance(raw, str):
        return raw
    raise XveonDecodeError("Invalid input type")


def _document(envelope, protocol=None):
    """Decrypted envelope as the worker document (data only, no APIs)."""
    doc = {"application": "XVEON Tunnel Pro 8.1", "config": envelope}
    if protocol is not None:
        doc["protocol"] = protocol
    else:
        doc["extension"] = ".xveon"
    return doc


def decode(raw, password=None):
    """Decrypt a `.xveon`/`.xvn` file (bytes/str) or an XVEON link.

    Returns the worker document dict. Raises ``XveonDecodeError`` with
    ``code`` ``PASSWORD_REQUIRED`` (locked, no password), ``AUTH_FAILED``
    (locked, wrong password or tampered data) or ``DECODE_FAILED``.
    """
    if isinstance(raw, bytes) and (not raw or len(raw) > MAX_BYTES):
        raise XveonDecodeError("Invalid .xveon file: empty or oversize")
    text = _as_text(raw).strip()
    if not text:
        raise XveonDecodeError("Invalid .xveon file: empty input")
    lowered = text.lower()
    protocol = None
    for scheme in SCHEMES:
        if lowered.startswith(scheme):
            protocol = scheme
            break
    try:
        envelope = decrypt_text(text, password=password or "")
    except NeedsPassword as exc:
        raise XveonDecodeError(str(exc), code="PASSWORD_REQUIRED") from None
    except XveonError as exc:
        if protocol is not None or text.startswith("XVN1:"):
            if password:
                raise XveonDecodeError(str(exc), code="AUTH_FAILED") from None
            raise XveonDecodeError(str(exc), code="DECODE_FAILED") from None
        raise XveonDecodeError("Invalid .xveon file") from None
    return _document(envelope, protocol=protocol)


def run(data: bytes, password=None) -> str:
    """Decrypt file/link bytes -> JSON document string."""
    return json.dumps(decode(data, password=password),
                      ensure_ascii=False, indent=2)


def decode_text(text: str, password=None) -> str | None:
    """Decrypt an `xveontunnel://` / `xveon://` / `xvn://` link.

    Returns the JSON document, or None when the text is not an XVEON
    link. A locked link without a password raises ``XveonDecodeError``
    (``PASSWORD_REQUIRED``) instead of returning None, so the caller
    reports the missing password instead of an undecodable link.
    """
    if not isinstance(text, str):
        return None
    value = text.strip()
    lowered = value.lower()
    if not any(lowered.startswith(scheme) for scheme in SCHEMES):
        return None
    return json.dumps(decode(value, password=password),
                      ensure_ascii=False, indent=2)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("file", nargs="?", type=Path)
    a = p.parse_args()
    try:
        if a.file:
            with a.file.open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
            # Credentials arrive on stdin as JSON (engine contract) when
            # a file path is given; never read a tty.
            password = None
            if not sys.stdin.isatty():
                raw_credentials = sys.stdin.buffer.read(8193)
                if raw_credentials:
                    credentials = json.loads(raw_credentials)
                    if isinstance(credentials, dict):
                        password = credentials.get("password")
            sys.stdout.write(run(data, password=password))
        else:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
            sys.stdout.write(run(data))
        return 0
    except XveonDecodeError as exc:
        if exc.code in ("PASSWORD_REQUIRED", "AUTH_FAILED"):
            sys.stdout.write(json.dumps({"workerError": exc.code}))
            return 3
        print("No se pudo leer el perfil XVEON Tunnel Pro.",
              file=sys.stderr)
        return 1
    except (ValueError, OSError):
        print("No se pudo leer el perfil XVEON Tunnel Pro.",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
