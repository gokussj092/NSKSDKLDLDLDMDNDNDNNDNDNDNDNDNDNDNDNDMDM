#!/usr/bin/env python3
"""Independent NPV text adapter; deliberately not registered in any live router.

Confirmed app representation: npvt-ssh:// + Base64(UTF8(JSON)). Other requested
schemes are explicit transport aliases, pending real exports for certification.
Plain JSON transport/npvs1 needs only stdlib. Binary NPVS transport delegates to
the existing authenticated file codec; no guessed keys or cross-mode fallback.
"""
from __future__ import annotations
import argparse
import base64
import binascii
from functools import lru_cache
import importlib.util
import json
from pathlib import Path
import re
import sys

PREFIXES = ("npvt://", "npvt-ssh://", "npvt-vless://", "npvt-vmess://", "npv://")
MAX_TEXT_CHARS = 2 * 1024 * 1024


class DecodeError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def identify(text: str) -> str | None:
    """Return the canonical prefix, or None; identification is not decryption."""
    if not isinstance(text, str) or not 0 < len(text) <= MAX_TEXT_CHARS:
        return None
    value = text.strip()
    return next((p for p in PREFIXES if value.lower().startswith(p) and
                 value[len(p):].strip()), None)


def _base64(value: str) -> bytes:
    compact = re.sub(r"[ \t\r\n]", "", value)
    if not compact or len(compact) > MAX_TEXT_CHARS or not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", compact):
        raise DecodeError("INVALID_BASE64")
    if "=" in compact and len(compact) % 4:
        raise DecodeError("INVALID_BASE64")
    try:
        data = base64.b64decode(compact + "=" * (-len(compact) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as error:
        raise DecodeError("INVALID_BASE64") from error
    if base64.urlsafe_b64encode(data).rstrip(b"=").decode() != compact.rstrip("=").replace("+", "-").replace("/", "_"):
        raise DecodeError("INVALID_BASE64")
    return data


def _json(data: bytes):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise DecodeError("INVALID_JSON")
            out[key] = value
        return out

    def constant(_):
        raise DecodeError("INVALID_JSON")

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        if isinstance(error, DecodeError):
            raise
        raise DecodeError("INVALID_JSON") from error


def _embedded(value, depth=0):
    if depth > 64:
        raise DecodeError("NESTING_LIMIT")
    if isinstance(value, dict):
        return {key: _embedded(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list):
        return [_embedded(item, depth + 1) for item in value]
    if not isinstance(value, str) or not value.startswith("npvs1:"):
        return value
    raw = _base64(value[6:])
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise DecodeError("INVALID_UTF8") from error
    if text.startswith("npvs1:"):
        return _embedded(text, depth + 1)
    if text.lstrip().startswith(("{", "[")):
        try:
            obj = _json(raw)
        except DecodeError:
            # The explicit string layer is valid; brace-prefixed prose is legal.
            return text
        return _embedded(obj, depth + 1)
    return text


@lru_cache(maxsize=1)
def _npvs():
    """Load only the fixed sibling/canonical codec, never an input-selected path."""
    here = Path(__file__).resolve()
    paths = (here.with_name("npvs.py"), here.parents[2] / "npvs.py")
    for path in paths:
        if not path.is_file():
            continue
        spec = importlib.util.spec_from_file_location("_npv_text_file_codec", path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except ImportError as error:
            raise DecodeError("ENGINE_UNAVAILABLE") from error
        return module
    raise DecodeError("ENGINE_UNAVAILABLE")


def decode(text: str, *, password: str | None = None, public_key: str | None = None):
    """Decode one complete link, preserving every JSON field, type and list item.

    Supported payloads are Base64 UTF8 JSON or Base64 binary NPVS. Known but
    different encrypted representations require their own verified reader.
    """
    prefix = identify(text)
    if prefix is None:
        raise DecodeError("UNSUPPORTED_TEXT_FORMAT")
    raw = _base64(text.strip()[len(prefix):])
    if raw.startswith(b"NPVS"):
        codec = _npvs()
        try:
            return codec.decode_npvs_complete(raw, password=password, public_key=public_key)
        except codec.DecodeError as error:
            raise DecodeError(error.code) from error
    if password is not None or public_key is not None:
        raise DecodeError("CREDENTIALS_NOT_ALLOWED")
    # Content must select the parser before it runs; never retry failed AEAD.
    if not raw.lstrip().startswith((b"{", b"[")):
        raise DecodeError("UNSUPPORTED_TEXT_PAYLOAD")
    obj = _json(raw)
    if not isinstance(obj, (dict, list)):
        raise DecodeError("INVALID_JSON")
    return _embedded(obj)


def decode_text(text: str, *, password: str | None = None, public_key: str | None = None) -> str | None:
    """Future dispatcher API: None only for unrecognized input; errors are typed."""
    if identify(text) is None:
        return None
    result = json.dumps(decode(text, password=password, public_key=public_key),
                        ensure_ascii=False, indent=2, allow_nan=False)
    try:
        result.encode("utf-8")
    except UnicodeError as error:
        raise DecodeError("INVALID_UTF8") from error
    return result


def run(data: bytes, *, password: str | None = None, public_key: str | None = None) -> str:
    if not isinstance(data, bytes) or len(data) > MAX_TEXT_CHARS * 4:
        raise DecodeError("INVALID_INPUT")
    try:
        text = data.decode("utf-8")
    except UnicodeError as error:
        raise DecodeError("INVALID_UTF8") from error
    out = decode_text(text, password=password, public_key=public_key)
    if out is None:
        raise DecodeError("UNSUPPORTED_TEXT_FORMAT")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", default="-", help="UTF8 text file, or - for stdin")
    parser.add_argument("--credentials-stdin", action="store_true", help="JSON password/publicKey; requires a file input")
    args = parser.parse_args()
    try:
        credentials = {}
        if args.credentials_stdin:
            if args.input == "-":
                raise DecodeError("INVALID_INPUT")
            incoming = sys.stdin.buffer.read(32769)
            if len(incoming) > 32768:
                raise DecodeError("INVALID_CREDENTIALS")
            credentials = _json(incoming)
            if not isinstance(credentials, dict) or set(credentials) - {"password", "publicKey"}:
                raise DecodeError("INVALID_CREDENTIALS")
            for name, maximum in (("password", 4096), ("publicKey", 128)):
                value = credentials.get(name)
                if value is not None and (not isinstance(value, str) or not 0 < len(value.encode("utf-8")) <= maximum):
                    raise DecodeError("INVALID_CREDENTIALS")
        if args.input == "-":
            data = sys.stdin.buffer.read(MAX_TEXT_CHARS * 4 + 1)
        else:
            with Path(args.input).open("rb") as stream:
                data = stream.read(MAX_TEXT_CHARS * 4 + 1)
        result = run(data, password=credentials.get("password"), public_key=credentials.get("publicKey"))
    except (OSError, ValueError, UnicodeError) as error:
        print(error.code if isinstance(error, DecodeError) else "INVALID_INPUT", file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
