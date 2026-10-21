#!/usr/bin/env python3
"""C2 dedicated text dispatcher, separate from Telegram decorated handlers.

This accepts *only* source-recognized protocols. No guessed keys, no network,
no generic brute force or user-provided module names.
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

MAX_TEXT_CHARS = 250_000
# Explicit modules: a protocol prefix never selects a shell command or path.
HANDLERS = (
    ("decoders.Python.text_structured_protocols", "decode_text"),
    ("decoders.Python.text_legacy_protocols", "decode_text"),
    ("decoders.Python.renz", "decode_text"),
    ("decoders.Python.xor_family", "decode_text"),
    ("decoders.Python.falcon_links", "decode_text"),
    ("decoders.Python.npvt_links", "decode_text"),
)

def dispatch(text: str, *, password: str | None = None) -> str | None:
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT_CHARS:
        return None
    value = text.strip()
    lowered = value.lower()
    # File/text twin formats: same vetted legacy algorithm, no unrelated fallback.
    direct = {
        "tls://": "decoders.Python.TLS",
        "ssc://": "decoders.Python.SSCCUSTOM",
        "dark://": "decoders.Python.DARKTUNNEL",
        "dt://": "decoders.Python.DARKTUNNEL",
        "dtunnel://": "decoders.Python.DARKTUNNEL",
    }
    for prefix, module_name in direct.items():
        if lowered.startswith(prefix):
            from_module = importlib.import_module(module_name)
            return from_module.run(value.encode("utf-8"))
    # The Ultra Custom scheme has an explicit codec, including UAP1 password
    # wrappers. Preserve the exact error instead of silently returning None.
    if lowered.startswith("ua://"):
        from decoders.Python.apps.Ultra_Custom import ultra_custom_52 as ultra
        normalized = "ua://" + value[5:]
        return json.dumps(ultra.decode(normalized, password=password), ensure_ascii=False, indent=2)
    # AC's verified export has a Name field; older generic RENZ vectors retain
    # their original wrapper/engine. A corrupt modern profile never falls back.
    if lowered.startswith("actunnelvpn://"):
        module = importlib.import_module("decoders.Python.apps.AC_TUNNEL_VPN.file_decoder")
        result = module.decode_text(value)
        if result is not None:
            return result
    # C8 isolated original application codecs. These prefixes are unambiguous.
    c8_links = (
        ("mkk://", "decoders.Python.apps.MKK_Hyper_VPN.MKK_Hyper_VPN_textos"),
        ("vpn://", "decoders.Python.apps.DTunnel_Mod.dtunnelmod"),
        ("mytunnelproxy://", "decoders.Python.apps.My_Tunnel_Proxy.file_decoder"),
    )
    for prefix, module_name in c8_links:
        if lowered.startswith(prefix):
            module = importlib.import_module(module_name)
            return module.run(value.encode("utf-8"))
    # Special Phase G protocols route to the same independent per-format source.
    byte_handlers = (
        (("izph://", "izphvpnpro://"), "decoders.Python.izph"),
        (("wyrlite://", "wyrvpnlite://", "wyrl://"), "decoders.Python.wyrlite"),
        (("wyrvpn://",), "decoders.Python.wyrvpn"),
        (("intvpn://",), "decoders.Python.intvpn"),
        (("slipnet-enc://",), "decoders.Python.slipnet"),
        (("juanscript://", "mobi://"), "decoders.Python.juanscript"),
        (("eut-settings://",), "decoders.Python.eut"),
    )
    for prefixes, module_name in byte_handlers:
        if lowered.startswith(prefixes):
            module = importlib.import_module(module_name)
            return module.run(value.encode("utf-8"))
    # Source dispatchers perform strict checks of their own protocols.
    # Never try unrelated *file* keys against a text token.
    for module_name, function_name in HANDLERS:
        module = importlib.import_module(module_name)
        result = getattr(module, function_name)(value)
        if result is not None:
            return json.dumps(result, ensure_ascii=False, indent=2) if isinstance(result, (dict, list)) else result
    return None


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    try:
        raw = Path(sys.argv[1]).read_bytes()
        if len(raw) > MAX_TEXT_CHARS * 4:
            return 2
        text = raw.decode("utf-8")
        incoming = sys.stdin.buffer.read(8193)
        credentials = json.loads(incoming) if incoming else {}
        if not isinstance(credentials, dict) or set(credentials) - {"password"}:
            return 2
        password = credentials.get("password")
        if password is not None and (not isinstance(password, str) or
                not 0 < len(password.encode("utf-8")) <= 4096):
            return 2
        if password is not None and not text.strip().lower().startswith("ua://"):
            return 2
        output = dispatch(text, password=password)
    except (OSError, UnicodeError, ValueError, ImportError) as error:
        if getattr(error, "code", None) in ("PASSWORD_REQUIRED", "AUTH_FAILED"):
            sys.stdout.write(json.dumps({"workerError": error.code}))
            return 3
        return 1
    if not isinstance(output, str) or not output:
        return 1
    sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
