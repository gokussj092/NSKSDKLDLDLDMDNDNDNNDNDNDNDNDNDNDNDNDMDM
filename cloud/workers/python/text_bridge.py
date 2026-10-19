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

def dispatch(text: str) -> str | None:
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
    # C8 isolated original application codecs. These prefixes are unambiguous.
    c8_links = (
        ("ua://", "decoders.Python.apps.Ultra_Custom.ultra_custom_52"),
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
        output = dispatch(text)
    except (OSError, UnicodeError, ValueError, ImportError):
        return 1
    if not isinstance(output, str) or not output:
        return 1
    sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
