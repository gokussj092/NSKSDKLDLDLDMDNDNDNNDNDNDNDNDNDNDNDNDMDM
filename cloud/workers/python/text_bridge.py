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
NPV_TEXT_PREFIXES = ("npvt://", "npvt-ssh://", "npvt-vless://", "npvt-vmess://", "npv://")

def is_npv_text(value: str) -> bool:
    return any(value.lower().startswith(prefix) and len(value) > len(prefix)
               for prefix in NPV_TEXT_PREFIXES)

# Explicit modules: a protocol prefix never selects a shell command or path.
HANDLERS = (
    ("decoders.Python.text_structured_protocols", "decode_text"),
    ("decoders.Python.text_legacy_protocols", "decode_text"),
    ("decoders.Python.renz", "decode_text"),
    ("decoders.Python.xor_family", "decode_text"),
    ("decoders.Python.falcon_links", "decode_text"),
    ("decoders.Python.npvt_links", "decode_text"),
    # HAPP RSA links: decode_text matches the HANDLERS contract (str -> str|None)
    # and is a no-op without SPDECODE_HAPP_KEYS_JSON configured locally.
    ("decoders.Python.happ_links", "decode_text"),
)

def dispatch(text: str, *, password: str | None = None) -> str | None:
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT_CHARS:
        return None
    value = text.strip()
    lowered = value.lower()
    from cloud.workers.python.supplied_bridge import text_decode
    supplied = text_decode(value, password=password)
    if supplied is not None:
        return supplied
    from decoders.Python.apps.MNR_TUNNEL_PLUS.codec import is_profile_text
    if is_profile_text(value):
        from decoders.Python.apps.MNR_TUNNEL_PLUS.file_decoder import run
        return run(value.encode('utf-8'))
    # Exact modern NPV handler owns five schemes. Preserve historical
    # dns:// and standalone npvs1: without retrying failed NPVS auth.
    if is_npv_text(value):
        from decoders.Python.apps.NPV_Tunnel.text_decoder import decode_text
        return decode_text(value, password=password)
    if value.startswith(("1FTnl.", "1FT1.", "1ftunnel://1FTnl/", "1ftunnel://1FT1/")):
        from decoders.Python.apps.OneFTunnel.file_decoder import run
        return run(value.encode("utf-8"), password=password)
    # File/text twin formats: same vetted legacy algorithm, no unrelated fallback.
    direct = {
        "tls://": "decoders.Python.TLS",
        "ssc://": "decoders.Python.SSCCUSTOM",
        "dark://": "decoders.Python.DARKTUNNEL",
        "darktunnel://": "decoders.Python.DARKTUNNEL",
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
    # Secondary text schemes wired from existing repo codecs only; no new
    # decryption logic. A malformed payload is an undecodable link (None),
    # never a fallback to another format.
    if lowered.startswith("httptweak://"):
        # Payload is the bare Base64 .ht blob; config_prefix is confirmed in
        # the decrypted config, but no real httptweak:// link has been seen
        # yet, so the payload shape is the repo's encode_text round-trip.
        module = importlib.import_module("decoders.Python.apps.HTTP_Tweak.HTTP_Tweak_archivos")
        try:
            result = module.decode_text(value[len("httptweak://"):])
        except Exception:
            return None
        return json.dumps(result, ensure_ascii=False, indent=2) if isinstance(result, (dict, list)) else result
    if lowered.startswith("eut://"):
        # sza blob; EUT_VPN_archivos.import_text strips the eut:// prefix
        # itself (sza_decrypt) and falls back from eut-payload:// to sza.
        module = importlib.import_module("decoders.Python.apps.EUT_VPN.EUT_VPN_archivos")
        _kind, obj = module.import_text(value)
        if obj is not None:
            return json.dumps(obj, ensure_ascii=False, indent=2) if isinstance(obj, (dict, list)) else obj
        return None
    if lowered.startswith("acvpn://"):
        # Decodes only the cloud reference identifier offline; the profile
        # itself is not downloaded (profileDownloaded is False by design).
        module = importlib.import_module("decoders.Python.apps.AC_TUNNEL_VPN.file_decoder")
        try:
            return module.render(module.cloud_reference(value.encode("utf-8")))
        except Exception:
            return None
    if lowered.startswith("netfluxvpn://"):
        # NetFlux VPN 1.1: explicit dispatch to the shared RENZ 'gcpvpn'
        # profile (same key material, same live catalog). No 'netflux'
        # profile is registered in renz.py, so the canonical RENZ route
        # cannot serve this scheme. The scheme is unambiguous: a None
        # result is final, never a fallback to renz.
        module = importlib.import_module("decoders.Python.apps.NETFLUX_VPN.file_decoder")
        return module.decode_text(value)
    if lowered.startswith("maya://"):
        # MAYA TUN PRO 43.0: explicit dispatch to codec.decode_text.
        # Mode 3 is ChaCha20-Poly1305 over the .maya file bytes (same
        # "maya" key); the decrypted bytes open through the existing
        # repo file route (_noobcrypt.decrypt_profile). No real maya://
        # link has been supplied, so this route is VERIFIED_SYNTHETIC.
        # The scheme is unambiguous: a None result is final, never a
        # fallback to another format.
        module = importlib.import_module("decoders.Python.apps.Maya_Tun_Pro.codec")
        return module.decode_text(value)
    if lowered.startswith("pmtunnellite://"):
        # PM Tunnel Lite 1.0: standalone codec (own key material, no
        # renz.py profile, so the canonical RENZ route cannot serve
        # this scheme). The scheme is unambiguous: a None result is
        # final, never a fallback to renz.
        module = importlib.import_module("decoders.Python.apps.PM_Tunnel_Lite.file_decoder")
        return module.decode_text(value)
    if lowered.startswith("rmplite://"):
        # RMP TUNNEL LITE RMP-4: explicit dispatch to the Lite file
        # decoder (.rmplite hex + XOR key + JNI modified UTF-8 tweak).
        # The scheme is unambiguous: a None result is final, never a
        # fallback to another format.
        module = importlib.import_module("decoders.Python.apps.RMP_Tunnel_Lite.file_decoder")
        return module.decode_text(value)
    if lowered.startswith(("xveontunnel://", "xveon://", "xvn://")):
        # XVEON Tunnel Pro 8.1: explicit dispatch to the file decoder
        # (PBKDF2-HMAC-SHA256 + AES-256-GCM, no catalog). The supplied
        # TEXT_ROUTES serve these schemes first; this block is the
        # explicit fallback, matching the netflux/maya/pmtunnel/rmplite
        # pattern. The scheme is unambiguous: a None result is final,
        # never a fallback to another format.
        module = importlib.import_module("decoders.Python.apps.XVEON_Tunnel_Pro.file_decoder")
        return module.decode_text(value, password=password)
    # C8 isolated original application codecs. These prefixes are unambiguous.
    c8_links = (
        ("bdnet://", "decoders.Python.apps.BD_NET_VPN.file_decoder"),
        ("apnavpn://", "decoders.Python.apps.APNA_VPN.file_decoder"),
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
        onef = text.strip().startswith(("1FTnl.", "1FT1.", "1FTlb.")) or text.strip().lower().startswith("1ftunnel://")
        npv = is_npv_text(text.strip())
        credential_limit = 32768 if (onef or npv) else 8192
        incoming = sys.stdin.buffer.read(credential_limit + 1)
        if len(incoming) > credential_limit:
            return 2
        credentials = json.loads(incoming) if incoming else {}
        if not isinstance(credentials, dict) or set(credentials) - {"password"}:
            return 2
        password = credentials.get("password")
        if password is not None and (not isinstance(password, str) or
                not 0 < len(password.encode("utf-8")) <= 4096):
            return 2
        if password is not None and not (text.strip().lower().startswith(("ua://", "v2box://", "xveontunnel://", "xveon://", "xvn://")) or
                onef or npv):
            return 2
        output = dispatch(text, password=password)
    except (OSError, UnicodeError, ValueError, ImportError) as error:
        # NPV uses CREDENTIALS_NOT_ALLOWED for passwords on plain JSON links.
        # Expose the existing public INVALID_CREDENTIALS contract, never a
        # misleading generic decode failure.
        code = getattr(error, "code", None)
        if code == "CREDENTIALS_NOT_ALLOWED":
            code = "INVALID_CREDENTIALS"
        if code in ("PASSWORD_REQUIRED", "AUTH_FAILED",
                "PRIVATE_KEY_REQUIRED", "RECIPIENT_MISMATCH",
                "INVALID_CREDENTIALS", "NPVS_PROTECTION_UNSUPPORTED"):
            sys.stdout.write(json.dumps({"workerError": code}))
            return 3
        return 1
    if not isinstance(output, str) or not output:
        return 1
    sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
