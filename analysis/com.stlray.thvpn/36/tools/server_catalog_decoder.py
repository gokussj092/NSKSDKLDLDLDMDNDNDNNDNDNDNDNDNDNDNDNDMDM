#!/usr/bin/env python3
"""SP-DECODE server-side catalog decoder for STLRAY 1.1.36.

Bridge contract (see cloud/workers/python/catalog_vpn_bridge.py): the
broker downloads the live catalog and passes the raw bytes here;
run() returns the decrypted catalog as one JSON string.

STLRAY's catalog is THREE files at one prefix
(https://stallionray.my.id/sray_v2x6w9c4/): config.json, modes.json
and policy.json, each a THAIVPN2 envelope (5-layer AES-256-GCM +
HMAC + ECDSA P-256 signature; see stlray.py). The broker therefore
fetches them as PAIRED_SOURCES and packs them into one bundle::

    {"kind": "spdecode-stlray-vpn-catalogs-v1",
     "catalogs": {"config": "<base64 envelope>",
                  "modes": "<base64 envelope>",
                  "policy": "<base64 envelope>"}}

run() also accepts a single THAIVPN2 envelope (config only) for
direct use and testing.

The result is the config catalog with the ``updates`` block REMOVED
from all three documents (each source carries its own — the block
holds the download API / locator — Pedro's rule: no download APIs
in a result JSON) plus the decrypted ``modes`` and ``policy``
documents under those keys, so nothing is truncated.
A present-but-invalid ECDSA signature fails closed (DecodeError);
an envelope without a signature (synthetic fixtures only) decrypts
with signature_valid None and is accepted.

VERIFIED_LIVE 2026-11-27: config rev 150086 / 15.86, 76 servers,
38 payloads, 6 certificates, signatures valid; modes rev 10009
(14 modes); policy rev 10007. Re-fetch 2026-11-27 ~20:40 UTC
byte-identical to the delivered sample except the stripped
``updates`` block.
"""
from __future__ import annotations

import base64
import json

if __package__:
    from .stlray import CATALOG_KEYS, thaivpn2_decrypt_envelope
else:
    from stlray import CATALOG_KEYS, thaivpn2_decrypt_envelope

BUNDLE_KIND = "spdecode-stlray-vpn-catalogs-v1"
BUNDLE_SOURCES = ("config", "modes", "policy")


class DecodeError(ValueError):
    pass


def _decode_envelope(raw: bytes) -> tuple[dict, bool | None]:
    """One THAIVPN2* envelope (bytes) -> (decrypted dict, sig_ok)."""
    try:
        env = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, UnicodeError):
        raise DecodeError("Catálogo no es JSON THAIVPN2.") from None
    if not isinstance(env, dict) or "data" not in env:
        raise DecodeError("Catálogo sin sobre THAIVPN2.")
    try:
        doc, sig_ok = thaivpn2_decrypt_envelope(env, CATALOG_KEYS)
    except (ValueError, TypeError):
        raise DecodeError(
            "Catálogo inválido o incompatible con STLRAY 1.1.36.") from None
    if env.get("signature") and sig_ok is not True:
        raise DecodeError("Firma ECDSA del catálogo inválida.")
    if not isinstance(doc, dict):
        raise DecodeError("Catálogo sin JSON válido.")
    return doc, sig_ok


def decode_catalog(data: bytes) -> dict:
    """Paired bundle bytes or a single envelope -> merged catalog dict."""
    if not isinstance(data, bytes) or not data:
        raise DecodeError("Catálogo vacío.")
    if len(data) > 8 * 1024 * 1024:
        raise DecodeError("Catálogo demasiado grande.")
    text = data.lstrip()
    if text.startswith(b"{"):
        try:
            bundle = json.loads(data.decode("utf-8-sig"))
        except (ValueError, UnicodeError):
            raise DecodeError("Paquete de catálogo inválido.") from None
        if (isinstance(bundle, dict) and bundle.get("kind") == BUNDLE_KIND
                and isinstance(bundle.get("catalogs"), dict)
                and set(bundle["catalogs"]) == set(BUNDLE_SOURCES)):
            docs = {}
            for name in BUNDLE_SOURCES:
                section = bundle["catalogs"][name]
                if not isinstance(section, str):
                    raise DecodeError("Fuente de catálogo inválida.")
                try:
                    raw = base64.b64decode(section, validate=True)
                except ValueError:
                    raise DecodeError("Fuente de catálogo inválida.") from None
                docs[name], _ = _decode_envelope(raw)
            config = docs["config"]
            # Every source carries its own updates block (download API /
            # locator) — strip all three, never only the config one.
            for doc in docs.values():
                if "updates" in doc:
                    del doc["updates"]
            config["modes"] = docs["modes"]
            config["policy"] = docs["policy"]
            return config
        # A lone "{" that is not our bundle falls through to the
        # single-envelope path below, which raises the proper error.
    config, _ = _decode_envelope(data)
    if "updates" in config:
        del config["updates"]
    return config


def run(data: bytes) -> str:
    """Bridge entry point: bytes -> JSON string."""
    return json.dumps(decode_catalog(data), ensure_ascii=False, indent=2) + "\n"
