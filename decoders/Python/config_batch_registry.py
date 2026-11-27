"""Bot-only extensions from the independent authorized 66.py file decoders.

Keep Android's 61-format decoders.json untouched until a separate parity phase.
All aliases in a family point to the same Python script.
"""
from __future__ import annotations

FILE_DECODER_FAMILIES: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "sentinel": ("Sentinel Tunnel 4.0.0", "decoders/Python/apps/Sentinel_Tunnel/file_decoder.py", (".st",)),
    "itv": ("ITV Tunnel", "decoders/Python/itv.py", (".itv",)),
    "eut": ("EUT Tunnel", "decoders/Python/eut.py", (".eut",)),
    "v2box": ("V2Box Export", "decoders/Python/v2box_export.py", (".v2box",)),
    "slipnet": ("SlipNet", "decoders/Python/slipnet.py", (".slipnet",)),
    "juanscript": ("JuanScript", "decoders/Python/juanscript.py",
                    (".juanscript", ".juan", ".mobi")),
    "wyrlite": ("WyrLite", "decoders/Python/wyrlite.py",
                (".wyrl", ".wyrlite", ".wyrvpnlite")),
    "wyrvpn": ("WyrVPN", "decoders/Python/wyrvpn.py", (".wyr",)),
    "intvpn": ("IntVPN", "decoders/Python/intvpn.py", (".int",)),
    "fthp": ("FTHP", "decoders/Python/fthp.py", (".fthp", ".ftp")),
    "ar_pro": ("AR Pro / MSY", "decoders/Python/ar_pro.py", (".ar", ".msy")),
    "ec": ("EC Tunnel", "decoders/Python/ec.py", (".ec",)),
    "xor": ("XOR VPN family", "decoders/Python/xor_family.py",
             (".apnalite", ".apnatnl", ".bdnet", ".hxt", ".fnf",
              ".4ulite", ".omanova", ".ursa", ".hsome")),
}

def file_decoder_specs() -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    for name, script, extensions in FILE_DECODER_FAMILIES.values():
        for extension in extensions:
            if extension in result:
                raise ValueError(f"Conflicting decoder entry: {extension}")
            result[extension] = (name, script)
    return result
