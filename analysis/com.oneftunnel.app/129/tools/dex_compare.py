#!/usr/bin/env python3
"""Compare the 0.7.1 and 0.7.3 DEX files for format-relevant changes.

Usage:
    python analysis/com.oneftunnel.app/129/tools/dex_compare.py <classes-0.7.1.dex> <classes-0.7.3.dex>

The app is R8-obfuscated, so raw class-name diffs are noise. This script
compares only what decides the format:
  * non-obfuscated class names (com.oneftunnel.app.* model classes, androidx,
    kotlin, libraries) — a new/removed model class would mean a format change;
  * enum value strings (InjectMode, SlowDnsRecordType, ConfigType,
    XrayProtocol) — a new value would mean a format change;
  * format-related string tokens — new tokens would mean a new feature.

Requires androguard (venv ~/workspace/http-custom-update/venv).
"""
from __future__ import annotations

import logging
import sys

logging.disable(logging.CRITICAL)

from androguard.core.dex import DEX  # noqa: E402


def load(path: str):
    dex = DEX(open(path, "rb").read())
    classes = sorted(c.get_name() for c in dex.get_classes())
    strings = set(dex.get_strings())
    return classes, strings


def real_classes(classes) -> set:
    out = set()
    for name in classes:
        parts = name.strip("L;").split("/")
        if any(len(part) > 2 for part in parts):
            out.add(name)
    return out


ENUMS = {
    "InjectMode": {"DIRECT", "SSH_PAYLOAD", "PROXY", "PROXY_SNI",
                   "WILDCARD", "SLOWDNS"},
    "SlowDnsRecordType": {"AUTO", "TXT", "NULL", "NS", "CNAME", "MX", "SRV",
                          "A", "AAAA"},
    "ConfigType": {"SSH", "VMESS", "VLESS", "TROJAN"},
    "XrayProtocol": {"VMESS", "VLESS", "TROJAN", "SHADOWSOCKS", "HTTP",
                     "SOCKS"},
}

FORMAT_TOKEN_HINTS = ("slowdns", "slow_dns", "inject", "configtype",
                      "tlsmode", "reality", "flow", "fingerprint", "spiderx",
                      "shortid", "cfg1", "1ft1", "load-balance", "xray",
                      "vless", "vmess", "trojan", "load_balance")


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    ca, sa = load(sys.argv[1])
    cb, sb = load(sys.argv[2])
    ok = True

    ra, rb = real_classes(ca), real_classes(cb)
    print(f"non-obfuscated classes: 0.7.1={len(ra)} 0.7.3={len(rb)}")
    added = sorted(rb - ra)
    removed = sorted(ra - rb)
    print("only in 0.7.3:", added)
    print("only in 0.7.1:", removed)
    onef_added = [c for c in added if "oneftunnel" in c]
    onef_removed = [c for c in removed if "oneftunnel" in c]
    if onef_added or onef_removed:
        print("FORMAT-RELEVANT class change:", onef_added, onef_removed)
        ok = False
    else:
        print("OK: no com.oneftunnel.app class added or removed")

    for name, values in ENUMS.items():
        present_a = sorted(values & sa)
        present_b = sorted(values & sb)
        print(f"{name}: 0.7.1={present_a} 0.7.3={present_b}")
        if present_a != present_b:
            print(f"FORMAT-RELEVANT enum change in {name}")
            ok = False

    def tokens(strings):
        return {s for s in strings
                if any(h in s.lower() for h in FORMAT_TOKEN_HINTS)}

    ta, tb = tokens(sa), tokens(sb)
    print("format tokens only in 0.7.3:", sorted(tb - ta))
    print("format tokens only in 0.7.1:", sorted(ta - tb))
    print("DEX_COMPARE:", "NO FORMAT CHANGE" if ok else "CHANGES FOUND")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
